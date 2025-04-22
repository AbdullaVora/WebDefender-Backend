# controllers/cors_controller.py
from fastapi import BackgroundTasks, HTTPException, status
import json
import os
import requests
import time
from datetime import datetime
from typing import List, Dict, Any
import threading
from queue import Queue
import uuid

from models.newScans.CORSModel import ScanRequest, ScanResponse, ScanStatus, ScanFileRequest

# Known CORS misconfigurations
CORS_VULN_DB = {
    "wildcard value": {
        "class": "wildcard value",
        "description": "This host allows requests made from any origin.",
        "severity": "low",
        "exploitation": "Not possible"
    },
    "origin reflected": {
        "class": "origin reflected",
        "description": "This host allows any origin to make requests to it.",
        "severity": "high",
        "exploitation": "Make requests from any domain you control."
    },
    "null origin allowed": {
        "class": "null origin allowed",
        "description": "This host allows requests from 'null' origin.",
        "severity": "high",
        "exploitation": "Make requests from a sandboxed iframe."
    },
    "http origin allowed": {
        "class": "http origin allowed",
        "description": "This host allows sharing resources over HTTP.",
        "severity": "low",
        "exploitation": "Sniff requests over unencrypted channel."
    },
    "third party allowed": {
        "class": "third party allowed",
        "description": "Whitelisted a 3rd-party domain.",
        "severity": "Medium",
        "exploitation": "Could be abused if 3rd-party is untrusted."
    },
    "invalid value": {
        "class": "invalid value",
        "description": "Invalid header value; CORS likely broken.",
        "severity": "low",
        "exploitation": "Not possible"
    }
}

# In-memory storage for scan results
scan_storage = {}

class CorsController:
    @staticmethod
    def classify_cors_vulnerability(origin, cors_headers):
        """Classify the type of CORS vulnerability based on headers"""
        allow_origin = cors_headers.get("Access-Control-Allow-Origin")
        allow_creds = cors_headers.get("Access-Control-Allow-Credentials")

        if allow_origin == "*":
            return CORS_VULN_DB["wildcard value"]

        if allow_origin == origin:
            if origin == "null":
                return CORS_VULN_DB["null origin allowed"]
            elif origin.startswith("http://"):
                return CORS_VULN_DB["http origin allowed"]
            elif origin in ["http://localhost", "http://127.0.0.1"]:
                return CORS_VULN_DB["third party allowed"]
            else:
                return CORS_VULN_DB["origin reflected"]

        if allow_origin is None:
            return {
                "class": "no cors",
                "description": "No CORS headers returned.",
                "severity": "info",
                "exploitation": "N/A"
            }

        if " " in allow_origin or not allow_origin.startswith("http"):
            return CORS_VULN_DB["invalid value"]

        return {
            "class": "unknown behavior",
            "description": "Unrecognized CORS response.",
            "severity": "unknown",
            "exploitation": "Unknown"
        }
    
    @staticmethod
    async def scan_target(url, headers, timeout=10, delay=0, result_list=None, scan_id=None):
        """Scan a single target URL for CORS misconfigurations"""
        test_origins = [
            "https://example.com",
            "http://malicious.com",
            "null",
            "http://localhost",
            "http://127.0.0.1",
        ]

        # Add scheme if missing
        if not url.startswith("http://") and not url.startswith("https://"):
            for proto in ["https://", "http://"]:
                try:
                    test_url = proto + url
                    response = requests.get(test_url, timeout=timeout)
                    if response.status_code < 400:
                        url = test_url
                        break
                except:
                    continue
            else:
                if scan_id and url in scan_storage[scan_id]["remaining_urls"]:
                    scan_storage[scan_id]["remaining_urls"].remove(url)
                    scan_storage[scan_id]["failed_urls"].append(url)
                return

        single_results = []

        for origin in test_origins:
            try:
                request_headers = {
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0"
                }
                if headers:
                    request_headers.update(headers)

                response = requests.get(url, headers=request_headers, timeout=timeout)

                cors_headers = {
                    "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                    "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials")
                }

                vuln = CorsController.classify_cors_vulnerability(origin, cors_headers)

                if vuln["severity"].lower() in ["low", "medium", "high"]:
                    result = {
                        "timestamp": datetime.now().isoformat(),
                        "host": url,
                        "origin": origin,
                        "classification": vuln["class"],
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "exploitation": vuln["exploitation"],
                        "allow_credentials": cors_headers["Access-Control-Allow-Credentials"],
                        "http_status": response.status_code
                    }
                    single_results.append(result)

            except Exception as e:
                pass
            time.sleep(delay)

        if scan_id and url in scan_storage[scan_id]["remaining_urls"]:
            scan_storage[scan_id]["remaining_urls"].remove(url)
            scan_storage[scan_id]["completed_urls"].append(url)
            scan_storage[scan_id]["results"].extend(single_results)

        if result_list is not None:
            result_list.extend(single_results)
    
    @staticmethod
    def worker(queue, headers, delay, results, scan_id=None):
        """Worker thread to process URLs from the queue"""
        while not queue.empty():
            url = queue.get()
            CorsController.scan_target(url, headers, delay=delay, result_list=results, scan_id=scan_id)
            queue.task_done()
    
    @staticmethod
    def generate_scan_id():
        """Generate a unique scan ID"""
        return str(uuid.uuid4())
    
    @staticmethod
    def calculate_progress(scan_id):
        """Calculate the progress of a scan"""
        if scan_id not in scan_storage:
            return 0
        
        total_urls = len(scan_storage[scan_id]["completed_urls"]) + len(scan_storage[scan_id]["failed_urls"]) + len(scan_storage[scan_id]["remaining_urls"])
        if total_urls == 0:
            return 100
        
        completed = len(scan_storage[scan_id]["completed_urls"]) + len(scan_storage[scan_id]["failed_urls"])
        return (completed / total_urls) * 100
    
    @staticmethod
    async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
        """
        Controller method to start a CORS scan
        """
        scan_id = CorsController.generate_scan_id()
        
        # Initialize scan status
        scan_storage[scan_id] = {
            "status": "queued",
            "progress": 0.0,
            "results": [],
            "remaining_urls": scan_request.urls.copy(),
            "completed_urls": [],
            "failed_urls": []
        }
        
        # Add scan to background tasks
        background_tasks.add_task(CorsController._run_scan, scan_request, scan_id)
        
        return ScanResponse(
            scan_id=scan_id,
            message=f"Scan started for {len(scan_request.urls)} URLs"
        )
    
    @staticmethod
    async def scan_from_file(scan_request: ScanFileRequest, background_tasks: BackgroundTasks) -> ScanResponse:
        """
        Controller method to start a CORS scan from a file
        """
        if not os.path.isfile(scan_request.file_path):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File not found: {scan_request.file_path}"
            )
        
        try:
            with open(scan_request.file_path, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error reading file: {str(e)}"
            )
        
        # Create a ScanRequest from the file data
        file_scan_request = ScanRequest(
            urls=urls,
            thread_count=scan_request.thread_count,
            delay=scan_request.delay,
            headers=scan_request.headers
        )
        
        return await CorsController.start_scan(file_scan_request, background_tasks)
    
    @staticmethod
    async def get_scan_status(scan_id: str) -> ScanStatus:
        """
        Controller method to get scan status
        """
        if scan_id not in scan_storage:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        scan_data = scan_storage[scan_id]
        progress = CorsController.calculate_progress(scan_id)
        
        return ScanStatus(
            scan_id=scan_id,
            status=scan_data["status"],
            progress=progress,
            results=scan_data["results"] if scan_data["status"] == "completed" else None
        )
    
    @staticmethod
    async def list_scans() -> List[str]:
        """
        Controller method to list all scan IDs
        """
        return list(scan_storage.keys())
    
    @staticmethod
    async def delete_scan(scan_id: str) -> None:
        """
        Controller method to delete a scan
        """
        if scan_id not in scan_storage:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        del scan_storage[scan_id]
    
    @staticmethod
    async def save_results_to_file(scan_id: str, file_path: str) -> Dict[str, Any]:
        """
        Controller method to save scan results to a file
        """
        if scan_id not in scan_storage:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        scan_data = scan_storage[scan_id]
        if scan_data["status"] != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan {scan_id} is not completed yet"
            )
        
        try:
            with open(file_path, "w") as f:
                json.dump(scan_data["results"], f, indent=4)
            
            return {"message": f"Results saved to {file_path}"}
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error saving results: {str(e)}"
            )
    
    @staticmethod
    async def _run_scan(scan_request: ScanRequest, scan_id: str) -> None:
        """
        Internal method to run the scan in the background
        """
        queue = Queue()
        
        # Update status to running
        scan_storage[scan_id]["status"] = "running"
        
        for url in scan_request.urls:
            queue.put(url)
        
        threads = []
        for _ in range(scan_request.thread_count):
            t = threading.Thread(
                target=CorsController.worker, 
                args=(queue, scan_request.headers, scan_request.delay, None, scan_id)
            )
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Wait for all tasks to complete
        for t in threads:
            t.join()
        
        # Update status to completed
        scan_storage[scan_id]["status"] = "completed"
        scan_storage[scan_id]["progress"] = 100.0