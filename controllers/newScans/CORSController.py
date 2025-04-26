# import requests
# import json
# import threading
# import time
# from datetime import datetime
# from queue import Queue
# import os
# import io
# import sys
# import logging
# from typing import List, Dict, Any
# from fastapi import HTTPException
# from models.newScans.CORSModel import ScanResult, ScanLog, ScanResponse

# class ScanController:
#     def __init__(self):
#         self.logs = []
#         self.log_capture = io.StringIO()
#         self.log_handler = logging.StreamHandler(self.log_capture)
#         self.log_handler.setLevel(logging.INFO)
#         logging.basicConfig(handlers=[self.log_handler], level=logging.INFO)
        
#         # CORS Vulnerability Database
#         self.CORS_VULN_DB = {
#             "wildcard value": {
#                 "class": "wildcard value",
#                 "description": "This host allows requests made from any origin.",
#                 "severity": "low",
#                 "exploitation": "Not possible"
#             },
#             "origin reflected": {
#                 "class": "origin reflected",
#                 "description": "This host allows any origin to make requests to it.",
#                 "severity": "high",
#                 "exploitation": "Make requests from any domain you control."
#             },
#             "null origin allowed": {
#                 "class": "null origin allowed",
#                 "description": "This host allows requests from 'null' origin.",
#                 "severity": "high",
#                 "exploitation": "Make requests from a sandboxed iframe."
#             },
#             "http origin allowed": {
#                 "class": "http origin allowed",
#                 "description": "This host allows sharing resources over HTTP.",
#                 "severity": "low",
#                 "exploitation": "Sniff requests over unencrypted channel."
#             },
#             "third party allowed": {
#                 "class": "third party allowed",
#                 "description": "Whitelisted a 3rd-party domain.",
#                 "severity": "medium",
#                 "exploitation": "Could be abused if 3rd-party is untrusted."
#             },
#             "invalid value": {
#                 "class": "invalid value",
#                 "description": "Invalid header value; CORS likely broken.",
#                 "severity": "low",
#                 "exploitation": "Not possible"
#             }
#         }

#     def _capture_logs(self):
#         logs = []
#         log_contents = self.log_capture.getvalue()
#         if log_contents:
#             for line in log_contents.split('\n'):
#                 if line.strip():
#                     log_level = "info"
#                     if line.startswith("[!]"):
#                         log_level = "error"
#                     elif line.startswith("[+]"):
#                         log_level = "info"
#                     elif line.startswith("[✔]"):
#                         log_level = "success"
                    
#                     logs.append(ScanLog(
#                         message=line.strip(),
#                         level=log_level,
#                         timestamp=datetime.now().isoformat()
#                     ))
#             self.log_capture.truncate(0)
#             self.log_capture.seek(0)
#         return logs

#     def _classify_cors_vulnerability(self, origin, cors_headers):
#         allow_origin = cors_headers.get("Access-Control-Allow-Origin")
#         allow_creds = cors_headers.get("Access-Control-Allow-Credentials")

#         if allow_origin == "*":
#             return self.CORS_VULN_DB["wildcard value"]

#         if allow_origin == origin:
#             if origin == "null":
#                 return self.CORS_VULN_DB["null origin allowed"]
#             elif origin.startswith("http://"):
#                 return self.CORS_VULN_DB["http origin allowed"]
#             elif origin in ["http://localhost", "http://127.0.0.1"]:
#                 return self.CORS_VULN_DB["third party allowed"]
#             else:
#                 return self.CORS_VULN_DB["origin reflected"]

#         if allow_origin is None:
#             return {
#                 "class": "no cors",
#                 "description": "No CORS headers returned.",
#                 "severity": "info",
#                 "exploitation": "N/A"
#             }

#         if " " in allow_origin or not allow_origin.startswith("http"):
#             return self.CORS_VULN_DB["invalid value"]

#         return {
#             "class": "unknown behavior",
#             "description": "Unrecognized CORS response.",
#             "severity": "unknown",
#             "exploitation": "Unknown"
#         }

#     def _scan_target(self, url, headers, timeout=10, delay=0, result_list=None):
#         test_origins = [
#             "https://example.com",
#             "http://malicious.com",
#             "null",
#             "http://localhost",
#             "http://127.0.0.1",
#         ]

#         # Add scheme if missing
#         original_url = url
#         if not url.startswith("http://") and not url.startswith("https://"):
#             for proto in ["https://", "http://"]:
#                 try:
#                     test_url = proto + url
#                     response = requests.get(test_url, timeout=timeout)
#                     if response.status_code < 400:
#                         url = test_url
#                         break
#                 except:
#                     continue
#             else:
#                 self.log_capture.write(f"[!] Could not connect to {url}\n")
#                 return

#         self.log_capture.write(f"\n[+] Scanning {url}\n{'=' * 60}\n")
#         single_results = []

#         for origin in test_origins:
#             try:
#                 request_headers = {
#                     "Origin": origin,
#                     "User-Agent": "Mozilla/5.0"
#                 }
#                 request_headers.update(headers)

#                 response = requests.get(url, headers=request_headers, timeout=timeout)

#                 cors_headers = {
#                     "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
#                     "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials")
#                 }

#                 vuln = self._classify_cors_vulnerability(origin, cors_headers)

#                 self.log_capture.write(f"[+] Origin: {origin}\n")
#                 self.log_capture.write(f"    Status: {response.status_code}\n")
#                 self.log_capture.write(f"    CORS: {cors_headers}\n")
#                 self.log_capture.write(f"    → {vuln['class'].upper()} | Severity: {vuln['severity']}\n")
#                 self.log_capture.write("-" * 50 + "\n")

#                 if vuln["severity"].lower() in ["low", "medium", "high"]:
#                     result = ScanResult(
#                         timestamp=datetime.now().isoformat(),
#                         host=url,
#                         origin=origin,
#                         classification=vuln["class"],
#                         description=vuln["description"],
#                         severity=vuln["severity"],
#                         exploitation=vuln["exploitation"],
#                         allow_credentials=cors_headers["Access-Control-Allow-Credentials"],
#                         http_status=response.status_code
#                     )
#                     single_results.append(result)

#             except Exception as e:
#                 self.log_capture.write(f"[!] Error with origin {origin}: {e}\n")
#             time.sleep(delay)

#         if single_results:
#             filename = f"cors_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.json"
#             with open(filename, "w") as f:
#                 json.dump([r.dict() for r in single_results], f, indent=4)
#             self.log_capture.write(f"[✔] Saved results to '{filename}'\n")

#         if result_list is not None:
#             result_list.extend(single_results)

#     def _worker(self, queue, headers, delay, results):
#         while not queue.empty():
#             url = queue.get()
#             self._scan_target(url, headers, delay=delay, result_list=results)
#             queue.task_done()

#     def scan_single_target(self, target: str, threads: int = 5, delay: float = 0, cookies: str = None) -> ScanResponse:
#         try:
#             headers = {}
#             if cookies:
#                 headers["Cookie"] = cookies
            
#             # Redirect stdout to capture print statements
#             old_stdout = sys.stdout
#             sys.stdout = self.log_capture
            
#             results = []
#             self._scan_target(target, headers, delay=delay, result_list=results)
            
#             # Restore stdout
#             sys.stdout = old_stdout
            
#             logs = self._capture_logs()
#             return ScanResponse(results=results, logs=logs)
            
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=str(e))

#     def scan_batch_targets(self, targets: List[str], threads: int = 5, delay: float = 0, cookies: str = None) -> ScanResponse:
#         try:
#             headers = {}
#             if cookies:
#                 headers["Cookie"] = cookies
            
#             # Create a temporary file for batch processing
#             import tempfile
#             with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
#                 for target in targets:
#                     tmp.write(f"{target}\n")
#                 tmp_path = tmp.name
            
#             # Redirect stdout to capture print statements
#             old_stdout = sys.stdout
#             sys.stdout = self.log_capture
            
#             results = []
            
#             # Implement batch processing without file dependency
#             queue = Queue()
#             for url in targets:
#                 queue.put(url)

#             worker_threads = []
#             for _ in range(threads):
#                 t = threading.Thread(target=self._worker, args=(queue, headers, delay, results))
#                 t.daemon = True
#                 worker_threads.append(t)
#                 t.start()

#             queue.join()
            
#             # Restore stdout
#             sys.stdout = old_stdout
            
#             # Clean up temporary file
#             import os
#             os.unlink(tmp_path)
            
#             logs = self._capture_logs()
#             return ScanResponse(results=results, logs=logs)
            
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=str(e))


import requests
import json
import threading
import time
from datetime import datetime
from queue import Queue
import os
import io
import sys
import logging
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from models.newScans.CORSModel import ScanResult, ScanLog, ScanResponse

class ScanController:
    def __init__(self):
        # Configure logging
        self.logger = logging.getLogger('CORSScanner')
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            
        # Create a string buffer to capture logs
        self.log_capture = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture)
        self.log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(self.log_handler)
        
        # CORS Vulnerability Database
        self.CORS_VULN_DB = {
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
                "severity": "medium",
                "exploitation": "Could be abused if 3rd-party is untrusted."
            },
            "invalid value": {
                "class": "invalid value",
                "description": "Invalid header value; CORS likely broken.",
                "severity": "low",
                "exploitation": "Not possible"
            }
        }

    def _capture_logs(self) -> List[ScanLog]:
        logs = []
        log_contents = self.log_capture.getvalue()
        if log_contents:
            for line in log_contents.split('\n'):
                if line.strip():
                    # Parse the structured log format
                    try:
                        timestamp_end = line.find(' - ')
                        level_end = line.find(' - ', timestamp_end + 3)
                        
                        timestamp = line[:timestamp_end]
                        level = line[timestamp_end+3:level_end].lower()
                        message = line[level_end+3:]
                        
                        logs.append(ScanLog(
                            message=message,
                            level=level,
                            timestamp=timestamp
                        ))
                    except:
                        # Fallback for non-formatted logs
                        logs.append(ScanLog(
                            message=line.strip(),
                            level="info",
                            timestamp=datetime.now().isoformat()
                        ))
            
            # Clear the buffer
            self.log_capture.truncate(0)
            self.log_capture.seek(0)
        return logs

    def _classify_cors_vulnerability(self, origin: str, cors_headers: Dict[str, Any]) -> Dict[str, Any]:
        allow_origin = cors_headers.get("Access-Control-Allow-Origin")
        allow_creds = cors_headers.get("Access-Control-Allow-Credentials")

        if allow_origin == "*":
            return self.CORS_VULN_DB["wildcard value"]

        if allow_origin == origin:
            if origin == "null":
                return self.CORS_VULN_DB["null origin allowed"]
            elif origin.startswith("http://"):
                return self.CORS_VULN_DB["http origin allowed"]
            elif origin in ["http://localhost", "http://127.0.0.1"]:
                return self.CORS_VULN_DB["third party allowed"]
            else:
                return self.CORS_VULN_DB["origin reflected"]

        if allow_origin is None:
            return {
                "class": "no cors",
                "description": "No CORS headers returned.",
                "severity": "info",
                "exploitation": "N/A"
            }

        if " " in allow_origin or not allow_origin.startswith("http"):
            return self.CORS_VULN_DB["invalid value"]

        return {
            "class": "unknown behavior",
            "description": "Unrecognized CORS response.",
            "severity": "unknown",
            "exploitation": "Unknown"
        }

    def _scan_target(self, url: str, headers: Dict[str, str], timeout: int = 10, 
                    delay: float = 0, result_list: Optional[List[ScanResult]] = None) -> None:
        test_origins = [
            "https://example.com",
            "http://malicious.com",
            "null",
            "http://localhost",
            "http://127.0.0.1",
        ]

        self.logger.info(f"Starting scan for {url}")
        
        # Add scheme if missing
        original_url = url
        if not url.startswith("http://") and not url.startswith("https://"):
            for proto in ["https://", "http://"]:
                try:
                    test_url = proto + url
                    response = requests.get(test_url, headers=headers, timeout=timeout)
                    if response.status_code < 400:
                        url = test_url
                        self.logger.info(f"Auto-detected working protocol: {proto}")
                        break
                except Exception as e:
                    self.logger.debug(f"Protocol {proto} failed: {str(e)}")
                    continue
            else:
                self.logger.error(f"Could not connect to {url} with either HTTP or HTTPS")
                return

        single_results = []
        for origin in test_origins:
            try:
                request_headers = {
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0"
                }
                request_headers.update(headers)

                self.logger.debug(f"Testing origin: {origin}")
                response = requests.get(url, headers=request_headers, timeout=timeout)

                cors_headers = {
                    "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                    "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials")
                }

                vuln = self._classify_cors_vulnerability(origin, cors_headers)
                
                if vuln["severity"].lower() in ["low", "medium", "high"]:
                    self.logger.warning(
                        f"Vulnerability found - {vuln['class']} "
                        f"(Severity: {vuln['severity']}) for origin {origin}"
                    )
                else:
                    self.logger.info(
                        f"Test completed - {vuln['class']} for origin {origin}"
                    )

                if vuln["severity"].lower() in ["low", "medium", "high"]:
                    result = ScanResult(
                        timestamp=datetime.now().isoformat(),
                        host=url,
                        origin=origin,
                        classification=vuln["class"],
                        description=vuln["description"],
                        severity=vuln["severity"],
                        exploitation=vuln["exploitation"],
                        allow_credentials=cors_headers["Access-Control-Allow-Credentials"],
                        http_status=response.status_code
                    )
                    single_results.append(result)

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed for origin {origin}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Unexpected error testing origin {origin}: {str(e)}")
                
            time.sleep(delay)

        if single_results:
            filename = f"cors_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.json"
            try:
                with open(filename, "w") as f:
                    json.dump([r.dict() for r in single_results], f, indent=4)
                self.logger.info(f"Saved results to '{filename}'")
            except IOError as e:
                self.logger.error(f"Failed to save results: {str(e)}")

        if result_list is not None:
            result_list.extend(single_results)

    def _worker(self, queue: Queue, headers: Dict[str, str], delay: float, 
               results: List[ScanResult]) -> None:
        while not queue.empty():
            url = queue.get()
            self._scan_target(url, headers, delay=delay, result_list=results)
            queue.task_done()

    def scan_single_target(self, domain: str, threads: int = 5, delay: float = 0, 
                          cookies: Optional[str] = None) -> ScanResponse:
        self.logger.info(f"Initiating single target scan for {domain}")
        try:
            headers = {}
            if cookies:
                headers["Cookie"] = cookies
                self.logger.debug("Cookies added to request headers")
            
            # Redirect stdout to capture print statements
            old_stdout = sys.stdout
            sys.stdout = self.log_capture
            
            results = []
            self._scan_target(domain, headers, delay=delay, result_list=results)
            
            # Restore stdout
            sys.stdout = old_stdout
            
            logs = self._capture_logs()
            self.logger.info("Single target scan completed")
            return ScanResponse(results=results, logs=logs)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    def scan_batch_targets(self, domains: List[str], threads: int = 5, delay: float = 0, 
                          cookies: Optional[str] = None) -> ScanResponse:
        self.logger.info(f"Initiating batch scan for {len(domains)} targets")
        try:
            headers = {}
            if cookies:
                headers["Cookie"] = cookies
                self.logger.debug("Cookies added to request headers")
            
            # Create a temporary file for batch processing
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                for target in domains:
                    tmp.write(f"{target}\n")
                tmp_path = tmp.name
            
            # Redirect stdout to capture print statements
            old_stdout = sys.stdout
            sys.stdout = self.log_capture
            
            results = []
            
            # Implement batch processing without file dependency
            queue = Queue()
            for url in domains:
                queue.put(url)

            worker_threads = []
            for _ in range(threads):
                t = threading.Thread(target=self._worker, args=(queue, headers, delay, results))
                t.daemon = True
                worker_threads.append(t)
                t.start()

            queue.join()
            
            # Restore stdout
            sys.stdout = old_stdout
            
            # Clean up temporary file
            try:
                import os
                os.unlink(tmp_path)
                self.logger.debug("Temporary file cleaned up")
            except Exception as e:
                self.logger.warning(f"Failed to clean up temp file: {str(e)}")
            
            logs = self._capture_logs()
            self.logger.info(f"Batch scan completed, found {len(results)} vulnerabilities")
            return ScanResponse(results=results, logs=logs)
            
        except Exception as e:
            self.logger.error(f"Batch scan failed: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))