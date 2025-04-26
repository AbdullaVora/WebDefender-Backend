# from fastapi import APIRouter, HTTPException
# from fastapi.responses import JSONResponse
# import logging
# import uuid
# from controllers.tools.HiddenFilesController import run_dirsearch
# from models.tools.HiddenFilesModel import ScanRequest

# payload_path = r"D:\WebDefender_Backend\WebDefender_API\helper\payloads\dirbrute.txt"

# router = APIRouter()
# @router.post("/Hidden-Files-Reconnaissance")
# async def start_scan(request: ScanRequest):
#     if request.custom:
#         if request.custom.payloads:
#             targets = request.custom.payloads
#         elif request.custom.urls:
#             targets = request.custom.urls
#         else:
#             targets = [request.domain] if request.domain else []
#     else:
#         targets = [request.domain] if request.domain else []

#     if not targets:
#         raise HTTPException(status_code=400, detail="No URLs, payloads, or domain provided.")

#     scan_id = str(uuid.uuid4())
#     logging.info(f"[+] Starting scan with ID: {scan_id}")

#     results = []
#     for target in targets:
#         scan_results = run_dirsearch(
#             # wordlist="dirbrute.txt",  # Default wordlist
#             url=target,
#             user_role="free",  # Default user role
#             delay=request.custom.delays if request.custom else 0.3,
#             threads=request.custom.threads if request.custom else 15,
#             extensions="php,html,txt,js,css",  # Default extensions
#             timeouts=request.custom.timeout if request.custom else 30,
#             retries=request.custom.retries if request.custom else 3
#         )
#         if scan_results:
#             results.append(scan_results)

#     if results:
#         return JSONResponse(content={
#             "scan_id": scan_id,
#             "status": "completed",
#             "results": results
#         })
#     else:
#         raise HTTPException(status_code=500, detail="Scan failed for all targets.")


from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import logging
import uuid
from controllers.tools.HiddenFilesController import run_dirsearch
from models.tools.HiddenFilesModel import ScanRequest
import io
from config.database import get_db
from datetime import datetime

db = get_db()

payload_path = r"D:\WebDefender_Backend\WebDefender_API\helper\payloads\dirbrute2.txt"

router = APIRouter()

class LogCapture:
    def __init__(self):
        self.logs = []
        self.log_handler = None
    
    def start_capture(self):
        class CaptureHandler(logging.Handler):
            def __init__(self, log_list):
                super().__init__()
                self.log_list = log_list
            
            def emit(self, record):
                log_entry = self.format(record)
                self.log_list.append(log_entry)
        
        self.log_handler = CaptureHandler(self.logs)
        self.log_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
        self.log_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(self.log_handler)
    
    def stop_capture(self):
        if self.log_handler:
            logging.getLogger().removeHandler(self.log_handler)
    
    def get_logs(self):
        return self.logs

@router.post("/Hidden-Files-Reconnaissance")
async def start_scan(request: ScanRequest):
    # Initialize log capture
    log_capture = LogCapture()
    log_capture.start_capture()
    
    try:
        if request.custom:
            if request.custom.payloads:
                targets = request.custom.payloads
            elif request.custom.urls:
                targets = request.custom.urls
            else:
                targets = [request.domain] if request.domain else []
        else:
            targets = [request.domain] if request.domain else []

        if not targets:
            raise HTTPException(status_code=400, detail="No URLs, payloads, or domain provided.")

        scan_id = str(uuid.uuid4())
        logging.info(f"[+] Starting scan with ID: {scan_id}")

        # For multi-target case
        if len(targets) > 1:
            all_results = []
            for target in targets:
                scan_result = await run_dirsearch(
                    url=target,
                    user_role="free",
                    delay=request.custom.delays if request.custom else 0.3,
                    threads=request.custom.threads if request.custom else 15,
                    extensions="php,html,txt,js,css",
                    timeouts=request.custom.timeout if request.custom else 30,
                    retries=request.custom.retries if request.custom else 3
                )
                if scan_result:
                    all_results.append({
                        "target": target,                                                                  
                        "scan_info": scan_result["scan_info"],
                        "results": scan_result["results"]
                    })
            
            if all_results:
                data = JSONResponse(content={
                    "scanType": "Hidden-Files-Reconnaissance",
                    "user_id": request.userId,
                    "scan_id": scan_id,
                    "status": "completed",
                    "results": all_results,
                    "logs": log_capture.get_logs(),
                    "scanStatus": "success",
                    "created_time": datetime.utcnow().isoformat() 

                })
                if db is not None:
                    try:
                        # Create a serializable version of the result for MongoDB
                        mongo_result = data.copy()
                        insert_result = await db.hidden_files.insert_one(mongo_result)
                        
                        # Return a clean result with string ID
                        data["_id"] = str(insert_result.inserted_id)
                        print("[✔] Stored in MongoDB with ID:", data["_id"])
                    except Exception as e:
                        print(f"[❌] Error saving to MongoDB: {e}")
                
                return data
            else:
                raise HTTPException(status_code=500, detail="Scan failed for all targets.")
        
        # For single target case (more common)
        else:
            target = targets[0]
            scan_result = await run_dirsearch(
                url=target,
                user_role="free",
                delay=request.custom.delays if request.custom else 0.3,
                threads=request.custom.threads if request.custom else 15,
                extensions="php,html,txt,js,css",
                timeouts=request.custom.timeout if request.custom else 30,
                retries=request.custom.retries if request.custom else 3
            )
            
            if scan_result:
                data = JSONResponse(content={
                    "scanType": "Hidden-Files-Reconnaissance",
                    "user_id": request.userId,
                    "scan_id": scan_id,
                    "status": "completed",
                    "scan_info": scan_result["scan_info"],
                    "results": scan_result["results"],
                    "logs": log_capture.get_logs()
                })
        
                if db is not None:
                    try:
                        # Create a serializable version of the result for MongoDB
                        mongo_result = data.copy()
                        insert_result = await db.hidden_files.insert_one(mongo_result)
                        
                        # Return a clean result with string ID
                        data["_id"] = str(insert_result.inserted_id)
                        print("[✔] Stored in MongoDB with ID:", data["_id"])
                    except Exception as e:
                        print(f"[❌] Error saving to MongoDB: {e}")
                
                return data
            else:
                raise HTTPException(status_code=500, detail="Scan failed.")
    
    except Exception as e:
        logging.error(f"[❗] Unexpected error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "scanType": "Hidden-Files-Reconnaissance",
                "user_id": request.userId,
                "scan_id": str(uuid.uuid4()),
                "status": "error",
                "message": str(e),
                "logs": log_capture.get_logs()
            }
        )
    
    finally:
        # Stop log capture
        log_capture.stop_capture()