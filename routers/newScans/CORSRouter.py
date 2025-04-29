# from fastapi import APIRouter, HTTPException
# from models.newScans.CORSModel import ScanRequest, ScanBatchRequest, ScanResponse
# from controllers.newScans.CORSController import ScanController

# router = APIRouter()

# controller = ScanController()

# @router.post("/CORS", response_model=ScanResponse)
# async def scan_single_target(request: ScanRequest):
#     return controller.scan_single_target(
#         target=request.target,
#         threads=request.threads,
#         delay=request.delay,
#         cookies=request.cookies
#     )

# @router.post("/batch", response_model=ScanResponse)
# async def scan_batch_targets(request: ScanBatchRequest):
#     return controller.scan_batch_targets(
#         targets=request.targets,
#         threads=request.threads,
#         delay=request.delay,
#         cookies=request.cookies
#     )

from fastapi import APIRouter, HTTPException, Form, UploadFile, File
from typing import List, Optional
import json
from models.newScans.CORSModel import ScanRequest, ScanBatchRequest, ScanResponse
from controllers.newScans.CORSController import ScanController
from config.database import get_db


router = APIRouter()

controller = ScanController()

@router.post("/CORS", response_model=ScanResponse)
async def scan_targets(
    domains: str = Form(...),
    threads: int = Form(5),
    retries: int = Form(3),
    delay: float = Form(0.3),
    timeout: int = Form(30),
    cookies: Optional[str] = Form(None),
    userId: str = Form(...),
    payloads: Optional[UploadFile] = File(None)
):
    db = get_db()
    try:
        domains_list = json.loads(domains)
        payloads_content = None
        
        if payloads:
            payloads_content = await payloads.read()
            payloads_content = payloads_content.decode('utf-8').splitlines()
        
        data = controller.scan_batch_targets(
            domains=domains_list,
            threads=threads,
            retries=retries,
            delay=delay,
            timeout=timeout,
            cookies=cookies,
            payloads=payloads_content
        )
        
        if db is not None:
            try:
                mongo_result = data  # Ensure it's serializable
                mongo_result['userId'] = userId
                insert_result = await db.Cors_Report.insert_one(mongo_result)
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return data
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid domains format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/CORSScan", response_model=ScanResponse, summary="Scan multiple targets for CORS vulnerabilities")
async def scan_batch_targets(request: ScanBatchRequest):
    db = get_db()
    """
    Scan multiple targets for CORS misconfigurations in batch mode.
    
    Parameters:
    - targets: List of URLs to scan
    - threads: Number of threads to use (default: 5)
    - delay: Delay between requests in seconds (default: 0)
    - cookies: Optional cookies to include in requests
    
    Returns:
    - Scan results with vulnerabilities found
    - Detailed scan logs
    """
    data = controller.scan_batch_targets(
        domains=request.domains,
        threads=request.threads,
        delay=request.delay,
        cookies=request.cookies
    )
    if db is not None:
        try:
            mongo_result = data.copy()  # Ensure it's serializable
            insert_result = await db.Cors_Report.insert_one(data)
        except Exception as e:
            print(f" Error saving to MongoDB: {e}")

    return data