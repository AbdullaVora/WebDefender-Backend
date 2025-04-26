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

from fastapi import APIRouter, HTTPException
from models.newScans.CORSModel import ScanRequest, ScanBatchRequest, ScanResponse
from controllers.newScans.CORSController import ScanController

router = APIRouter()

controller = ScanController()

@router.post("/CORS", response_model=ScanResponse, summary="Scan single target for CORS vulnerabilities")
async def scan_single_target(request: ScanRequest):
    """
    Scan a single target for CORS misconfigurations.
    
    Parameters:
    - target: URL to scan (can be with or without protocol)
    - threads: Number of threads to use (default: 5)
    - delay: Delay between requests in seconds (default: 0)
    - cookies: Optional cookies to include in requests
    
    Returns:
    - Scan results with vulnerabilities found
    - Detailed scan logs
    """
    return controller.scan_single_target(
        domain=request.domain,
        threads=request.threads,
        delay=request.delay,
        cookies=request.cookies
    )

@router.post("/CORSScan", response_model=ScanResponse, summary="Scan multiple targets for CORS vulnerabilities")
async def scan_batch_targets(request: ScanBatchRequest):
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
    return controller.scan_batch_targets(
        domains=request.domains,
        threads=request.threads,
        delay=request.delay,
        cookies=request.cookies
    )