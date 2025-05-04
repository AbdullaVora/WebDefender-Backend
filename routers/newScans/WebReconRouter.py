# from fastapi import APIRouter, HTTPException
# from typing import Optional

# from controllers.newScans.WebReconController import perform_scan
# from models.newScans.WebReconModel import ScanResponse, scanRequest
# from config.database import get_db

# router = APIRouter()

# @router.post("/webReconScan", response_model=ScanResponse)
# async def scan_website(request: scanRequest):
#     """
#     Perform a comprehensive security scan on a target website.
    
#     Args:
#         request: scanRequest with target URL and userId
    
#     Returns:
#         ScanResponse with results from all security tools
#     """
#     db = get_db()
    
#     try:
#         scan_data = perform_scan(request.target)
        
#         if db is not None:
#             try:
#                 # Convert Pydantic model to dictionary for MongoDB
#                 mongo_data = scan_data.dict()
#                 mongo_data['userId'] = request.userId
#                 await db.Whois_Report.insert_one(mongo_data)
#             except Exception as e:
#                 print(f"[❌] Error saving to MongoDB: {e}")
        
#         # Always return the scan data
#         return scan_data
        
#     except Exception as e:
#         error_message = str(e)
#         print(f"[❌] Scan error: {error_message}")
#         raise HTTPException(
#             status_code=500,
#             detail=f"Scan failed: {error_message}"
#         )
from fastapi import APIRouter, HTTPException, status
from typing import Optional
from datetime import datetime
import logging

from controllers.newScans.WebReconController import perform_scan
from models.newScans.WebReconModel import ScanResponse, ScanRequest
from config.database import get_db

router = APIRouter()

# Set up logging
logger = logging.getLogger(__name__)

@router.post(
    "/webReconScan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Perform comprehensive website security scan",
    response_description="Results from all security tools",
    tags=["Web Reconnaissance"]
)
async def scan_website(request: ScanRequest):
    """
    Perform a comprehensive security scan on a target website.
    
    This endpoint runs multiple security tools against the target URL and returns
    consolidated results including:
    - DNS information
    - SSL/TLS configuration
    - Security headers
    - Web application firewall detection
    - Technology stack analysis
    - And more
    
    Args:
        request: ScanRequest with:
            - target: URL to scan (required)
            - userId: User identifier for audit logging (optional)
    
    Returns:
        ScanResponse with:
            - target: Scanned URL
            - status: Scan status
            - results: Individual tool results
            - merged_data: Consolidated findings from all tools
            - timestamp: When the scan was performed
    """
    db = None
    try:
        # Get database connection
        db = get_db()
        
        logger.info(f"Starting scan for target: {request.target}")
        start_time = datetime.now()
        
        # Perform the scan
        scan_data = perform_scan(request.target)
        
        # Log scan duration
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f} seconds")
        
        # Save to MongoDB if database is available
        if db is not None:
            try:
                mongo_data = scan_data.dict()
                mongo_data.update({
                    'userId': request.userId,
                    'scanDuration': duration,
                    'createdAt': datetime.now()
                })
                
                # Store in appropriate collection
                await db.WebReconScans.insert_one(mongo_data)
                logger.info("Scan results saved to database")
            except Exception as db_error:
                logger.error(f"Database save error: {db_error}", exc_info=True)
        
        return scan_data
        
    except ValueError as ve:
        logger.error(f"Validation error: {ve}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve)
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )
    finally:
        # Close any resources if needed
        pass