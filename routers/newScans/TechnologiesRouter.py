from fastapi import APIRouter, HTTPException, status
from typing import List
from controllers.newScans.TechnologiesContoller import WappalyzerController
from models.newScans.TechnologiesModel import WappalyzerScanResponse, WappalyzerScanHistory, WappalyzerScanRequest
from config.database import get_db
import json
from datetime import datetime



router = APIRouter()

# @router.post("/technologiesScan", response_model=WappalyzerScanResponse)
# async def scan_website(request: WappalyzerScanRequest):
#     """
#     Scan a website for technologies using Wappalyzer
    
#     - **url**: Website URL to scan (e.g., "https://example.com")
#     """
#     # Access the url field from the request model
#     db = get_db()
    
#     if not request.url.startswith(('http://', 'https://')):
#         raise HTTPException(
#             status_code=422,
#             detail="URL must start with http:// or https://"
#         )
    
#     result = await WappalyzerController.analyze_website(request)
    
#     if 'error' in result:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=result['error']
#         )
    
#     if db is not None:
#         try:
#             mongo_result = result.copy()  # Ensure it's serializable
#             mongo_result['userId'] = request.userId
#             insert_result = await db.Technologies_Report.insert_one(mongo_result)
#         except Exception as e:
#             print(f"[❌] Error saving to MongoDB: {e}")

#     return result


@router.post("/technologiesScan", response_model=WappalyzerScanResponse)
async def scan_website(request: WappalyzerScanRequest):
    """Scan a website for technologies using Wappalyzer"""
    db = get_db()
    
    if not request.url.startswith(('http://', 'https://')):
        raise HTTPException(
            status_code=422,
            detail="URL must start with http:// or https://"
        )
    
    result = await WappalyzerController.analyze_website(request)
    
    if 'error' in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result['error']
        )
    
    if db is not None:
        try:
            # Convert Pydantic model to dictionary
            if isinstance(result, WappalyzerScanResponse):
                # Use .dict() for Pydantic v1 or .model_dump() for Pydantic v2
                try:
                    # First try Pydantic v2 method
                    mongo_result = result.model_dump()
                except AttributeError:
                    # Fall back to Pydantic v1 method
                    mongo_result = result.dict()
                
                print(f"[✓] Successfully converted Pydantic model to dict")
            else:
                # If it's already a dict, use it directly
                mongo_result = result
            
            # Add additional fields
            mongo_result['userId'] = request.userId
            mongo_result['timestamp'] = datetime.utcnow()
            mongo_result['url'] = request.url
            
            # Insert into MongoDB
            insert_result = await db.Technologies_Report.insert_one(mongo_result)
            print(f"[✓] Successfully inserted data with ID: {insert_result.inserted_id}")
            
        except Exception as e:
            print(f"[❌] MongoDB insertion error: {e}")
            import traceback
            traceback.print_exc()
            # Log the error but don't fail the request
    
    return result
@router.get("/getTechnologies", response_model=List[WappalyzerScanHistory])
async def get_scans():
    """Get all previous scan results"""
    return await WappalyzerController.get_scan_history()

@router.get("/scans/{scan_id}", response_model=WappalyzerScanHistory)
async def get_scan(scan_id: str):  # Changed to str if using MongoDB ObjectId
    """Get specific scan by ID"""
    scan = await WappalyzerController.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    return scan