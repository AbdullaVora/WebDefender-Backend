
# from fastapi import APIRouter, HTTPException, Body
# from pydantic import BaseModel, Field
# from typing import List, Optional, Dict, Any, Union
# import asyncio
# import json
# import os
# import sys

# # Add the project root to Python path
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# # Now we can import our modules
# from controllers.tools.WAFController import scan_target, create_map
# from models.tools.WAFModel import ScanRequest

# # Create APIRouter for WAF routes
# router = APIRouter()

# @router.post("/WAFDetector", response_model=List[Dict[str, Any]])
# async def scan_endpoint(scan_request: ScanRequest = Body(...)):
#     # Convert single string target to list
#     targets = scan_request.domain
#     if isinstance(targets, str):
#         targets = [targets]
    
#     if not targets:
#         raise HTTPException(status_code=400, detail="No valid targets provided")
    
#     # Execute scans - FastAPI already runs in an async context
#     results = await asyncio.gather(*(scan_target(target) for target in targets))
    
#     # Generate maps if requested
#     if scan_request.generate_maps:
#         map_files = await asyncio.gather(*(create_map(result) for result in results))
#         for i, result in enumerate(results):
#             if map_files[i]:
#                 result['Map'] = map_files[i]
    
#     # Save results to file if requested
#     if scan_request.save_results:
#         output_file = scan_request.output_file
#         os.makedirs(os.path.dirname(output_file), exist_ok=True)
#         with open(output_file, "w") as file:
#             json.dump(results, file, indent=4)
    
#     return results

# @router.get("/health")
# async def health_check():
#     return {"status": "healthy", "message": "WAF Detection API is running"}


from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import asyncio
import json
import os
import sys
from config.database import get_db
from datetime import datetime



# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Now we can import our modules
from controllers.tools.WAFController import scan_target, create_map
from models.tools.WAFModel import ScanRequest

# Create APIRouter for WAF routes
router = APIRouter()


@router.post("/WAFDetector", response_model=List[Dict[str, Any]])
async def scan_endpoint(scan_request: ScanRequest = Body(...)):

    db = get_db()

    targets = []
    
    if hasattr(scan_request, 'custom') and scan_request.custom:
        if hasattr(scan_request.custom, 'urls') and scan_request.custom.urls:
            targets = scan_request.custom.urls
    
    if not targets and hasattr(scan_request, 'urls') and scan_request.urls:
        targets = scan_request.urls
    
    if not targets:
        targets = scan_request.domain
        if isinstance(targets, str):
            targets = [targets]
    
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")

    # ✅ Remove '/r/' prefix if it exists
    targets = [url.replace("/r/", "") if url.startswith("/r/") else url for url in targets]
    
    results = await asyncio.gather(*(scan_target(target) for target in targets))
    
    if scan_request.generate_maps:
        map_files = await asyncio.gather(*(create_map(result) for result in results))
        for i, result in enumerate(results):
            if map_files[i]:
                result['Map'] = map_files[i]
    
    if scan_request.save_results:
        output_file = scan_request.output_file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as file:
            json.dump(results, file, indent=4)

    if db is not None:
        try:
            for result in results:
                mongo_result = result.copy()  # Ensure it's serializable
                mongo_result['userId'] = scan_request.userId  # ✅ Add this line
                mongo_result['scanStatus'] = "success"
                mongo_result['created_time'] = datetime.utcnow().isoformat()
                insert_result = await db.Waf_Report.insert_one(mongo_result)
        except Exception as e:
            print(f"[❌] Error saving to MongoDB: {e}")
    return results


@router.get("/health")
async def health_check():
    return {"status": "healthy", "message": "WAF Detection API is running"}