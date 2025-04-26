
from fastapi import APIRouter, HTTPException
from controllers.tools.sqlController import scan_url
from models.tools.sqlModel import sqlModel
from config.database import db
from datetime import datetime

router = APIRouter()

@router.post("/SQLInjectionScanner")
async def scan(request: sqlModel):
    custom = request.custom or {}
    
    # Extract values from the request and custom dictionary
    domain = request.domain
    urls = custom.get("urls", [])  # Get urls from custom dictionary
    
    if not domain and not urls:
        raise HTTPException(status_code=400, detail="Either 'domain' or 'custom.urls' array is required.")

    techniques = custom.get("techniques", "BEUSTQ") 
    proxy = custom.get("proxy", None)
    database = custom.get("database", False)
    payloads = custom.get("payloads", None)

    # Determine which URLs to scan
    urls_to_scan = [domain] if domain else urls

    results = []
    
    import asyncio
    scan_tasks = [scan_url(url, techniques, proxy, database, payloads) for url in urls_to_scan]
    results = await asyncio.gather(*scan_tasks)

    data = {
        "scanType": "SQLInjectionScanner",
        "user_id": request.userId,
        "status": "200",
        "message": "Scan completed",
        "results": results,
        "created_time": datetime.utcnow().isoformat(), 
        "scanStatus": "success"
    }

    if db is not None:
        try:
            # Create a serializable version of the result for MongoDB
            mongo_result = data.copy()
            insert_result = await db.sql_reports.insert_one(mongo_result)
            
            # Return a clean result with string ID
            data["_id"] = str(insert_result.inserted_id)
            print("[✔] Stored in MongoDB with ID:", data["_id"])
        except Exception as e:
            print(f"[❌] Error saving to MongoDB: {e}")

    return data

# # Get scan status
# @app.route('/api/scan/<task_id>/status', methods=['GET'])
# def get_scan_status(task_id):
#     try:
#         # Check if task exists
#         status_response = sqlmap_api_request(f'scan/{task_id}/status')
        
#         if 'error' in status_response:
#             return jsonify({"error": "Invalid task ID"}), 404
        
#         return jsonify(status_response)
        
#     except Exception as e:
#         logger.error(f"Error getting scan status: {str(e)}")
#         return jsonify({"error": str(e)}), 500
