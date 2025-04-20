from fastapi import APIRouter, Body, HTTPException
from controllers.newScans.WHOIS import WhoisController
from models.newScans.WHOISModel import WhoisRequest
from config.database import db

router = APIRouter()

@router.post("/whois")
async def post_whois_info(request: WhoisRequest):
    """
    Fetch WHOIS information for a domain via POST.
    
    Request Body:
    - domain: The domain name to query (e.g., example.com)
    - save_json: Whether to save results to JSON file (default: False)
    - filename: Output filename (default: whois_info.json)
    
    Returns:
    - WHOIS information in JSON format
    """
    try:
        whois_data = WhoisController.fetch_whois_info(request.domain)
        
        if request.save_json:
            save_result = WhoisController.save_whois_to_json(whois_data, request.filename)
            whois_data["save_result"] = save_result
            
        result = {
            "scanType": "WHOIS",
            "user_id": request.userId,
            "status": "success",
            "domain": request.domain,
            "data": whois_data
        }
    
        if db is not None:
            try:
                mongo_result = result.copy()  # Ensure it's serializable
                insert_result = await db.Whois_Report.insert_one(mongo_result)
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return result
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))