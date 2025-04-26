from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from controllers.newScans.googleHackingController import DorkController
from models.newScans.googleHackingModel import SearchRequest
from config.database import get_db



router = APIRouter()

# Initialize controller with error handling
try:
    dork_controller = DorkController()
except Exception as e:
    error_msg = f"Failed to initialize DorkController: {str(e)}"
    print(error_msg)
    raise RuntimeError(error_msg) from e    

@router.get("/google-dorks")
async def get_dorks():
    """Get available Google dork categories"""
    try:
        return dork_controller.get_dork_categories()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/google-search")
async def search(request: SearchRequest):
    """Perform Google dork search"""
    db = get_db()
    try:
        result, status_code = dork_controller.perform_search(request.domain, request.dork)
        if status_code != 200:
            raise HTTPException(status_code=status_code, detail=result.get("message"))

        if db is not None:
            try:
                mongo_result = result.copy()  # Ensure it's serializable
                mongo_result['user_id'] = request.userId
                insert_result = await db.EmailAudit_Report.insert_one(mongo_result)
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))