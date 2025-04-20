from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from controllers.newScans.JSParserController import SecretScanner
from models.newScans.JSParserModel import ScanRequest
import json
from config.database import db

router = APIRouter()

@router.post("/JSParser")
async def scan_website(request: ScanRequest):
    """
    Scan a website for secrets in JavaScript files
    
    - **url**: Website URL to scan (e.g., https://example.com)
    """
    try:
        results = SecretScanner.scan_target(request.domain)
        result = {
            "status": "success",
            "results": results
        }

        if db is not None:
            try:
                mongo_result = result.copy()  # Ensure it's serializable
                mongo_result['user_id'] = request.userId
                insert_result = await db.JsParser_Report.insert_one(mongo_result)
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return result
    
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error during scanning: {str(e)}"
        )

@router.get("/results")
async def get_scan_results():
    """
    Get the latest scan results from the JSON output file
    """
    try:
        with open(SecretScanner.JSON_OUTPUT, "r") as f:
            results = json.load(f)
        return {
            "status": "success",
            "results": results
        }
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="No scan results found. Please run a scan first."
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error reading results: {str(e)}"
        )