# routers/alldata.py
from fastapi import APIRouter, HTTPException, Query, Body
from config.database import get_db
import asyncio
from bson import ObjectId
from typing import List, Union

router = APIRouter()

async def fetch_data(collection_name: str, user_id: str = None):
    db = get_db()
    collection = db[collection_name]
    results = []
    try:
        query = {"userId": user_id} if user_id else {}
        async for doc in collection.find(query):
            doc["_id"] = str(doc["_id"])
            results.append(doc)
    except Exception as e:
        raise Exception(f"Error fetching {collection_name}: {e}")
    return results

from typing import List
from fastapi import Body, HTTPException

@router.delete("/reports")
async def delete_reports(
    reportType: str = Body(..., embed=True),
    reportIds: List[str] = Body(..., embed=True),
    user_id: str = Body(None)
):
    try:
        db = get_db()
        
        if not reportType:
            raise HTTPException(status_code=400, detail="reportType is required")
        if not reportIds:
            raise HTTPException(status_code=400, detail="reportIds is required")

        collection = db[reportType]
        object_ids = [ObjectId(id) for id in reportIds]
        
        query = {"_id": {"$in": object_ids}}
        if user_id:
            query["userId"] = user_id
            
        result = await collection.delete_many(query)
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="No documents found to delete")
            
        return {
            "status": "success",
            "deleted_count": result.deleted_count,
            "collection": reportType
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.get("/reports")
async def get_all_data(userId: str = Query(None)):
    print(userId)
    try:
        subdomain_reports = fetch_data("subdomain_reports", userId)
        sql_reports = fetch_data("sql_reports", userId)
        hidden_files = fetch_data("hidden_files", userId)
        Xss_Report = fetch_data("Xss_Report", userId)
        Waf_Report = fetch_data("Waf_Report", userId)
        JsParser_Report = fetch_data("JsParser_Report", userId)
        EmailAudit_Report = fetch_data("EmailAudit_Report", userId)
        Whois_Report = fetch_data("Whois_Report", userId)
        Cors_Report = fetch_data("Cors_Report", userId)

        subdomain_reports, sql_reports, hidden_files, Xss_Report, Waf_Report, JsParser_Report, EmailAudit_Report, Whois_Report, Cors_Report = await asyncio.gather(
            subdomain_reports, sql_reports, hidden_files, Xss_Report, Waf_Report, JsParser_Report, EmailAudit_Report, Whois_Report, Cors_Report
        )

        return {
            "subdomain_reports": subdomain_reports,
            "sql_reports": sql_reports,
            "hidden_files": hidden_files,
            "Xss_Report": Xss_Report,
            "Waf_Report": Waf_Report,
            "JsParser_Report": JsParser_Report,
            "EmailAudit_Report": EmailAudit_Report,
            "Whois_Report": Whois_Report,
            "Cors_Report": Cors_Report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))