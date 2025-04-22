# routers/alldata.py
from fastapi import APIRouter, HTTPException
from config.database import db
import asyncio

router = APIRouter()

async def fetch_data(collection_name: str):
    collection = db[collection_name]
    results = []
    try:
        async for doc in collection.find():
            doc["_id"] = str(doc["_id"])
            results.append(doc)
    except Exception as e:
        raise Exception(f"Error fetching {collection_name}: {e}")
    return results

@router.get("/reports")
async def get_all_data():
    try:
        subdomain_reports = fetch_data("subdomain_reports")
        sql_reports = fetch_data("sql_reports")
        hidden_files = fetch_data("hidden_files")
        Xss_Report = fetch_data("Xss_Report")
        Waf_Report = fetch_data("Waf_Report")
        JsParser_Report = fetch_data("JsParser_Report")
        EmailAudit_Report = fetch_data("EmailAudit_Report")

        subdomain_reports, sql_reports, hidden_files, Xss_Report, Waf_Report, JsParser_Report, EmailAudit_Report = await asyncio.gather(
            subdomain_reports, sql_reports, hidden_files, Xss_Report, Waf_Report, JsParser_Report, EmailAudit_Report
        )

        return {
            "subdomain_reports": subdomain_reports,
            "sql_reports": sql_reports,
            "hidden_files": hidden_files,
            "Xss_Report": Xss_Report,
            "Waf_Report": Waf_Report,
            "JsParser_Report": JsParser_Report,
            "EmailAudit_Report": EmailAudit_Report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
