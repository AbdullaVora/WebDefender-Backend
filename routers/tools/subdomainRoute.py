from fastapi import APIRouter, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from controllers.tools.subDomainController import SubdomainScanner  # Ensure correct import
from config.database import db
from models.tools.subDomainModel import SubdomainScanRequest
from config.database import db

router = APIRouter()


@router.post("/Subdomain-Reconnaissance")
async def subdomain_scan(request: SubdomainScanRequest):
    domain = request.domain.strip() if request.domain else None
    urls = request.custom.get("urls") if request.custom else None
    payloads = request.custom.get("payloads") if request.custom else None
    userId = request.userId

    if not userId:
        return "userId does not exist"

    if urls:
        targets = [url.strip() for url in urls if url.strip()]
        print(f"Received URLs: {targets}")
    elif domain:
        targets = [domain]
        print(f"Received domain: {domain}")
    else:
        raise HTTPException(status_code=400, detail="Either 'domain' or 'urls' must be provided")

    # Check if a scan is already in progress
    # existing_scan = await db.subdomain_reports.find_one({"domain": {"$in": targets}})
    # if existing_scan:
    #     existing_scan["_id"] = str(existing_scan["_id"])  # ✅ Convert ObjectId to string
    #     return {
    #         "scanType": "Subdomain-Reconnaissance",
    #         "status": "running",
    #         "message": f"Scan for {targets} is already in progress.",
    #         "results": existing_scan
    #     }

    # **Fix Here:** Properly handle multiple targets
    scan_results = []
    for target in targets:
        subdomain_controller = SubdomainScanner(target)  # Pass single domain, not list
        result = await subdomain_controller.run_scan(payloads=payloads)
        scan_results.append(result)

    data = {
        "scanType": "Subdomain-Reconnaissance",
        "userId": userId,
        "status": 200,
        "message": f"Scan completed for {targets}",
        "results": scan_results  # ✅ Full scan results returned as a list
    }

    if db is not None:
        try:
            result = await db.subdomain_reports.insert_one(data)
            data["_id"] = str(result.inserted_id)  # ✅ Convert ObjectId to string
            print("[✔] Stored in MongoDB with ID:", data["_id"])
        except Exception as e:
            print(f"[❌] Error saving to MongoDB: {e}")

    return data

# Define request model
# class SubdomainScanRequest(BaseModel):
#     domain: str


# @router.post("/Subdomain-Reconnaissance")
# async def subdomain_scan(request: SubdomainScanRequest):
#     domain = request.domain.strip()
#     print(f"Received domain: {domain}")

#     if not domain:
#         raise HTTPException(status_code=400, detail="Domain is required")

#     # Check if a scan is already in progress
#     existing_scan = await db.subdomain_reports.find_one({"domain": domain})
#     if existing_scan:
#         existing_scan["_id"] = str(existing_scan["_id"])  # ✅ Convert ObjectId to string
#         return {
#             "status": "running",
#             "message": f"Scan for {domain} is already in progress.",
#             "results": existing_scan
#         }

#     # Start scanning and wait for it to complete
#     subdomain_controller = SubdomainScanner(domain)
#     scan_results = await subdomain_controller.run_scan()

#     return {
#         "status": 200,
#         "message": f"Scan completed for {domain}",
#         "results": scan_results  # ✅ No more null! Full scan results returned.
#     }



# ✅ Get Scan Status
@router.get("/Subdomain-Reconnaissance-status/{domain}")
async def get_scan_status(domain: str):
    """Fetch scan results from MongoDB."""
    scan = await db.subdomain_reports.find_one({"domain": domain})

    if not scan:
        raise HTTPException(status_code=404, detail="No scan found for this domain.")

    return {
        "domain": scan.get("domain", "Unknown"),  # Default to "Unknown" if missing
        # "status": scan.get("status", "Pending"),  # Default "Pending" status
        "subdomains": scan.get("subdomains", []),  # Default to empty list
        "live_subdomains": scan.get("live_subdomains", []),
        "logs": scan.get("logs", []), # Default
        "created_at": scan.get("timestamp", "N/A"),  # Default to "N/A" if missing
    }


# ✅ Get All Scan Records
@router.get("/all-scans")
async def get_all_scans():
    """Fetch all scans from MongoDB."""
    scans = []
    cursor = db.subdomain_reports.find()
    async for document in cursor:
        scans.append(document)
    return scans

# ✅ Delete a Scan
@router.delete("/delete-scan/{domain}")
async def delete_scan(domain: str):
    """Delete a scan result."""
    result = await db.subdomain_reports.delete_one({"domain": domain})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": f"Scan for {domain} deleted successfully"}
