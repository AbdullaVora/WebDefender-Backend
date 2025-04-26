# routes/email_router.py
from fastapi import APIRouter, HTTPException, Depends
from controllers.newScans.emailAuditController import EmailSecurityController
from models.newScans.emailAuditModel import EmailSecurityResponse, EmailSecurityRequest
import dns.resolver
from config.database import get_db

db = get_db()

router = APIRouter()

@router.post("/emailAudit", response_model=EmailSecurityResponse)
async def check_email_security(request: EmailSecurityRequest):
    """
    Check email security configuration for a domain including:
    - SPF records
    - DKIM records (with optional selector)
    - DMARC records
    - MX records
    - DNSSEC status
    - Security validation audit
    
    Expects JSON payload:
    {
        "domain": "example.com",
        "dkim_selector": "optional_selector"
    }
    """
    controller = EmailSecurityController()
    try:
        data = controller.check_email_security(
            domain=request.domain,
            dkim_selector=request.dkim_selector
        )

        if db is not None:
            try:
                mongo_result = data.copy()  # Ensure it's serializable
                mongo_result["user_id"] = request.userId
                insert_result = await db.EmailAudit_Report.insert_one(mongo_result)
            except Exception as e:
                print(f"[❌] Error saving to MongoDB: {e}")

        return data
    
    except dns.resolver.NXDOMAIN:
        raise HTTPException(status_code=404, detail="Domain not found")
    except dns.resolver.NoAnswer:
        raise HTTPException(status_code=404, detail="No DNS records found for this domain")
    except dns.exception.DNSException as e:
        raise HTTPException(status_code=500, detail=f"DNS lookup failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/scan/{domain}", response_model=EmailSecurityResponse)
async def scan_domain(domain: str, selector: str = "default"):
    """
    API endpoint to scan a domain via GET request
    """
    controller = EmailSecurityController()
    try:
        return controller.check_email_security(domain=domain, dkim_selector=selector)
    except dns.resolver.NXDOMAIN:
        raise HTTPException(status_code=404, detail="Domain not found")
    except dns.resolver.NoAnswer:
        raise HTTPException(status_code=404, detail="No DNS records found for this domain")
    except dns.exception.DNSException as e:
        raise HTTPException(status_code=500, detail=f"DNS lookup failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/export/{domain}")
async def export_results(domain: str, selector: str = "default"):
    """
    API endpoint to export scan results to JSON file
    """
    controller = EmailSecurityController()
    try:
        filename = controller.export_results(domain=domain, dkim_selector=selector)
        return {
            "success": True,
            "message": "Report exported successfully",
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@router.get("/report/{domain}")
async def get_report(domain: str, selector: str = "default"):
    """
    API endpoint to get only validation summary for a domain
    """
    controller = EmailSecurityController()
    try:
        return controller.get_summary(domain=domain, dkim_selector=selector)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")