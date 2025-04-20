from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

class SubdomainEntry(BaseModel):
    subdomain: str
    ip: str

class subdomainReport(BaseModel):
    domain: str
    subdomains: List[str]
    live_subdomains: List[SubdomainEntry]
    logs: List[Dict[str, Optional[str]]]  # Allow None values in logs
    timestamp: datetime

# class ScanningLog(BaseModel):
#     domain: str
#     timestamp: datetime
#     event: str
#     details: Optional[str] = None  # Store additional information or errors
