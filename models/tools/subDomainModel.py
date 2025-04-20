from typing import List, Optional
from pydantic import BaseModel

class SubdomainScanRequest(BaseModel):
    domain: Optional[str] = None
    custom: Optional[dict] = None
    userId: str
