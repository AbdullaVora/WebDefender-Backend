from pydantic import BaseModel
from typing import List, Optional, Union

class CustomScan(BaseModel):
    urls: Optional[List[str]] = None
    payloads: Optional[List[str]] = None


class ScanRequest(BaseModel):
    domain: Optional[str] = None
    custom: Optional[CustomScan] = None
    userId: str
