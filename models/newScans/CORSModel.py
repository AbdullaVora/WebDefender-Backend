from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class SeverityLevel(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"

class ScanResult(BaseModel):
    timestamp: str
    host: str
    origin: str
    classification: str
    description: str
    severity: SeverityLevel
    exploitation: str
    allow_credentials: Optional[str]
    http_status: int

class ScanRequest(BaseModel):
    domain: str
    threads: int = 5
    retries: int = 3  # Add this
    delay: float = 0.3
    timeout: int = 30  # Add this
    cookies: Optional[str] = None


class ScanBatchRequest(BaseModel):
    domains: List[str]
    threads: int = 5
    retries: int = 3  # Add this
    delay: float = 0.3
    timeout: int = 30  # Add this
    cookies: Optional[str] = None

class ScanLog(BaseModel):
    message: str
    level: str  # "info", "warning", "error"
    timestamp: str

class ScanResponse(BaseModel):
    results: List[ScanResult]
    logs: List[ScanLog]