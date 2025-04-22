# models/cors_models.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict

class ScanRequest(BaseModel):
    urls: List[str] = Field(..., description="List of URLs to scan")
    thread_count: int = Field(5, description="Number of threads for scanning")
    delay: float = Field(0, description="Delay between requests in seconds")
    headers: Optional[Dict[str, str]] = Field(None, description="Additional headers for requests")

class ScanResult(BaseModel):
    timestamp: str
    host: str
    origin: str
    classification: str
    description: str
    severity: str
    exploitation: str
    allow_credentials: Optional[str]
    http_status: int

class ScanResponse(BaseModel):
    scan_id: str
    message: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    results: Optional[List[ScanResult]] = None

class ScanFileRequest(BaseModel):
    file_path: str = Field(..., description="Path to file containing URLs")
    thread_count: int = Field(5, description="Number of threads for scanning")
    delay: float = Field(0, description="Delay between requests in seconds")
    headers: Optional[Dict[str, str]] = Field(None, description="Additional headers for requests")