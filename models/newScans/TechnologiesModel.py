from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class TechnologyInfo(BaseModel):
    technology: str  # Changed to lowercase to match JSON conventions
    version: str

class WappalyzerScanResponse(BaseModel):
    website: str
    detected_technologies: Dict[str, List[TechnologyInfo]]
    created_time: datetime = Field(default_factory=datetime.utcnow)
    scanStatus: str = "success"


class WappalyzerScanRequest(BaseModel):  # New model for request validation
    url: str
    userId: str

class WappalyzerScanHistory(BaseModel):
    url: str
    created_at: datetime
    results: WappalyzerScanResponse