from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class WhoisRequest(BaseModel):
    domain: str
    userId: str
    save_json: Optional[bool] = False
    filename: Optional[str] = "whois_info.json"
    created_time: datetime = Field(default_factory=datetime.utcnow)
    scanStatus: str = "success"
