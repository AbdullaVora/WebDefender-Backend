from typing import Optional
from pydantic import BaseModel

class WhoisRequest(BaseModel):
    domain: str
    userId: str
    save_json: Optional[bool] = False
    filename: Optional[str] = "whois_info.json"
