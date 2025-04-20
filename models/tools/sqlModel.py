from typing import Optional, Dict, Any
from pydantic import BaseModel

class subdoaminModel(BaseModel):
    tool_name: str

class sqlModel(BaseModel):
    domain: str
    techniques: str = "BEUSTQ"
    proxy: str = None  # ✅ Allows `None`
    extract_db: bool = False
    custom: Optional[Dict[str, Any]]
    userId: str
