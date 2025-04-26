from pydantic import BaseModel, Field
from datetime import datetime

# Define a request model
class ScanRequest(BaseModel):
    domain: str  # or 'url' if you prefer
    userId: str
    created_time: datetime = Field(default_factory=datetime.utcnow)
    scanStatus: str = "success"
