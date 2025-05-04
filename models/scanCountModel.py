from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
from bson import ObjectId

class ScanCountCreate(BaseModel):
    userId: str = Field(..., description="The user's unique identifier")
    scan_count: int = Field(default=1, description="Count to increment by (typically 1)")

class ScanCountResponse(BaseModel):
    userId: str
    scan_count: int
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={ObjectId: str},
        arbitrary_types_allowed=True
    )