
from typing import Union, Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class ToolResult(BaseModel):
    tool_name: str
    status: str
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    file_data: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = Field(default_factory=dict)
    error: Optional[str] = None
    traceback: Optional[str] = None
class ScanResponse(BaseModel):
    target: str
    status: str
    results: List[ToolResult]
    merged_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str

class ScanRequest(BaseModel):
    target: str
    userId: str

# from pydantic import BaseModel
# from typing import Dict, List, Optional, Any

# class ScanRequest(BaseModel):
#     target: str
#     tools: Optional[List[str]] = None  # If None, run all tools

# class ToolResult(BaseModel):
#     success: bool
#     data: Optional[Dict[str, Any]] = None
#     error: Optional[str] = None

# class ScanResponse(BaseModel):
#     target: str
#     results: Dict[str, ToolResult]
#     scan_time: float