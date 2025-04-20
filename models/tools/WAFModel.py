from pydantic import BaseModel, Field
from typing import List, Optional, Union

class CustomKeyword(BaseModel):
    urls: Optional[List[str]] = Field(default=None, description="List of URLs to scan")
    # Add any other fields that might be in the custom keyword object

class ScanRequest(BaseModel):
    domain: Union[str, List[str]] = Field(default=None, description="Domain or list of domains to scan")
    urls: Optional[List[str]] = Field(default=None, description="Direct list of URLs to scan")
    custom: Optional[CustomKeyword] = Field(default=None, description="Custom keyword object containing URLs")
    generate_maps: bool = Field(default=False, description="Generate visual maps of results")
    save_results: bool = Field(default=False, description="Save results to file")
    output_file: str = Field(default="results/waf_scan_results.json", description="Path to save results")
    userId: str