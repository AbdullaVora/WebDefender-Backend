from pydantic import BaseModel, Field
from typing import List, Optional

class CustomConfig(BaseModel):
    urls: Optional[List[str]] = Field(
        None,
        description="Array of URLs to scan. Overrides 'domain' if provided."
    )
    payloads: Optional[List[str]] = Field(
        None,
        description="Array of payloads to scan. Overrides 'domain' and 'urls' if provided."
    )
    threads: Optional[int] = Field(
        15,
        description="Number of threads to use for scanning."
    )
    delays: Optional[float] = Field(
        0.3,
        description="Delay between requests in seconds."
    )
    retries: Optional[int] = Field(
        3,
        description="Number of retries for failed requests."
    )
    timeout: Optional[int] = Field(
        30,
        description="Timeout for each request in seconds."
    )

class ScanRequest(BaseModel):
    domain: Optional[str] = Field(
        "",
        description="Domain to scan. Ignored if 'urls' or 'payloads' are provided in 'custom'."
    )
    path: Optional[str] = Field(
        "",
        description="Path for the scan (e.g., 'Hidden-Files-Reconnaissance')."
    )
    custom: Optional[CustomConfig] = Field(
        None,
        description="Custom configuration for the scan, including URLs, payloads, and other parameters."
    )
    userId: str