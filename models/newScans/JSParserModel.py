from pydantic import BaseModel

# Define a request model
class ScanRequest(BaseModel):
    domain: str  # or 'url' if you prefer
    userId: str