from pydantic import BaseModel

class SearchRequest(BaseModel):
    domain: str
    dork: str
    userId: str
