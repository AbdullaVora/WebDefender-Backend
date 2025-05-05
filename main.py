from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from routers.userRoute import router as user_router
from routers.tools.subdomainRoute import router as subdomain_router
from routers.tools.sqlRoute import router as sql_router
from routers.tools.HiddenFilesRoute import router as hidden_files_router
from routers.tools.WAFRouter import router as waf_router
from routers.tools.XSSRoute import router as Xss_Router
from routers.newScans.googleHackingRoute import router as googleHacking_Route
from routers.newScans.WHOISRoute import router as Whois_Route
from routers.newScans.emailAuditRoute import router as email_Route
from routers.newScans.JSParserRoute import router as JSParser_Route
from routers.newScans.TechnologiesRouter import router as Technologies_Route
from routers.newScans.CORSRouter import router as Cors_Route
from routers.ReportsRouter import router as reports_router
from routers.scanCountRoute import router as scanCount_Router
from routers.newScans.WebReconRouter import router as Web_Recon
from routers.forgotPasswordRouter import router as forgot_route

from config.database import db, connect_to_mongo

import os
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Your API",
    root_path=""
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","http://localhost:5174","http://localhost:5175", "https://web-defender-admin.vercel.app"],  # Allow frontend origin
    allow_credentials=True,
    allow_methods=["POST","GET","DELETE","PUT","PATCH"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Include routers
app.include_router(user_router, prefix="/api/auth")  # User authentication routes
app.include_router(subdomain_router, prefix="/api/tools")  # Tools-related routes
app.include_router(sql_router, prefix="/api/tools")  # Tools-related routes
app.include_router(hidden_files_router, prefix="/api/tools")
app.include_router(waf_router, prefix="/api/tools")
app.include_router(waf_router, prefix="/api/tools")
app.include_router(Xss_Router, prefix="/api/tools")
app.include_router(googleHacking_Route, prefix="/api/newScans")
app.include_router(Whois_Route, prefix="/api/newScans")
app.include_router(email_Route, prefix="/api/newScans")
app.include_router(JSParser_Route, prefix="/api/newScans")
app.include_router(Technologies_Route, prefix="/api/newScans")
app.include_router(Cors_Route, prefix="/api/newScans")
app.include_router(Web_Recon, prefix="/api/newScans")

app.include_router(reports_router, prefix="/api")
app.include_router(scanCount_Router, prefix="/api")  # Scan count routes
app.include_router(forgot_route, prefix="/api/auth")


@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()
    
# Root endpoint
@app.get("/")   
async def home():
    return "Server is running successfully"

# Run the app using Uvicorn
if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")  # Default to 127.0.0.1 if HOST is not set
    port = int(os.environ.get("PORT", 8002))  # Default to 8080 if PORT is not set
    uvicorn.run("main:app", host=host, port=port, reload=True)
