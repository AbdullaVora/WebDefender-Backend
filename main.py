from fastapi import FastAPI, Request
from starlette.middleware.cors import CORSMiddleware
from routers.userRoute import router as user_router
import os
import uvicorn
from fastapi.responses import RedirectResponse

app = FastAPI(
    title="Your API",
    root_path="/"
)

# Middleware to remove double slashes
@app.middleware("http")
async def remove_double_slash(request: Request, call_next):
    corrected_path = request.url.path.replace("//", "/")
    if corrected_path != request.url.path:
        return RedirectResponse(url=corrected_path)
    return await call_next(request)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include user routes with correct prefix handling
app.include_router(user_router, prefix="/api/auth")

@app.get("/")
async def home():
    return "Server is running successfully"

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Default to 8080 if PORT is not set
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
