from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from routers.userRoute import router as user_router
import os
import uvicorn

app = FastAPI(
    title="Your API",
    root_path=""
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(user_router, prefix="/api/auth")

@app.get("/")
async def home():
    return "Server is running successfully"

# Handler for Vercel
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Default to 8080 if PORT is not set
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)