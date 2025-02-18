from math import trunc
from sys import prefix
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from config.database import db
from routers.userRoute import router as user_router
import uvicorn
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Only allow requests from your React app
    allow_credentials=True,
    allow_methods=["POST","GET","PUT","PATCH","DELETE"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

app.include_router(user_router, prefix="/api/auth")


@app.get("/")
async def home():
    return {"message": "Server is running successfully"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))  # Use PORT from Render, default to 8000 if not set
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)