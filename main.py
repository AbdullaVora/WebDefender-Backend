from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from routers.userRoute import router as user_router
from mangum import Mangum  # ASGI Adapter for Vercel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(user_router, prefix="/api/auth")

@app.get("/")
async def home():
    return {"message": "Server is running successfully"}

# ASGI Adapter for Vercel
handler = Mangum(app)
