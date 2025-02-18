from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from routers.userRoute import router as user_router
from mangum import Mangum

app = FastAPI(
    title="Your API",
    root_path="/"
)

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
    return "Server is running successfully"

# Handler for Vercel
handler = Mangum(app, lifespan="off")