from fastapi import APIRouter, Depends
from controllers.forgotPasswordController import (
    forgot_password,
    verify_otp,
    reset_password
)
from models.forgotPasswordModel import (
    ForgotPasswordRequest,
    VerifyOTPRequest,
    ResetPasswordRequest
)

router = APIRouter()

@router.post("/forgot-password")
async def forgot_password_route(request: ForgotPasswordRequest):
    return await forgot_password(request)

@router.post("/verify-otp")
async def verify_otp_route(request: VerifyOTPRequest):
    return await verify_otp(request)

@router.post("/reset-password")
async def reset_password_route(request: ResetPasswordRequest):
    return await reset_password(request)