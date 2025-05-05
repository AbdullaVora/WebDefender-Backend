import random
import string
from datetime import datetime, timedelta
from fastapi import HTTPException, status, Depends
from models.forgotPasswordModel import ForgotPasswordRequest, VerifyOTPRequest, ResetPasswordRequest
from config.database import get_db
from utils.emailUtils import send_email
from utils.security import get_password_hash

# In-memory storage for OTPs
otp_storage = {}

async def forgot_password(request: ForgotPasswordRequest):
    db = get_db()
    # Check if user exists
    user = await db.users.find_one({"email": request.email})
    if not user:
        return {"message": "If this email exists, we've sent an OTP", "email": request.email}
    
    # Generate OTP
    otp = ''.join(random.choices(string.digits, k=6))
    expiration_time = datetime.now() + timedelta(minutes=15)
    
    otp_storage[request.email] = {
        "otp": otp,
        "expires_at": expiration_time,
        "verified": False
    }
    
    await send_email(
        recipient=request.email,
        subject="Password Reset OTP",
        body=f"Your OTP is: {otp}. Expires in 15 minutes."
    )
    
    return {"message": "If this email exists, we've sent an OTP", "email": request.email}

async def verify_otp(request: VerifyOTPRequest):
    otp_data = otp_storage.get(request.email)
    if not otp_data:
        raise HTTPException(status_code=400, detail="OTP expired or invalid")
    
    if datetime.now() > otp_data["expires_at"]:
        del otp_storage[request.email]
        raise HTTPException(status_code=400, detail="OTP has expired")
    
    if otp_data["otp"] != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    otp_storage[request.email]["verified"] = True
    return {"message": "OTP verified successfully"}

async def reset_password(request: ResetPasswordRequest):
    
    db = get_db()
        
    # Validate passwords match
    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )    
    otp_data = otp_storage.get(request.email)
    if not otp_data or not otp_data.get("verified"):
        raise HTTPException(status_code=400, detail="OTP not verified")
    
    if otp_data["otp"] != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if datetime.now() > otp_data["expires_at"]:
        del otp_storage[request.email]
        raise HTTPException(status_code=400, detail="OTP expired")
    
    hashed_password = get_password_hash(request.new_password)
    await db.users.update_one(
            {"email": request.email},
            {"$set": {"password": hashed_password}}
        )
    
    del otp_storage[request.email]
    return {"message": "Password updated successfully"}