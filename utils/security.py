from fastapi import HTTPException, status
from passlib.hash import argon2

def get_password_hash(password: str) -> str:
    """Generate Argon2 hash using passlib's defaults"""
    try:
        return argon2.hash(password)
    except (ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password hashing failed: {str(e)}"
        )

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2 hash"""
    try:
        return argon2.verify(plain_password, hashed_password)
    except (ValueError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password verification failed: {str(e)}"
        )