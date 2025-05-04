from fastapi import APIRouter, HTTPException, status, Depends
from models.scanCountModel import (
    ScanCountCreate,
    ScanCountResponse
)
from config.database import get_db
from datetime import datetime
from bson import ObjectId
from typing import Optional

router = APIRouter()

async def get_user_scan_count(userId: str) -> Optional[dict]:
    db = get_db()

    # Check if the user exists in the database
    return await db["scan_counts"].find_one({"userId": userId})

@router.post(
    "/scanCount",
    response_model=ScanCountResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Scan count created/updated successfully"},
        400: {"description": "Invalid request data"},
        500: {"description": "Internal server error"}
    }
)
async def upsert_scan_count(scan_data: ScanCountCreate):
    print(scan_data)
    db = get_db()
    try:
        # Always increment by 1 (or by scan_data.scan_count if you want flexibility)
        increment_value = scan_data.scan_count  # Typically 1 in your case
        
        # Use find_one_and_update with upsert for atomic operation
        result = await db["scan_counts"].find_one_and_update(
            {"userId": scan_data.userId},
            {
                "$inc": {"scan_count": increment_value},  # Increment the count
                "$setOnInsert": {  # Only set these on insert (creation)
                    "created_at": datetime.utcnow(),
                    "userId": scan_data.userId
                },
                "$set": {  # Always update
                    "updated_at": datetime.utcnow()
                }
            },
            upsert=True,  # Create if doesn't exist
            return_document=True  # Return the updated document
        )
        
        if result:
            return result
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan count operation failed"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )
@router.get(
    "/getscanCounts/{userId}",
    response_model=ScanCountResponse,
    responses={
        404: {"description": "Scan count not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_scan_count(userId: str):
    db = get_db()
    try:
        count_data = await get_user_scan_count(userId)
        if count_data:
            return count_data
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan count found for user {userId}"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )