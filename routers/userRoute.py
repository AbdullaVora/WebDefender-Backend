from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer
from models.userModel import UserModel, LoginModel, UserUpdateModel
from controllers.userControl import UserController
from typing import Annotated  # For Python 3.9+


router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # or your login endpoint

@router.post("/register")
async def register_user(register: UserModel):
    result = await UserController.register_user(register)
    return result  # Make sure we're returning this correctly

@router.post("/login")
async def login_user(login: LoginModel):
    print("Login route hit")
    # Pass the entire LoginModel object instead of individual fields
    result = await UserController.login_user(login)
    return result

@router.put("/update/{user_id}")
async def update_user(
    user_id: str,
    update_data: UserUpdateModel,
    token: Annotated[str, Depends(oauth2_scheme)]  # Correct dependency injection
):
    result = await UserController.update_user(user_id, update_data, token)
    return result