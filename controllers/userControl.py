from config.database import get_db
from models.userModel import UserModel
from fastapi import HTTPException
from pymongo.errors import PyMongoError
import json
import jwt
import datetime
from passlib.hash import argon2  # Argon2 for password hashing

# Secret key for JWT (Keep it safe)
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"


class UserController:
    @staticmethod
    async def register_user(register: UserModel):
        try:
            db = get_db()
            # Step 1: Convert request model to dictionary
            user_dict = register.model_dump()

            # Remove confirmPassword from the dictionary before saving to the database
            if "confirmPassword" in user_dict:
                del user_dict["confirmPassword"]

            # 🔒 Step 2: Hash the password before storing it
            if "password" in user_dict and user_dict["password"]:
                user_dict["password"] = argon2.hash(user_dict["password"])
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Password is required"
                )

            # Step 3: Insert user into the database
            result = await db.users.insert_one(user_dict)
            user_id = str(result.inserted_id)  # Get user ID

            # Step 4: Generate JWT Token for the registered user
            token_payload = {
                "user_id": user_id,
                "username": user_dict["name"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
            }
            token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)

            # Step 5: Store the token in the database
            token_data = {
                "user_id": user_id,
                "token": token,
                "created_at": datetime.datetime.utcnow()
            }
            await db.tokens.insert_one(token_data)  # Save token in a "tokens" collection

            # Step 6: Prepare response data (Exclude password and confirmPassword)
            response_data = user_dict.copy()
            response_data["_id"] = user_id
            del response_data["password"]  # Remove password from response

            # Step 7: Return response with token
            return {
                "message": "User Registered Successfully",
                "token": token,  # Include JWT token in response
                "data": response_data,
                "status_code": 201,
            }

        except PyMongoError as e:
            print("MongoDB Error:", str(e))
            raise HTTPException(
                status_code=500,
                detail=f"Database error occurred: {str(e)}"
            )

        except Exception as e:
            print("Unexpected Error:", str(e))
            print("Error occurred at step:", e.__traceback__.tb_lineno)  # Show the line number
            raise HTTPException(
                status_code=500,
                detail=f"An unexpected error occurred: {str(e)}"
            )

    @staticmethod
    async def login_user(email: str, password: str):
        try:
            db = get_db()  # Get the database instance
            print(email, password)
            # step 1 find user
            user = await db.users.find_one({"email": email})
            print("User found:", user)

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # step 2 verify password
            if not argon2.verify(password, user["password"]):
                raise HTTPException(status_code=401, detail="Invalid password")

            # step 3 generate token
            token_payload = {
                "user_id": str(user["_id"]),
                "username": user["name"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
            }

            token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)

            token_data = {
                "user_id": str(user["_id"]),
                "token": token,
                "create_at": datetime.datetime.utcnow()
            }

            await db.tokens.insert_one(token_data)

            # step 5 response data
            response_data = {
                "_id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"]
            }

            # step 6 return response
            return {
                "message": "Login Success",
                "user_id": str(user["_id"]),
                "token": token,
                "data": response_data,
                "status_code": 200
            }

        except PyMongoError as e:
            print("MongoDB Error:", str(e))
            raise HTTPException(
                status_code=500,
                detail=f"Database error occurred: {str(e)}"
            )

        except Exception as e:
            print("Unexpected Error:", str(e))
            print("Error occurred at step:", e.__traceback__.tb_lineno)  # Show the line number
            raise HTTPException(
                status_code=500,
                detail=f"An unexpected error occurred: {str(e)}"
            )
