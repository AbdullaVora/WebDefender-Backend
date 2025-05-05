# from config.database import get_db
# from models.userModel import UserModel, UserUpdateModel, LoginModel
# from fastapi import HTTPException, status
# from pymongo.errors import PyMongoError
# import json
# import jwt
# import datetime
# from passlib.hash import argon2  # Argon2 for password hashing
# from bson import ObjectId
# from datetime import datetime


# # Secret key for JWT (Keep it safe)
# SECRET_KEY = "your_secret_key"
# ALGORITHM = "HS256"


# class UserController:
#     @staticmethod
#     async def register_user(register: UserModel):
#         try:
#             db = get_db()
#             # Step 1: Convert request model to dictionary
#             user_dict = register.model_dump()

#             # Remove confirmPassword from the dictionary before saving to the database
#             if "confirmPassword" in user_dict:
#                 del user_dict["confirmPassword"]

#             # 🔒 Step 2: Hash the password before storing it
#             if "password" in user_dict and user_dict["password"]:
#                 user_dict["password"] = argon2.hash(user_dict["password"])
#             else:
#                 raise HTTPException(
#                     status_code=400,
#                     detail="Password is required"
#                 )

#             # Step 3: Insert user into the database
#             result = await db.users.insert_one(user_dict)
#             user_id = str(result.inserted_id)  # Get user ID

#             # Step 4: Generate JWT Token for the registered user
#             token_payload = {
#                 "user_id": user_id,
#                 "username": user_dict["name"],
#                 "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
#             }
#             token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)

#             # Step 5: Store the token in the database
#             token_data = {
#                 "user_id": user_id,
#                 "token": token,
#                 "created_at": datetime.datetime.utcnow()
#             }
#             await db.tokens.insert_one(token_data)  # Save token in a "tokens" collection

#             # Step 6: Prepare response data (Exclude password and confirmPassword)
#             response_data = user_dict.copy()
#             response_data["_id"] = user_id
#             del response_data["password"]  # Remove password from response

#             # Step 7: Return response with token
#             return {
#                 "message": "User Registered Successfully",
#                 "token": token,  # Include JWT token in response
#                 "data": response_data,
#                 "status_code": 201,
#             }

#         except PyMongoError as e:
#             print("MongoDB Error:", str(e))
#             raise HTTPException(
#                 status_code=500,
#                 detail=f"Database error occurred: {str(e)}"
#             )

#         except Exception as e:
#             print("Unexpected Error:", str(e))
#             print("Error occurred at step:", e.__traceback__.tb_lineno)  # Show the line number
#             raise HTTPException(
#                 status_code=500,
#                 detail=f"An unexpected error occurred: {str(e)}"
#             )

#     @staticmethod
#     async def login_user(loginData: LoginModel):
#         try:
#             db = get_db()  # Get the database instance
#             print(loginData.email, loginData.password)
#             # step 1 find user
#             user = await db.users.find_one({"email": loginData.email})
#             print("User found:", user)

#             if not user:
#                 raise HTTPException(status_code=404, detail="User not found")

#             # step 2 verify password
#             if not argon2.verify(loginData.password, user["password"]):
#                 raise HTTPException(status_code=401, detail="Invalid password")

#             # step 3 generate token
#             token_payload = {
#                 "user_id": str(user["_id"]),
#                 "username": user["name"],
#                 "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
#             }

#             token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)

#             token_data = {
#                 "user_id": str(user["_id"]),
#                 "token": token,
#                 "create_at": datetime.datetime.utcnow()
#             }

#             await db.tokens.insert_one(token_data)

#             # step 5 response data
#             response_data = {
#                 "_id": str(user["_id"]),
#                 "name": user["name"],
#                 "email": user["email"]
#             }

#             # step 6 return response
#             return {
#                 "message": "Login Success",
#                 "user_id": str(user["_id"]),
#                 "token": token,
#                 "data": response_data,
#                 "status_code": 200
#             }

#         except PyMongoError as e:
#             print("MongoDB Error:", str(e))
#             raise HTTPException(
#                 status_code=500,
#                 detail=f"Database error occurred: {str(e)}"
#             )

#         except Exception as e:
#             print("Unexpected Error:", str(e))
#             print("Error occurred at step:", e.__traceback__.tb_lineno)  # Show the line number
#             raise HTTPException(
#                 status_code=500,
#                 detail=f"An unexpected error occurred: {str(e)}"
#             )

#     @staticmethod
#     async def update_user(user_id: str, update_data: UserUpdateModel, token: str):
#         try:
#             db = get_db()
            
#             # 1. Verify the JWT token
#             try:
#                 payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#                 token_user_id = payload.get("user_id")
#                 if token_user_id != user_id:
#                     raise HTTPException(
#                         status_code=status.HTTP_403_FORBIDDEN,
#                         detail="Not authorized to update this user"
#                     )
#             except jwt.ExpiredSignatureError:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Token has expired"
#                 )
#             except jwt.InvalidTokenError:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Invalid authentication token"
#                 )

#             # 2. Prepare update dictionary (exclude unset fields)
#             update_dict = update_data.dict(exclude_unset=True)
            
#             # 3. If password is being updated, hash the new password
#             if "password" in update_dict:
#                 update_dict["password"] = argon2.hash(update_dict["password"])
#                 # Remove any confirmPassword if it exists
#                 update_dict.pop("confirmPassword", None)

#             # 4. Add updated_at timestamp
#             update_dict["updated_at"] = datetime.utcnow()

#             # 5. Perform the update
#             result = await db.users.update_one(
#                 {"_id": ObjectId(user_id)},
#                 {"$set": update_dict}
#             )

#             if result.modified_count == 0:
#                 raise HTTPException(
#                     status_code=status.HTTP_404_NOT_FOUND,
#                     detail="User not found or no changes made"
#                 )

#             # 6. Fetch and return the updated user data
#             updated_user = await db.users.find_one({"_id": ObjectId(user_id)})
#             updated_user["_id"] = str(updated_user["_id"])
            
#             # Remove sensitive data before returning
#             updated_user.pop("password", None)
#             updated_user.pop("confirmPassword", None)

#             return {
#                 "message": "User updated successfully",
#                 "data": updated_user,
#                 "status_code": status.HTTP_200_OK
#             }

#         except PyMongoError as e:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail=f"Database error: {str(e)}"
#             )
#         except Exception as e:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail=f"An unexpected error occurred: {str(e)}"
#             )



from config.database import get_db
from models.userModel import UserModel, UserUpdateModel, LoginModel
from fastapi import HTTPException, status
from pymongo.errors import PyMongoError
import json
import jwt
import datetime  # Import the module
from passlib.hash import argon2  # Argon2 for password hashing
from bson import ObjectId


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
                "user_id": user_id,
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
    async def login_user(loginData: LoginModel):
        try:
            db = get_db()  # Get the database instance
            print(loginData.email, loginData.password)
            # step 1 find user
            user = await db.users.find_one({"email": loginData.email})
            print("User found:", user)

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # step 2 verify password
            if not argon2.verify(loginData.password, user["password"]):
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

    @staticmethod
    async def update_user(user_id: str, update_data: UserUpdateModel, token: str):
        try:
            db = get_db()
            
            # 1. Verify the JWT token
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                token_user_id = payload.get("user_id")
                if token_user_id != user_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Not authorized to update this user"
                    )
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            except jwt.InvalidTokenError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token"
                )

            # 2. Prepare update dictionary (exclude unset fields)
            update_dict = update_data.dict(exclude_unset=True)
            
            # 3. If password is being updated, hash the new password
            if "password" in update_dict:
                update_dict["password"] = argon2.hash(update_dict["password"])
                # Remove any confirmPassword if it exists
                update_dict.pop("confirmPassword", None)

            # 4. Add updated_at timestamp
            update_dict["updated_at"] = datetime.datetime.utcnow()

            # 5. Perform the update
            result = await db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_dict}
            )

            if result.modified_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found or no changes made"
                )

            # 6. Fetch and return the updated user data
            updated_user = await db.users.find_one({"_id": ObjectId(user_id)})
            updated_user["_id"] = str(updated_user["_id"])
            
            # Remove sensitive data before returning
            updated_user.pop("password", None)
            updated_user.pop("confirmPassword", None)

            return {
                "message": "User updated successfully",
                "data": updated_user,
                "status_code": status.HTTP_200_OK
            }

        except PyMongoError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred: {str(e)}"
            )