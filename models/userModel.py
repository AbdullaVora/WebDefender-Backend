from pydantic import BaseModel, validator, Field, EmailStr
from typing import Optional

class UserModel(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirmPassword: str = Field(exclude=True)  # Add confirmPassword field

    @validator('confirmPassword')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class TokenModel(BaseModel):
    user_id: str
    token: str
    created_at: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class UserUpdateModel(BaseModel):
    name: Optional[str] = Field(None, min_length=2)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)



# from pydantic import BaseModel, validator, Field, EmailStr
# from typing import Optional

# # Base model with common fields
# class UserBaseModel(BaseModel):
#     name: str
#     email: EmailStr  # Using EmailStr for email validation

# # For user registration (requires password confirmation)
# class UserCreateModel(UserBaseModel):
#     password: str = Field(..., min_length=8)
#     confirmPassword: str = Field(..., exclude=True)

#     @validator('confirmPassword')
#     def passwords_match(cls, v, values, **kwargs):
#         if 'password' in values and v != values['password']:
#             raise ValueError('Passwords do not match')
#         return v

# # For user updates (all fields optional)
# class UserUpdateModel(BaseModel):
#     name: Optional[str] = Field(None, min_length=2)
#     email: Optional[EmailStr] = None
#     password: Optional[str] = Field(None, min_length=8)
    
#     class Config:
#         extra = "forbid"  # Reject any extra fields

# class TokenModel(BaseModel):
#     user_id: str
#     token: str
#     created_at: str

# class LoginModel(BaseModel):
#     email: EmailStr
#     password: str