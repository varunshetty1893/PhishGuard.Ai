from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Full Name of the user")
    email: EmailStr = Field(..., description="Valid corporate or personal email address")
    password: str = Field(..., min_length=8, max_length=128, description="Account password")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="Account password")
    remember_me: bool = Field(False, description="Persist session for extended duration")


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    created_at: datetime
    account_status: str

    class Config:
        from_attributes = True


class AuthSuccessResponse(BaseModel):
    user: UserResponse
    csrf_token: str
    message: str


class MessageResponse(BaseModel):
    message: str
