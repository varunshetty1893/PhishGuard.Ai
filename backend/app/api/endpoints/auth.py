from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    AuthSuccessResponse,
    MessageResponse
)
from app.services.auth import AuthService
from app.api.deps import get_current_user_and_session, extract_session_token
from app.core.config import settings
from app.models.user import User, UserSession

router = APIRouter()


@router.post(
    "/auth/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New User Account"
)
def register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers an individual user with Argon2id password hashing and unique email enforcement.
    Strictly standard user accounts - NO admin role exists.
    """
    user = AuthService.register_user(db, request)
    return MessageResponse(
        message=f"Account created successfully for {user.full_name}. You can now log in."
    )


@router.post(
    "/auth/login",
    response_model=AuthSuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login & Session Establishment"
)
def login(
    request: UserLoginRequest,
    http_req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates user against Neon PostgreSQL / database.
    Establishes secure server-managed session with HttpOnly SameSite cookie.
    """
    user = AuthService.authenticate_user(db, request)

    # Invalidate any existing session token sent in the cookie to prevent session fixation
    existing_token = extract_session_token(http_req)
    if existing_token:
        AuthService.invalidate_session(db, existing_token)

    # Capture IP address and User-Agent
    ip_addr = http_req.client.host if http_req.client else None
    user_agent = http_req.headers.get("user-agent")

    session_record = AuthService.create_user_session(
        db,
        user=user,
        remember_me=request.remember_me,
        ip_address=ip_addr,
        user_agent=user_agent
    )

    max_age = (
        settings.REMEMBER_MAX_AGE_SECONDS
        if request.remember_me
        else settings.SESSION_MAX_AGE_SECONDS
    )

    # 1. HttpOnly Session Cookie (invisible to client-side JavaScript)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_record.session_token,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/"
    )

    # 2. CSRF Token Cookie (readable by client for X-CSRF-Token double-submit)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=session_record.csrf_token,
        max_age=max_age,
        expires=max_age,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/"
    )

    return AuthSuccessResponse(
        user=UserResponse.model_validate(user),
        csrf_token=session_record.csrf_token,
        message="Login successful."
    )


@router.post(
    "/auth/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Invalidate Session & Logout"
)
def logout(
    http_req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Performs server-side invalidation of session in database
    and clears both session and CSRF cookies.
    """
    token = extract_session_token(http_req)
    if token:
        AuthService.invalidate_session(db, token)

    # Clear cookies
    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

    return MessageResponse(message="Successfully signed out.")


@router.get(
    "/auth/me",
    response_model=AuthSuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Authenticated User Profile"
)
def get_me(
    response: Response,
    auth_data=Depends(get_current_user_and_session)
):
    """
    Returns current user's profile and active CSRF token.
    Used on app load / page refresh to verify and restore session state.
    """
    user, session_record = auth_data

    # Ensure CSRF cookie matches session CSRF token
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=session_record.csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/"
    )

    return AuthSuccessResponse(
        user=UserResponse.model_validate(user),
        csrf_token=session_record.csrf_token,
        message="Session active."
    )
