from typing import Optional, Tuple
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserSession
from app.services.auth import AuthService
from app.core.config import settings


def extract_session_token(request: Request) -> Optional[str]:
    """Extracts session token from HttpOnly cookie or Authorization Bearer header."""
    # 1. Primary: HttpOnly session cookie
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if token:
        return token

    # 2. Secondary: Authorization header for API testing
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    return None


def get_current_user_and_session(
    request: Request,
    db: Session = Depends(get_db)
) -> Tuple[User, UserSession]:
    """
    Mandatory authentication dependency.
    Validates server-managed session in database and yields current User and Session.
    """
    token = extract_session_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in to access this feature."
        )

    validated = AuthService.validate_session(db, token)
    if not validated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please log in again."
        )

    user, session_record = validated
    return user, session_record


def get_current_user(
    auth_data: Tuple[User, UserSession] = Depends(get_current_user_and_session)
) -> User:
    """Convenience dependency that returns only the authenticated User."""
    user, _ = auth_data
    return user


def verify_csrf(
    request: Request,
    auth_data: Tuple[User, UserSession] = Depends(get_current_user_and_session)
):
    """
    Validates double-submit / session-bound CSRF token on state-changing operations
    when requests arrive via cookie authentication.
    """
    _, session_record = auth_data
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    
    # Only enforce CSRF if authenticated via browser cookie
    if cookie_token:
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_header or csrf_header != session_record.csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF security token mismatch or missing. Action rejected."
            )
