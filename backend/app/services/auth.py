from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User, UserSession
from app.schemas.auth import UserRegisterRequest, UserLoginRequest
from app.core.security import (
    hash_password,
    verify_password,
    normalize_email,
    validate_email_format,
    validate_password_strength,
    generate_session_token,
    generate_csrf_token
)
from app.core.config import settings


def utc_now():
    return datetime.now(timezone.utc)


class AuthService:

    @staticmethod
    def register_user(db: Session, request: UserRegisterRequest) -> User:
        # 1. Match passwords
        if request.password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match. Please re-enter both password fields."
            )

        # 2. Validate email format
        email_valid, email_err = validate_email_format(request.email)
        if not email_valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=email_err)

        # 3. Validate password complexity
        pwd_valid, pwd_err = validate_password_strength(request.password)
        if not pwd_valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pwd_err)

        normalized_email = normalize_email(request.email)

        # 4. Check for existing duplicate account
        existing_user = db.query(User).filter(User.email == normalized_email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists."
            )

        # 5. Hash password with Argon2id
        pw_hash = hash_password(request.password)

        # 6. Create user record
        user = User(
            full_name=request.full_name.strip(),
            email=normalized_email,
            password_hash=pw_hash,
            account_status="active"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def authenticate_user(db: Session, request: UserLoginRequest) -> User:
        normalized_email = normalize_email(request.email)
        user = db.query(User).filter(User.email == normalized_email).first()

        # Generic authentication failure prevents user enumeration
        if not user or not verify_password(request.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email address or password."
            )

        if user.account_status != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account has been deactivated. Please contact support."
            )

        return user

    @staticmethod
    def create_user_session(
        db: Session,
        user: User,
        remember_me: bool = False,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSession:
        max_age = (
            settings.REMEMBER_MAX_AGE_SECONDS
            if remember_me
            else settings.SESSION_MAX_AGE_SECONDS
        )
        now = utc_now()
        expires_at = now + timedelta(seconds=max_age)

        session_token = generate_session_token()
        csrf_token = generate_csrf_token()

        session_record = UserSession(
            session_token=session_token,
            csrf_token=csrf_token,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=(user_agent[:250] if user_agent else None),
            created_at=now,
            expires_at=expires_at,
            last_active_at=now
        )
        db.add(session_record)
        db.commit()
        db.refresh(session_record)
        return session_record

    @staticmethod
    def validate_session(db: Session, session_token: str) -> Optional[Tuple[User, UserSession]]:
        if not session_token:
            return None

        session_record = db.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()

        if not session_record:
            return None

        # Check expiration
        now = datetime.now(timezone.utc)
        record_expires = session_record.expires_at
        if record_expires.tzinfo is None:
            record_expires = record_expires.replace(tzinfo=timezone.utc)

        if now > record_expires:
            # Expired session -> remove
            db.delete(session_record)
            db.commit()
            return None

        # Update last active timestamp
        session_record.last_active_at = now
        db.commit()

        user = db.query(User).filter(User.id == session_record.user_id).first()
        if not user or user.account_status != "active":
            return None

        return user, session_record

    @staticmethod
    def invalidate_session(db: Session, session_token: str):
        if not session_token:
            return
        session_record = db.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()
        if session_record:
            db.delete(session_record)
            db.commit()
