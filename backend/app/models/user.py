from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey
)
from sqlalchemy.orm import relationship
from app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    """
    Standard registered user account.
    NO admin role or elevated privileges exist in this architecture.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    account_status = Column(String(20), default="active", nullable=False)  # active, suspended
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Scans owned exclusively by this user
    scans = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    # Active authenticated sessions
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """
    Server-managed authentication sessions.
    Stores cryptographically secure session tokens tied to individual users.
    Supports server-side invalidation upon logout and session rotation.
    """
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_token = Column(String(64), unique=True, index=True, nullable=False)
    csrf_token = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, index=True, nullable=False)
    last_active_at = Column(DateTime, default=utc_now, nullable=False)

    user = relationship("User", back_populates="sessions")
