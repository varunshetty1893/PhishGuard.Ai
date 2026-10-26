import re
import secrets
from typing import Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id password hasher with RFC 9106 recommended parameters
hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32
)

# Email syntax validator
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash with constant-time security."""
    try:
        return hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def normalize_email(email: str) -> str:
    """Normalizes an email address consistently (stripped and lowercase)."""
    if not email:
        return ""
    return email.strip().lower()


def validate_email_format(email: str) -> Tuple[bool, str]:
    """Validates email format."""
    normalized = normalize_email(email)
    if not normalized or len(normalized) > 254:
        return False, "Email address is required and must not exceed 254 characters."
    if not EMAIL_REGEX.match(normalized):
        return False, "Please enter a valid email address (e.g. user@example.com)."
    return True, ""


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforces password complexity policy:
    - Minimum 8 characters, maximum 128
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one digit
    - At least one special character
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_]", password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, ""


def generate_session_token() -> str:
    """Generates a cryptographically secure 256-bit session token."""
    return secrets.token_hex(32)


def generate_csrf_token() -> str:
    """Generates a cryptographically secure CSRF prevention token."""
    return secrets.token_hex(32)
