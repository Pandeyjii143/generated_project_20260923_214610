from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User


_password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Return a secure hash of a plaintext password."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return _password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against its stored hash."""
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    try:
        return _password_context.verify(plain_password, hashed_password)
    except (TypeError, ValueError):
        return False


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Create a signed JWT access token from the supplied claims."""
    claims = data.copy()
    if claims.get("sub") is not None:
        claims["sub"] = str(claims["sub"])

    now = datetime.now(timezone.utc)
    lifetime = expires_delta or timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    claims.update(
        {
            "iat": int(now.timestamp()),
            "exp": int((now + lifetime).timestamp()),
            "token_type": "access",
        }
    )
    return jwt.encode(claims, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> dict[str, Any] | None:
    """Decode and validate a JWT, returning its claims or None if invalid."""
    try:
        claims = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except (JWTError, TypeError, ValueError):
        return None

    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        return None
    if claims.get("token_type") != expected_type:
        return None
    return claims


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    """Return the matching active user when the supplied credentials are valid."""
    user = db.query(User).filter(User.email == email).first()
    if user is None or not verify_password(password, user.hashed_password):
        return None
    if not getattr(user, "is_active", True):
        return None
    return user
