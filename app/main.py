import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Generator, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, validator
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, declarative_base, sessionmaker


# Configuration is environment-driven. Set JWT_SECRET_KEY to a strong, private
# value outside local development.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "local-development-only-change-this-secret")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("JWT_ISSUER", "fastapi-auth")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
AUTO_CREATE_TABLES = os.getenv("AUTO_CREATE_TABLES", "true").lower() in {"1", "true", "yes"}
PASSWORD_HASH_ITERATIONS = 310_000

_engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Integer().with_variant(Integer, "sqlite")
    id = __import__("sqlalchemy").Column(Integer, primary_key=True, index=True)
    email = __import__("sqlalchemy").Column(String(320), unique=True, index=True, nullable=False)
    password_hash = __import__("sqlalchemy").Column(String(256), nullable=False)
    is_active = __import__("sqlalchemy").Column(Boolean, nullable=False, default=True)
    created_at = __import__("sqlalchemy").Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=8, max_length=128)

    @validator("email")
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        local, separator, domain = value.rpartition("@")
        if not separator or not local or "." not in domain or any(char.isspace() for char in value):
            raise ValueError("A valid email address is required")
        return value


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${_b64url_encode(salt)}${_b64url_encode(digest)}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64url_decode(salt), int(iterations)
        )
        return hmac.compare_digest(actual, _b64url_decode(expected))
    except (ValueError, TypeError):
        return False


def _create_access_token(user_id: int) -> str:
    now = int(time.time())
    expires_at = now + ACCESS_TOKEN_EXPIRE_MINUTES * 60
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {"sub": str(user_id), "iss": JWT_ISSUER, "iat": now, "exp": expires_at}
    signing_input = f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _decode_access_token(token: str) -> int:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(
            JWT_SECRET_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_signature, _b64url_decode(encoded_signature)):
            raise ValueError("Invalid signature")
        header = json.loads(_b64url_decode(encoded_header))
        payload = json.loads(_b64url_decode(encoded_payload))
        if header.get("alg") != JWT_ALGORITHM:
            raise ValueError("Unsupported algorithm")
        if payload.get("iss") != JWT_ISSUER or int(payload["exp"]) <= int(time.time()):
            raise ValueError("Expired or invalid token")
        return int(payload["sub"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    user_id = _decode_access_token(token)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@asynccontextmanager
async def lifespan(_: FastAPI):
    # For production, set AUTO_CREATE_TABLES=false and apply Alembic migrations.
    if AUTO_CREATE_TABLES:
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="JWT Authentication API", version="1.0.0", lifespan=lifespan)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["authentication"],
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> User:
    email = payload.email
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")

    user = User(email=email, password_hash=_hash_password(payload.password))
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    return user


@app.post("/auth/login", response_model=TokenResponse, tags=["authentication"])
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> TokenResponse:
    email = form_data.username.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is None or not _verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")

    return TokenResponse(
        access_token=_create_access_token(user.id),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.get("/auth/me", response_model=UserResponse, tags=["authentication"])
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
