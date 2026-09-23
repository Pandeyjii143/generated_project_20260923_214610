from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and an optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "FastAPI Authentication API"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"

    # Override this value with a securely generated secret in deployed environments.
    secret_key: str = "development-only-change-this-secret-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=30, gt=0)
    refresh_token_expire_days: int = Field(default=7, gt=0)

    database_url: str = "sqlite:///./app.db"

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, value: str) -> str:
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("algorithm must be one of HS256, HS384, or HS512")
        return value

    @model_validator(mode="after")
    def validate_production_secret(self) -> "Settings":
        if self.environment.lower() == "production":
            if self.secret_key == "development-only-change-this-secret-key":
                raise ValueError("Set a unique secret_key in production")
            if len(self.secret_key) < 32:
                raise ValueError("Production secret_key must be at least 32 characters")
        return self


@lru_cache
 def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


settings = get_settings()
