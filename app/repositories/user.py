from typing import Any

from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    """Persistence operations for users."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: int) -> User | None:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_by_email(self, email: str) -> User | None:
        normalized_email = email.strip().lower()
        return self.db.query(User).filter(User.email == normalized_email).first()

    def exists_by_email(self, email: str) -> bool:
        normalized_email = email.strip().lower()
        return (
            self.db.query(User.id)
            .filter(User.email == normalized_email)
            .first()
            is not None
        )

    def create(
        self,
        email: str,
        hashed_password: str,
        **attributes: Any,
    ) -> User:
        user = User(
            email=email.strip().lower(),
            hashed_password=hashed_password,
            **attributes,
        )
        self.db.add(user)
        try:
            self.db.commit()
            self.db.refresh(user)
        except Exception:
            self.db.rollback()
            raise
        return user
