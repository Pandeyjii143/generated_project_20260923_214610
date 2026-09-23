import os
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
_url = make_url(DATABASE_URL)
_is_sqlite = _url.get_backend_name() == "sqlite"

_engine_kwargs: dict[str, object] = {"pool_pre_ping": True}
if _is_sqlite:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    if _url.database in (None, "", ":memory:"):
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(DATABASE_URL, **_engine_kwargs)


if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: object, connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    """Provide a database session and ensure it is closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
