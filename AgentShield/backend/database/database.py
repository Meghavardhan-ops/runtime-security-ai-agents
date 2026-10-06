"""SQLAlchemy engine, declarative base, and session dependency."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.core.config import settings


def _create_engine(database_url: str) -> Engine:
    """Create an engine, applying SQLite's ASGI-compatible thread setting."""
    is_sqlite = make_url(database_url).get_backend_name() == "sqlite"
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    return create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)


engine = _create_engine(settings.database_url)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models added by later backend features."""


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and close it after the request completes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
