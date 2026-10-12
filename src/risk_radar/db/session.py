"""SQLAlchemy engine and session factory."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from risk_radar.core.config import get_settings

settings = get_settings()
_db_url = settings.database_url
_is_sqlite = _db_url.drivername.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}

engine = create_engine(_db_url, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Initialize database tables when running on SQLite or in standalone mode."""
    from risk_radar.db.base import Base

    Base.metadata.create_all(bind=engine)


def get_db():
    """Yield a scoped database session and always close it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
