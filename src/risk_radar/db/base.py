"""SQLAlchemy declarative base for future persistence models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class used by SQLAlchemy models and Alembic metadata."""
