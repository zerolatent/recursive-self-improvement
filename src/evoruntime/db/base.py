"""SQLAlchemy declarative base and engine/session factories.

Domain models (events, payloads, lineage nodes/edges, dataset partitions,
holdout handles, the query ledger) are declared against `Base` in later
deliverables so Alembic autogenerate can diff against a single metadata
object.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from evoruntime.db.settings import get_database_settings


class Base(DeclarativeBase):
    """Declarative base for every EvoRuntime ORM model."""


def build_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for the given (or configured) database URL."""
    url = database_url or get_database_settings().database_url
    return create_engine(url, pool_pre_ping=True)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to the given engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Yield a session, committing on success and rolling back on error."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
