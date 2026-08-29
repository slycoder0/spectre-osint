"""SQLite (default) / PostgreSQL session factory."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.models import Base, CaseRow

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _sqlite_on_connect(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def get_engine(settings: Settings | None = None) -> Engine:
    global _engine, _SessionLocal
    cfg = settings or get_settings()
    if _engine is not None:
        return _engine
    connect_args = {"check_same_thread": False} if cfg.db_url.startswith("sqlite") else {}
    _engine = create_engine(cfg.db_url, future=True, connect_args=connect_args)
    if cfg.db_url.startswith("sqlite"):
        event.listen(_engine, "connect", _sqlite_on_connect)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def init_db(settings: Settings | None = None) -> None:
    engine = get_engine(settings)
    Base.metadata.create_all(engine)


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Iterator[Session]:
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_active_case(session: Session) -> CaseRow | None:
    return session.scalar(select(CaseRow).where(CaseRow.active.is_(True)))
