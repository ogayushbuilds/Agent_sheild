"""Database configuration and initialization for AgentShield."""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

DEFAULT_DATABASE_URL = "sqlite:///./agentshield.db"


def database_url() -> str:
    return os.getenv("AGENTSHIELD_DATABASE_URL", DEFAULT_DATABASE_URL)


def create_database(url: str | None = None):
    """Create an engine and session factory for the configured database."""
    selected_url = url or database_url()
    kwargs = (
        {"connect_args": {"check_same_thread": False}}
        if selected_url.startswith("sqlite")
        else {}
    )
    engine = create_engine(selected_url, future=True, **kwargs)
    return engine, sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def initialize_database(engine) -> None:
    Base.metadata.create_all(engine)
    # Keep the demo's existing SQLite file usable as the schema evolves.
    if engine.dialect.name == "sqlite":
        columns = {
            column["name"]
            for column in inspect(engine).get_columns("approval_requests")
        }
        additions = {
            "request_hash": "VARCHAR(64) NOT NULL DEFAULT ''",
            "risk_score": "FLOAT NOT NULL DEFAULT 0",
            "reasons": "JSON NOT NULL DEFAULT '[]'",
            "policy_context": "JSON NOT NULL DEFAULT '{}'",
            "expires_at": "DATETIME NOT NULL DEFAULT '2099-01-01 00:00:00'",
            "reviewer": "VARCHAR(255)",
            "acted_at": "DATETIME",
        }
        with engine.begin() as connection:
            for name, definition in additions.items():
                if name not in columns:
                    statement = (
                        f"ALTER TABLE approval_requests ADD COLUMN {name} {definition}"
                    )
                    connection.execute(text(statement))


def get_db(session_factory) -> Generator[Session, None, None]:
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
