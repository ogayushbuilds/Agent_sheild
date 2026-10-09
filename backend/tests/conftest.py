"""Ensure every backend test starts with isolated state and local demo settings."""

import pytest


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("AGENTSHIELD_DEMO_MODE", "true")
    monkeypatch.delenv("AGENTSHIELD_API_KEY", raising=False)
