"""Focused persistence, validation, and API behavior tests."""

from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import initialize_database
from app.main import create_app
from app.models import ActionRequest
from app.schemas import ActionRequestCreate, SessionCreate
from app.services import record_audit_event, save_action_request, start_session


def database_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    initialize_database(engine)
    return engine, Session(engine)


def test_strict_validation_rejects_coercion_and_extra_fields():
    try:
        SessionCreate(agent_id=123)
    except ValidationError:
        pass
    else:
        raise AssertionError("agent_id should be strict")

    try:
        SessionCreate(agent_id="agent", unexpected=True)
    except ValidationError:
        pass
    else:
        raise AssertionError("unknown fields should be rejected")


def test_action_persists_required_fields_and_redacts_nested_arguments():
    _, db = database_session()
    session = start_session(db, "agent-1", {})
    request = ActionRequestCreate(
        session_id=session.id,
        agent_id="agent-1",
        tool_name="shell",
        action_type="execute",
        arguments={"nested": {"api_key": "do-not-store"}, "items": [{"token": "x"}]},
        source_trust_level="untrusted",
        risk_score=50,
        decision="allow",
        reasons=["safe"],
    )
    row = save_action_request(db, request)
    stored = db.scalar(select(ActionRequest).where(ActionRequest.id == row.id))
    assert stored.arguments == {
        "nested": {"api_key": "[REDACTED]"},
        "items": [{"token": "[REDACTED]"}],
    }


def test_audit_is_append_only_service_and_redacts_payload():
    _, db = database_session()
    session = start_session(db, "agent-1", {})
    event = record_audit_event(
        db,
        session.id,
        "action",
        {"password": "hidden", "nested": [{"secret": "hidden"}]},
    )
    assert event.payload == {
        "password": "[REDACTED]",
        "nested": [{"secret": "[REDACTED]"}],
    }
    assert not hasattr(
        __import__("app.repository", fromlist=["x"]), "update_audit_event"
    )
    assert not hasattr(
        __import__("app.repository", fromlist=["x"]), "delete_audit_event"
    )


def test_session_endpoint_and_audit_retrieval():
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/sessions", json={"agent_id": "agent-api", "metadata": {}}
        )
        assert response.status_code == 201
        session_id = response.json()["id"]
        assert client.get(f"/sessions/{session_id}/audit-events").json() == {
            "events": []
        }
