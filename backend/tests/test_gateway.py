"""Integration coverage for the action gateway and simulator boundary."""

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import create_app
from app.models import ApprovalRequest, SecurityDecision


def _session(client: TestClient) -> str:
    response = client.post(
        "/sessions", json={"agent_id": "gateway-agent", "metadata": {}}
    )
    assert response.status_code == 201
    return response.json()["id"]


def _request(session_id: str, action_type: str, arguments: dict, **extra):
    return {
        "session_id": session_id,
        "agent_id": "gateway-agent",
        "tool_name": extra.pop("tool_name", action_type),
        "action_type": action_type,
        "arguments": arguments,
        "source_trust_level": extra.pop("source_trust_level", "trusted"),
        "simulator_mode": True,
        **extra,
    }


def test_blocked_action_is_not_executed_and_is_audited():
    app = create_app()
    with TestClient(app) as client:
        session_id = _session(client)
        response = client.post(
            "/api/v1/execute-action",
            json=_request(
                session_id, "read_restricted_document", {"document": "secret"}
            ),
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "block"
        assert response.json()["executed"] is False
        events = client.get(f"/sessions/{session_id}/audit-events").json()["events"]
        assert [event["event_type"] for event in events] == ["action_checked"]


def test_allowed_action_runs_only_as_deterministic_simulation():
    app = create_app()
    with TestClient(app) as client:
        session_id = _session(client)
        response = client.post(
            "/api/v1/execute-action",
            json=_request(session_id, "read_public_document", {"document": "guide"}),
        )
        body = response.json()
        assert response.status_code == 200
        assert body["decision"] == "allow"
        assert body["executed"] is True
        assert body["result"]["content"] == "SIMULATED_PUBLIC_DOCUMENT"


def test_approved_http_get_runs_in_simulator():
    app = create_app()
    with TestClient(app) as client:
        session_id = _session(client)
        response = client.post(
            "/api/v1/execute-action",
            json=_request(
                session_id,
                "http_get",
                {"url": "https://example.com/docs"},
                tool_name="http_get",
            ),
        )
        body = response.json()
        assert body["decision"] == "allow"
        assert body["executed"] is True
        assert body["result"]["method"] == "GET"


def test_http_post_with_sensitive_data_is_blocked_in_simulator():
    app = create_app()
    with TestClient(app) as client:
        session_id = _session(client)
        response = client.post(
            "/api/v1/execute-action",
            json=_request(
                session_id,
                "http_post",
                {
                    "url": "https://example.com/ingest",
                    "body": {"api_key": "fake-test-key"},
                },
                tool_name="http_post",
            ),
        )
        body = response.json()
        assert body["decision"] == "block"
        assert body["executed"] is False


def test_approval_required_action_is_queued_and_not_executed():
    app = create_app()
    with TestClient(app) as client:
        session_id = _session(client)
        response = client.post(
            "/api/v1/execute-action",
            json=_request(
                session_id,
                "run_shell_command",
                {"command": "touch should-never-run"},
                tool_name="shell",
            ),
        )
        body = response.json()
        assert body["decision"] == "approval_required"
        assert body["executed"] is False
        assert body["approval_request_id"]
        with app.state.session_factory() as db:
            approval = db.get(ApprovalRequest, body["approval_request_id"])
            assert approval is not None
            assert approval.status == "pending"
            assert approval.action_request_id == body["action_request_id"]
            decision = db.scalar(
                select(SecurityDecision).where(
                    SecurityDecision.action_request_id == body["action_request_id"]
                )
            )
            assert decision is not None
            assert decision.decision == "approval_required"
        events = client.get(f"/sessions/{session_id}/audit-events").json()["events"]
        assert [event["event_type"] for event in events] == ["action_checked"]
