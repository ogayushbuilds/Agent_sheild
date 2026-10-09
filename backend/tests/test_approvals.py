"""Approval lifecycle and hash binding coverage."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_approval_is_reviewable_and_single_use():
    with TestClient(create_app()) as client:
        session = client.post("/sessions", json={"agent_id": "reviewer-demo"}).json()[
            "id"
        ]
        request = {
            "session_id": session,
            "agent_id": "reviewer-demo",
            "tool_name": "shell",
            "action_type": "run_shell_command",
            "arguments": {"command": "echo approved"},
            "source_trust_level": "trusted",
            "simulator_mode": True,
        }
        checked = client.post("/api/v1/check-action", json=request).json()
        approval_id = checked["approval_request_id"]
        listed = client.get("/api/v1/approvals").json()["approvals"]
        approval = next(item for item in listed if item["id"] == approval_id)
        assert (
            approval["reasons"]
            and approval["action"]["arguments"] == request["arguments"]
        )
        assert (
            client.post(f"/api/v1/approvals/{approval_id}/approve", json={}).status_code
            == 200
        )
        executed = client.post(
            "/api/v1/execute-action",
            json={**request, "approval_request_id": approval_id},
        )
        assert executed.status_code == 200
        assert executed.json()["executed"] is True
        assert (
            client.post(
                "/api/v1/execute-action",
                json={**request, "approval_request_id": approval_id},
            ).status_code
            == 409
        )


def test_modified_request_cannot_use_approval():
    with TestClient(create_app()) as client:
        session = client.post("/sessions", json={"agent_id": "hash-demo"}).json()["id"]
        request = {
            "session_id": session,
            "agent_id": "hash-demo",
            "tool_name": "shell",
            "action_type": "run_shell_command",
            "arguments": {"command": "echo original"},
            "source_trust_level": "trusted",
            "simulator_mode": True,
        }
        approval = client.post("/api/v1/check-action", json=request).json()[
            "approval_request_id"
        ]
        assert (
            client.post(f"/api/v1/approvals/{approval}/approve", json={}).status_code
            == 200
        )
        changed = client.post(
            "/api/v1/execute-action",
            json={
                **request,
                "arguments": {"command": "echo modified"},
                "approval_request_id": approval,
            },
        )
        assert changed.status_code == 409
