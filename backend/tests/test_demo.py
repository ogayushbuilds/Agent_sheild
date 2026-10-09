"""Integration coverage for fixed, side-effect-free demo scenarios."""

import json
import socket
import subprocess
import urllib.request

import pytest
from fastapi.testclient import TestClient

from app import gateway
from app.main import create_app
from app.models import DemoTrace


@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", f"sqlite:///{tmp_path / 'demo.db'}")
    return create_app()


def test_attack_order_findings_and_policy_blocks(demo_app):
    with TestClient(demo_app) as client:
        response = client.post("/api/v1/demo/attack-run")
        assert response.status_code == 200
        trace = response.json()
    assert trace["simulator_mode"] is True
    assert trace["final_decision"] == "block"
    events = trace["events"]
    assert [e["sequence"] for e in events] == list(range(1, 8))
    assert [e["event_type"] for e in events] == [
        "scenario_started",
        "user_request",
        "tool_call",
        "page_content_observed",
        "tool_call",
        "tool_call",
        "decision",
    ]
    assert "hospital cybersecurity" in events[1]["description"]
    prompt = events[3]["detector_findings"][0]
    assert prompt["detected"]
    assert {
        "ignore_previous_instructions",
        "exfiltrate_confidential_data",
        "hidden_html_instruction",
    } <= set(prompt["indicators"])
    read, upload = events[4:6]
    assert read["decision"] == upload["decision"] == "block"
    assert read["risk_score"] == upload["risk_score"] == 100
    assert "restricted_document" in read["policy_matches"]
    assert "untrusted_content_secret_access" in read["policy_matches"]
    assert "unapproved_destination_domain" in upload["policy_matches"]
    assert {"medical_information", "internal_document"} <= set(
        read["detector_findings"][1]["categories"]
    )
    assert "external_upload" in {f["name"] for f in upload["risk_factors"]}
    assert all(not e["tool_call"]["executed"] for e in events if e["tool_call"])


@pytest.mark.parametrize("scenario,decision", [("safe", "allow"), ("attack", "block")])
def test_repeatability_retrieval_and_sqlite_persistence(demo_app, scenario, decision):
    with TestClient(demo_app) as client:
        first = client.post(f"/api/v1/demo/{scenario}-run", json={}).json()
        second = client.post(f"/api/v1/demo/{scenario}-run", json={}).json()
        assert first == second
        assert first["final_decision"] == decision
        trace_id = first["trace_id"]
        assert client.get(f"/api/v1/demo/trace/{trace_id}").json() == first
        assert client.get("/api/v1/demo/trace/missing").status_code == 404
    with demo_app.state.session_factory() as db:
        stored = db.get(DemoTrace, trace_id)
        assert stored.payload == first
        text = json.dumps(stored.payload)
        assert "[MEDICAL_TERM_REDACTED]" in text if scenario == "attack" else True
    # A fresh application proves retrieval is persisted rather than process-local.
    with TestClient(create_app()) as client:
        assert client.get(f"/api/v1/demo/trace/{trace_id}").json() == first
    if scenario == "safe":
        tool = first["events"][2]
        assert tool["decision"] == "allow"
        assert "approved_destination_domain" in tool["policy_matches"]
        assert all(not f["detected"] for f in tool["detector_findings"])


def test_scenarios_never_execute_network_or_tools(demo_app, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Demo attempted a real operation")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(gateway, "execute_action", forbidden)
    monkeypatch.setattr(gateway, "_simulate", forbidden)
    with TestClient(demo_app) as client:
        for scenario in ("safe", "attack"):
            response = client.post(f"/api/v1/demo/{scenario}-run", json={})
            assert response.status_code == 200
            assert all(
                not e["tool_call"]["executed"]
                for e in response.json()["events"]
                if e["tool_call"]
            )
        assert (
            client.post(
                "/api/v1/demo/attack-run", json={"url": "https://real.example"}
            ).status_code
            == 422
        )
