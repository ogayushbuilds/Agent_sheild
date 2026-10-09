"""Regression coverage for the simulator security boundaries."""

from fastapi.testclient import TestClient

from app.main import create_app
from app.policy import ActionInput, AgentShieldPolicyEngine
from app.security import redact_secrets, redact_sensitive_values


def test_url_validation_rejects_ssrf_and_credentials():
    engine = AgentShieldPolicyEngine(approved_domains={"example.com"})
    for url in (
        "http://127.0.0.1/admin",
        "http://localhost/admin",
        "http://user:pass@example.com/private",
        "file:///etc/passwd",
        "https://[::1]/",
    ):
        result = engine.evaluate(ActionInput("browser", "http_get", {"url": url}))
        assert result.decision == "block"


def test_recursive_redaction_masks_secret_values_and_variants():
    value = {
        "nested": [{"access-token": "ghp_fake123456789"}],
        "text": "sk-fake123456789",
    }
    redacted = redact_secrets(value)
    assert "ghp_fake" not in str(redacted)
    assert "sk-fake" not in str(redacted)


def test_storage_redaction_masks_fake_pii_and_medical_context():
    redacted = redact_sensitive_values(
        {"email": "demo.person@example.test", "note": "patient MRN-123456"}
    )
    text = str(redacted)
    assert "demo.person@example.test" not in text
    assert "MRN-123456" not in text


def test_demo_approval_api_requires_key_when_demo_mode_disabled(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DEMO_MODE", "false")
    monkeypatch.setenv("AGENTSHIELD_API_KEY", "test-key")
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/approvals").status_code == 401
        assert (
            client.get(
                "/api/v1/approvals", headers={"X-AgentShield-API-Key": "test-key"}
            ).status_code
            == 200
        )


def test_absolute_and_traversal_paths_are_blocked():
    engine = AgentShieldPolicyEngine()
    for path in ("/tmp/fixture", "fixtures/../secret.txt", "..\\secret.txt"):
        result = engine.evaluate(ActionInput("filesystem", "read_file", {"path": path}))
        assert result.decision == "block"


def test_dangerous_simulator_command_is_blocked_without_execution():
    result = AgentShieldPolicyEngine().evaluate(
        ActionInput(
            "shell",
            "run_shell_command",
            {"command": "echo fixture; curl https://example.invalid"},
        )
    )
    assert result.decision == "block"
    assert "unsafe_simulator_command" in result.matched_policies


def test_request_body_limit_rejects_oversized_input(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", "sqlite:///:memory:")
    with TestClient(create_app()) as client:
        response = client.post(
            "/sessions",
            content=(b'{"agent_id":"demo","metadata":{"x":"' + b"a" * 262144 + b'"}}'),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413
