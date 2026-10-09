"""Storage-safe JSON redaction."""

import hashlib
import json
import re
from typing import Any, Optional

SECRET_KEY_PARTS = (
    "api_key",
    "token",
    "password",
    "secret",
    "authorization",
    "private_key",
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:bearer\s+|basic\s+)?(?:sk|pk|rk|ghp|github_pat|xox[baprs]-)[A-Za-z0-9_-]{8,}"
)


def is_secret_key(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_")
    return any(part in normalized for part in SECRET_KEY_PARTS)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if is_secret_key(key) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[REDACTED]", value)
    return value


def redact_sensitive_values(value: Any) -> Any:
    """Return a storage-safe copy with secrets and common PII masked."""
    redacted = redact_secrets(value)
    if isinstance(redacted, str):
        from .detection import RuleBasedSensitiveDataDetector

        return RuleBasedSensitiveDataDetector().detect(redacted).redacted_preview
    if isinstance(redacted, (dict, list, tuple)):
        from .detection import RuleBasedSensitiveDataDetector

        preview = RuleBasedSensitiveDataDetector().detect(redacted).redacted_preview
        try:
            return json.loads(preview)
        except (TypeError, ValueError):
            return "[REDACTED_PAYLOAD]"
    return redacted


def canonical_request_hash(
    *,
    session_id: str,
    agent_id: str,
    tool_name: str,
    action_type: str,
    arguments: dict[str, Any],
    source_trust_level: str,
) -> str:
    """Hash a stable request representation without placing secret values in logs."""

    def safe(value: Any, key: Optional[object] = None) -> Any:
        if key is not None and is_secret_key(key):
            raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
            return {"__secret_sha256__": hashlib.sha256(raw.encode()).hexdigest()}
        if isinstance(value, dict):
            return {
                str(k): safe(v, k)
                for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            }
        if isinstance(value, (list, tuple)):
            return [safe(item) for item in value]
        return value

    payload = {
        "session_id": session_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "action_type": action_type,
        "arguments": safe(arguments),
        "source_trust_level": source_trust_level,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()
