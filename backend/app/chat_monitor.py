"""Local-only chat transcript monitoring primitives."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .chatgpt_share import import_share, validate_share_url
from .detection import RuleBasedPromptInjectionDetector, RuleBasedSensitiveDataDetector
from .models import ChatEvent, ChatMonitorAuditEvent, ChatMonitorSession
from .risk import RiskScorer
from .security import redact_sensitive_values

MAX_TRANSCRIPT = 128 * 1024
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TOOL_RE = re.compile(
    r"\b(?:run|execute|call|invoke|use)\s+(?:the\s+)?(?:tool|function|command|browser|shell)\b",
    re.IGNORECASE,
)

RECOMMENDATION_SCOPE = "retrospective_analysis"


def recommendation(injection, sensitive, unsafe_links, tool_instructions, risk_score):
    """Recommend treatment of imported text, never authorize an actual action."""
    matches = ["chat_untrusted_imported_content"]
    reasons = [
        "Supplied transcript is untrusted imported content, "
        "not instructions to execute."
    ]
    if injection:
        matches.append("chat_prompt_injection")
        reasons.append(
            "Prompt-injection indicators warrant blocking reliance "
            "on these instructions."
        )
    if sensitive:
        matches.append("chat_sensitive_data_redaction")
        reasons.append("Sensitive values require redaction before storage or display.")
    if unsafe_links:
        matches.append("chat_unsafe_links")
        reasons.append(
            "Text contains malformed or non-public links; do not act on them."
        )
    if tool_instructions:
        matches.append("chat_tool_instruction_review")
        reasons.append(
            "Text contains possible tool-call instructions, not observed tool calls; "
            "review is recommended."
        )
    if risk_score >= 60:
        matches.append("chat_elevated_risk_review")
        reasons.append("The retrospective risk score warrants human review.")
    if injection or unsafe_links or risk_score >= 80:
        decision = "block"
    elif tool_instructions or risk_score >= 60:
        decision = "approval_required"
    elif sensitive:
        decision = "redact"
    else:
        decision = "allow"
    return {
        "decision": decision,
        "policy_matches": matches,
        "reasons": reasons,
        "recommendation_scope": RECOMMENDATION_SCOPE,
        "runtime_enforced": False,
    }


def check_transcript(text: str):
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as error:
        raise HTTPException(422, "Invalid transcript encoding") from error
    if size > MAX_TRANSCRIPT:
        raise HTTPException(413, "transcript is too large")


def validate_public_url(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        len(value) > 2048
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or "\\" in value
        or re.search(r"%(?![0-9a-fA-F]{2})", value)
    ):
        raise ValueError("URL is malformed")
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        if parsed.scheme.casefold() not in {"http", "https"} or not host:
            raise ValueError("URL must use HTTP(S) and include a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL credentials are not allowed")
        if (
            any(char.isspace() for char in value)
            or parsed.port is not None
            and not 0 < parsed.port < 65536
        ):
            raise ValueError("URL is malformed")
        host = host.rstrip(".").casefold()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            if (
                not address.is_global
                or (
                    isinstance(address, ipaddress.IPv6Address)
                    and address.ipv4_mapped is not None
                )
            ) or (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ValueError("private or reserved destinations are not allowed")
        else:
            labels = host.split(".")
            if (
                len(labels) < 2
                or len(host) > 253
                or any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    for label in labels
                )
                or host in {"localhost", "localhost.localdomain"}
                or host.endswith((".local", ".localhost", ".internal", ".home", ".lan"))
                or labels[-1].isdigit()
                or re.fullmatch(
                    r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host
                )
                or not re.fullmatch(r"[a-z0-9.-]+", host)
            ):
                raise ValueError("private, local, or malformed hostname")
        return value
    except (ValueError, UnicodeError) as error:
        raise ValueError(
            "URL must be a valid public HTTP(S) URL without credentials"
        ) from error


def safe_url(value: str) -> str:
    """Retain only a validated origin; shared-link paths may contain secrets."""
    validate_public_url(value)
    parsed = urlparse(value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def transcript_preview(text: str) -> str:
    return redact_sensitive_values(URL_RE.sub("[URL_REDACTED]", text))


def safe_metadata(value):
    if isinstance(value, dict):
        return {
            transcript_preview(key): safe_metadata(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [safe_metadata(item) for item in value]
    if isinstance(value, str):
        return transcript_preview(value)
    return value


def create_session(
    db: Session, source_type: str, url: str | None, text: str | None, metadata: dict
):
    if source_type == "metadata_only":
        if text is not None:
            raise HTTPException(
                422, "metadata_only sessions cannot include pasted_text"
            )
        if url is None:
            raise HTTPException(422, "metadata_only sessions require a URL")
        url = safe_url(url)
    elif source_type == "pasted_text":
        if text is not None:
            check_transcript(text)
            if not text.strip():
                raise HTTPException(422, "Transcript must not be empty")
        if url is not None:
            url = safe_url(url)
    elif source_type == "chatgpt_share":
        url = validate_share_url(url)
        if text is not None:
            raise HTTPException(
                422, "chatgpt_share sessions cannot include pasted_text"
            )
    else:
        raise HTTPException(422, "Unsupported source type")
    row = ChatMonitorSession(
        source_type=source_type,
        source_url=url,
        metadata_json=safe_metadata(redact_sensitive_values(metadata)),
    )
    db.add(row)
    db.flush()
    audit(db, row.id, "chat_monitor_session_created", {"source_type": source_type})
    if text is not None or source_type == "metadata_only":
        analyze(db, row, text)
    db.commit()
    db.refresh(row)
    return row


def audit(db: Session, session_id: str, event_type: str, payload: dict):
    row = ChatMonitorAuditEvent(
        session_id=session_id,
        event_type=event_type,
        payload=redact_sensitive_values(payload),
    )
    db.add(row)
    db.flush()
    return row


def analyze(
    db: Session, row: ChatMonitorSession, text: str | None, fetch_consent: bool = False
):
    if row.source_type == "chatgpt_share":
        if text is not None:
            raise HTTPException(
                422, "chatgpt_share analysis cannot include pasted_text"
            )
        if fetch_consent is not True:
            raise HTTPException(
                422, "Explicit fetch_consent=true is required for each import"
            )
        try:
            text = asyncio.run(import_share(row.source_url))
        except HTTPException as error:
            row.status = "analysis_failed"
            audit(
                db,
                row.id,
                "chat_monitor_import_failed",
                {"status_code": error.status_code},
            )
            db.commit()
            raise
    if row.source_type == "metadata_only":
        if text is not None:
            raise HTTPException(
                422, "metadata_only sessions cannot analyze transcripts"
            )
        row.status = "not_evaluated"
        recommendation_result = {
            "decision": "not_evaluated",
            "policy_matches": ["chat_no_connector_configured"],
            "reasons": [
                "No connector is configured; URL metadata is not transcript evidence."
            ],
            "recommendation_scope": RECOMMENDATION_SCOPE,
            "runtime_enforced": False,
            "content_sha256": None,
        }
        audit(
            db,
            row.id,
            "chat_monitor_not_evaluated",
            {"reason": "no connector configured", **recommendation_result},
        )
        return {
            "status": "not_evaluated",
            **recommendation_result,
            "limitation": "URL metadata was not fetched; no connector is configured.",
        }
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(422, "pasted_text is required for analysis")
    check_transcript(text)
    try:
        injection = RuleBasedPromptInjectionDetector().detect(text)
        sensitive = RuleBasedSensitiveDataDetector().detect(text)
        preview = transcript_preview(text)
        assessment = RiskScorer().score(
            {
                "untrusted_source": True,
                "prompt_injection_detected": injection.detected,
                "sensitive_data_detected": sensitive.detected,
            }
        )
    except Exception as error:
        row.status = "analysis_failed"
        audit(
            db, row.id, "chat_monitor_analysis_failed", {"reason": "detector failure"}
        )
        db.commit()
        raise HTTPException(503, "Transcript could not be evaluated safely") from error
    urls = []
    unsafe_links = False
    for value in URL_RE.findall(text):
        try:
            origin = safe_url(value.rstrip(".,);"))
        except ValueError:
            origin = "[UNSAFE_URL_REDACTED]"
            unsafe_links = True
        if origin not in urls and len(urls) < 100:
            urls.append(origin)
    tool_instructions = bool(TOOL_RE.search(text))
    recommendation_result = recommendation(
        injection.detected,
        sensitive.detected,
        unsafe_links,
        tool_instructions,
        assessment.score,
    )
    content_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    event = ChatEvent(
        session_id=row.id,
        sequence=1
        + (
            db.scalar(
                select(func.max(ChatEvent.sequence)).where(
                    ChatEvent.session_id == row.id
                )
            )
            or 0
        ),
        event_type="transcript_analyzed",
        payload={
            **recommendation_result,
            "content_sha256": content_sha256,
            "source_trust_level": "untrusted",
            "executed": False,
            "risk_score": assessment.score,
            "prompt_injection": {
                "detected": injection.detected,
                "indicators": injection.indicators,
                "severity": injection.severity,
                "confidence": injection.confidence,
            },
            "sensitive_data": {
                "detected": sensitive.detected,
                "categories": sensitive.categories,
                "confidence": sensitive.confidence,
            },
            "urls_detected": len(urls),
            "tool_call_instructions_detected": tool_instructions,
        },
        redacted_text=preview,
    )
    db.add(event)
    row.status = "evaluated"
    db.flush()
    db.refresh(event)
    audit(
        db,
        row.id,
        "chat_monitor_transcript_analyzed",
        {
            "event_id": event.id,
            "content_sha256": content_sha256,
            **recommendation_result,
        },
    )
    return {
        "status": "evaluated",
        **recommendation_result,
        "content_sha256": content_sha256,
        "risk_score": assessment.score,
        "findings": [
            {
                "detector": "prompt_injection",
                "detected": injection.detected,
                "indicators": injection.indicators,
                "severity": injection.severity,
                "confidence": injection.confidence,
                "reasons": injection.reasons,
                "redacted_preview": "",
            },
            {
                "detector": "sensitive_data",
                "detected": sensitive.detected,
                "categories": sensitive.categories,
                "confidence": sensitive.confidence,
                "redacted_preview": preview,
            },
        ],
        "urls_detected": urls,
        "tool_call_instructions_detected": tool_instructions,
        "redacted_preview": preview,
    }


def get_session(db: Session, session_id: str):
    row = db.get(ChatMonitorSession, session_id)
    if row is None:
        raise HTTPException(404, "Chat monitor session not found")
    return row


def list_sessions(db: Session):
    return list(
        db.scalars(
            select(ChatMonitorSession).order_by(
                ChatMonitorSession.created_at, ChatMonitorSession.id
            )
        )
    )


def list_events(db: Session, session_id: str):
    get_session(db, session_id)
    return list(
        db.scalars(
            select(ChatEvent)
            .where(ChatEvent.session_id == session_id)
            .order_by(ChatEvent.sequence, ChatEvent.id)
        )
    )


def list_audits(db: Session, session_id: str):
    get_session(db, session_id)
    return list(
        db.scalars(
            select(ChatMonitorAuditEvent)
            .where(ChatMonitorAuditEvent.session_id == session_id)
            .order_by(ChatMonitorAuditEvent.created_at, ChatMonitorAuditEvent.id)
        )
    )
