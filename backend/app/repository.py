"""Persistence operations; audit events intentionally have no update/delete API."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    ActionRequest,
    Agent,
    AgentSession,
    ApprovalRequest,
    AuditEvent,
    SecurityDecision,
)
from .security import redact_secrets, redact_sensitive_values


def list_agents(db: Session) -> list[Agent]:
    return list(db.scalars(select(Agent).order_by(Agent.created_at, Agent.id)))


def get_agent(db: Session, agent_id: str) -> Agent | None:
    return db.scalar(
        select(Agent).where(
            (Agent.id == agent_id) | (Agent.external_agent_id == agent_id)
        )
    )


def create_agent(db: Session, **values) -> Agent:
    row = Agent(**values)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def action_evidence(db: Session, action_ids: list[str]) -> dict[str, dict]:
    """Read recorded check-time evidence; historical rows have no evidence."""
    if not action_ids:
        return {}
    rows = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.event_type.in_(["action_checked", "agent_action_denied"]),
            AuditEvent.payload["action_request_id"].as_string().in_(action_ids),
        )
        .order_by(AuditEvent.created_at, AuditEvent.id)
    )
    return {row.payload["action_request_id"]: row.payload for row in rows}


def create_session(db: Session, agent_id: str, metadata: dict) -> AgentSession:
    row = AgentSession(
        agent_id=agent_id, metadata_json=redact_sensitive_values(metadata)
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def append_audit_event(
    db: Session, session_id: str, event_type: str, payload: dict
) -> AuditEvent:
    row = AuditEvent(
        session_id=session_id,
        event_type=event_type,
        payload=redact_sensitive_values(payload),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_action_request(db: Session, **values) -> ActionRequest:
    """Persist an action snapshot with storage-safe arguments."""
    values["arguments"] = redact_sensitive_values(values["arguments"])
    row = ActionRequest(**values)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_audit_events(db: Session, session_id: str) -> list[AuditEvent]:
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.session_id == session_id)
            .order_by(AuditEvent.created_at, AuditEvent.id)
        )
    )


def create_security_decision(
    db: Session, action_request_id: str, decision: str, reasons: list[str]
) -> SecurityDecision:
    row = SecurityDecision(
        action_request_id=action_request_id,
        decision=decision,
        reasons=redact_secrets(reasons),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_approval_request(
    db: Session, action_request_id: str, **values
) -> ApprovalRequest:
    ttl = int(os.getenv("AGENTSHIELD_APPROVAL_TTL_SECONDS", "300"))
    row = ApprovalRequest(
        action_request_id=action_request_id,
        expires_at=datetime.utcnow() + timedelta(seconds=ttl),
        **values,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_approval_requests(db: Session) -> list[ApprovalRequest]:
    return list(
        db.scalars(
            select(ApprovalRequest).order_by(
                ApprovalRequest.created_at, ApprovalRequest.id
            )
        )
    )
