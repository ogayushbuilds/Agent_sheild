"""Application services for persistence and audit behavior."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from . import repository
from .models import (
    ActionRequest,
    AgentSession,
    ApprovalRequest,
    AuditEvent,
    SecurityDecision,
)


def start_session(db: Session, agent_id: str, metadata: dict) -> AgentSession:
    return repository.create_session(db, agent_id, metadata)


def record_audit_event(
    db: Session, session_id: str, event_type: str, payload: dict
) -> AuditEvent:
    return repository.append_audit_event(db, session_id, event_type, payload)


def save_action_request(db: Session, request) -> ActionRequest:
    return repository.create_action_request(db, **request.model_dump())


def get_audit_events(db: Session, session_id: str) -> list[AuditEvent]:
    return repository.list_audit_events(db, session_id)


def save_security_decision(
    db: Session, action_request_id: str, decision: str, reasons: list[str]
) -> SecurityDecision:
    return repository.create_security_decision(db, action_request_id, decision, reasons)


def queue_approval(db: Session, action_request_id: str, **values) -> ApprovalRequest:
    return repository.create_approval_request(db, action_request_id, **values)


def expire_approval(db: Session, approval: ApprovalRequest) -> bool:
    if approval.status == "pending" and approval.expires_at <= datetime.utcnow():
        approval.status = "expired"
        approval.acted_at = datetime.utcnow()
        db.commit()
        record_audit_event(
            db,
            approval_action_session(db, approval),
            "approval_expired",
            {"approval_request_id": approval.id},
        )
        return True
    return False


def conditional_approval_update(
    db: Session,
    approval_id: str,
    old_status: str,
    new_status: str,
    reviewer: str | None,
) -> bool:
    result = db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.status == old_status,
            ApprovalRequest.expires_at > datetime.utcnow(),
        )
        .values(status=new_status, reviewer=reviewer, acted_at=datetime.utcnow())
    )
    db.commit()
    return result.rowcount == 1


def approval_action_session(db: Session, approval: ApprovalRequest) -> str:
    from .models import ActionRequest

    return db.get(ActionRequest, approval.action_request_id).session_id
