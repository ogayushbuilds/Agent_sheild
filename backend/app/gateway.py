"""The single security gateway for all agent actions."""

from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .detection import RuleBasedPromptInjectionDetector, RuleBasedSensitiveDataDetector
from .models import Agent, AgentSession, ApprovalRequest
from .policy import ActionInput, AgentShieldPolicyEngine
from .schemas import ActionRequestCreate, GatewayActionRequest, GatewayActionResponse
from .security import canonical_request_hash, redact_secrets
from .services import (
    queue_approval,
    record_audit_event,
    save_action_request,
    save_security_decision,
)


def classify_source(value: str) -> str:
    """Normalize source trust without trusting arbitrary caller labels."""
    normalized = value.casefold().strip()
    return (
        normalized
        if normalized in {"trusted", "untrusted", "user", "system"}
        else "unknown"
    )


def _simulate(action_type: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic results; this function has no I/O by design."""
    safe_args = redact_secrets(arguments)
    if action_type == "read_public_document":
        return {
            "status": "simulated",
            "trust_level": "untrusted_result",
            "document": safe_args.get("document", "public-document"),
            "content": "SIMULATED_PUBLIC_DOCUMENT",
        }
    if action_type == "http_get":
        return {
            "status": "simulated",
            "trust_level": "untrusted_result",
            "method": "GET",
            "url": safe_args.get("url", ""),
            "body": "SIMULATED_HTTP_GET",
        }
    if action_type == "http_post":
        return {
            "status": "simulated",
            "trust_level": "untrusted_result",
            "method": "POST",
            "url": safe_args.get("url", ""),
            "body": "SIMULATED_HTTP_POST",
        }
    if action_type == "run_shell_command":
        return {
            "status": "simulated",
            "trust_level": "untrusted_result",
            "command": safe_args.get("command", ""),
            "stdout": "SIMULATED_SHELL_OUTPUT",
            "returncode": 0,
        }
    if action_type == "send_email":
        return {
            "status": "simulated",
            "recipient": safe_args.get("to", ""),
            "message_id": "simulated-message",
        }
    return {
        "status": "simulated",
        "document": safe_args.get("document", "restricted-document"),
    }


def _validate_registered_agent(
    db: Session, request: GatewayActionRequest
) -> Agent | None:
    agent = db.scalar(select(Agent).where(Agent.external_agent_id == request.agent_id))
    if agent is None:
        # Compatibility for the original custom-action UI: local demo mode,
        # simulator-only schemas, and an entirely empty registry. Shared mode
        # and any configured registry always require a registered identity.
        demo = os.getenv("AGENTSHIELD_DEMO_MODE", "true").casefold() in {
            "true",
            "1",
            "yes",
        }
        if demo and db.scalar(select(Agent.id).limit(1)) is None:
            return None
        raise HTTPException(status_code=403, detail="Unknown agent")
    if agent.status != "active":
        raise HTTPException(status_code=403, detail=f"Agent is {agent.status}")
    if request.tool_name not in agent.allowed_tools:
        raise HTTPException(status_code=403, detail="Tool is not allowed for agent")
    if request.action_type == "send_email":
        recipient = request.arguments.get("to")
        if (
            not isinstance(recipient, str)
            or recipient.count("@") != 1
            or recipient.rsplit("@", 1)[1].casefold() not in agent.approved_domains
            or any(char.isspace() for char in recipient)
        ):
            raise HTTPException(
                status_code=403, detail="Recipient domain is not approved"
            )
    url = request.arguments.get("url")
    if url is not None or request.action_type in {"http_get", "http_post"}:
        try:
            parsed = urlparse(url) if isinstance(url, str) else None
            valid = (
                parsed is not None
                and parsed.scheme in {"https", "http"}
                and parsed.hostname is not None
                and parsed.hostname.casefold() in agent.approved_domains
                and parsed.username is None
                and parsed.password is None
                and not any(char.isspace() for char in url)
            )
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(
                status_code=403, detail="Destination domain is not approved"
            )
    return agent


def check_action(
    db: Session, request: GatewayActionRequest, *, create_approval: bool = True
) -> GatewayActionResponse:
    session = db.scalar(
        select(AgentSession).where(AgentSession.id == request.session_id)
    )
    if session is None or session.agent_id != request.agent_id:
        raise HTTPException(status_code=404, detail="Session not found")
    # Capture original evidence before arguments are redacted for storage. Never
    # retain detector previews or snippets of sensitive/untrusted source text.
    prompt = asdict(
        RuleBasedPromptInjectionDetector().detect(
            AgentShieldPolicyEngine._text(request.arguments)
        )
    )
    sensitive = asdict(RuleBasedSensitiveDataDetector().detect(request.arguments))
    sensitive.pop("redacted_preview", None)
    try:
        agent = _validate_registered_agent(db, request)
    except HTTPException as error:
        # Store denied attempts just like policy blocks, without ever executing.
        denied = save_action_request(
            db,
            ActionRequestCreate(
                session_id=request.session_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                action_type=request.action_type,
                arguments=request.arguments,
                source_trust_level=request.source_trust_level,
                risk_score=100,
                decision="block",
                reasons=[str(error.detail)],
            ),
        )
        save_security_decision(db, denied.id, "block", [str(error.detail)])
        record_audit_event(
            db,
            request.session_id,
            "agent_action_denied",
            {
                "action_request_id": denied.id,
                "reason": error.detail,
                "prompt_injection": prompt,
                "sensitive_data": sensitive,
                "matched_policies": ["agent_registry"],
            },
        )
        raise
    source = classify_source(request.source_trust_level)
    evaluation = AgentShieldPolicyEngine(
        approved_domains=set(agent.approved_domains) if agent is not None else None
    ).evaluate(
        ActionInput(
            request.tool_name,
            request.action_type,
            request.arguments,
            source,
            request.agent_id,
            request.session_id,
        )
    )
    snapshot = request.model_dump(
        exclude={
            "simulator_mode",
            "action_id",
            "idempotency_key",
            "approval_request_id",
        }
    )
    snapshot.update(
        risk_score=evaluation.risk_score,
        decision=evaluation.decision,
        reasons=evaluation.reasons,
        source_trust_level=source,
    )
    action = save_action_request(db, ActionRequestCreate.model_validate(snapshot))
    save_security_decision(db, action.id, evaluation.decision, evaluation.reasons)
    approval_id = None
    if evaluation.decision == "approval_required" and create_approval:
        approval_hash = canonical_request_hash(
            session_id=request.session_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            action_type=request.action_type,
            arguments=request.arguments,
            source_trust_level=source,
        )
        approval_id = queue_approval(
            db,
            action.id,
            request_hash=approval_hash,
            risk_score=evaluation.risk_score,
            reasons=evaluation.reasons,
            policy_context={
                "decision": evaluation.decision,
                "matched_policies": evaluation.matched_policies,
            },
        ).id
    record_audit_event(
        db,
        request.session_id,
        "action_checked",
        {
            "action_request_id": action.id,
            "decision": evaluation.decision,
            "risk_score": evaluation.risk_score,
            "reasons": evaluation.reasons,
            "action_type": request.action_type,
            "approval_created": approval_id is not None,
            "approval_request_id": approval_id,
            "prompt_injection": prompt,
            "sensitive_data": sensitive,
            "matched_policies": evaluation.matched_policies,
        },
    )
    return GatewayActionResponse(
        action_request_id=action.id,
        decision=evaluation.decision,
        risk_score=evaluation.risk_score,
        reasons=evaluation.reasons,
        source_trust_level=source,
        executed=False,
        approval_request_id=approval_id,
    )


def execute_action(db: Session, request: GatewayActionRequest) -> GatewayActionResponse:
    approval = None
    if request.approval_request_id:
        approval = db.get(ApprovalRequest, request.approval_request_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        from .services import expire_approval

        if expire_approval(db, approval):
            raise HTTPException(status_code=410, detail="Approval expired")
        if approval.status != "approved":
            raise HTTPException(status_code=409, detail="Approval is not approved")
        supplied_hash = canonical_request_hash(
            session_id=request.session_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            action_type=request.action_type,
            arguments=request.arguments,
            source_trust_level=classify_source(request.source_trust_level),
        )
        if supplied_hash != approval.request_hash:
            record_audit_event(
                db,
                request.session_id,
                "approval_replay_or_modification_failed",
                {"approval_request_id": approval.id, "reason": "request_hash_mismatch"},
            )
            raise HTTPException(
                status_code=409, detail="Approval does not match request"
            )
    checked = check_action(db, request, create_approval=approval is None)
    if approval is not None:
        if checked.decision == "block":
            raise HTTPException(
                status_code=403, detail="Mandatory policy block cannot be bypassed"
            )
        if checked.decision != "approval_required":
            raise HTTPException(status_code=409, detail="Approval no longer applies")
        # check_action performs the final policy recheck; consume only after it passes.
        consumed = (
            db.execute(
                update(ApprovalRequest)
                .where(
                    ApprovalRequest.id == approval.id,
                    ApprovalRequest.status == "approved",
                    ApprovalRequest.request_hash == supplied_hash,
                )
                .values(status="consumed")
            ).rowcount
            == 1
        )
        if not consumed:
            db.rollback()
            raise HTTPException(status_code=409, detail="Approval was already consumed")
        db.commit()
        checked.decision = "allow"
    if checked.decision != "allow":
        return checked
    result = _simulate(request.action_type, request.arguments)
    record_audit_event(
        db,
        request.session_id,
        "action_executed",
        {
            "action_request_id": checked.action_request_id,
            "action_type": request.action_type,
            "result": result,
        },
    )
    checked.executed = True
    checked.result = result
    return checked
