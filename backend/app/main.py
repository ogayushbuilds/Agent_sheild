"""FastAPI application entrypoint for AgentShield."""

import os
import secrets
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .chat_monitor import (
    analyze as analyze_chat,
)
from .chat_monitor import (
    create_session as create_chat_session,
)
from .chat_monitor import (
    get_session as get_chat_session,
)
from .chat_monitor import (
    list_audits as list_chat_audits,
)
from .chat_monitor import (
    list_events as list_chat_events,
)
from .chat_monitor import (
    list_sessions as list_chat_sessions,
)
from .database import create_database, get_db, initialize_database
from .demo import build_trace, load_trace, persist_trace
from .gateway import (
    check_action as gateway_check_action,
)
from .gateway import (
    execute_action as gateway_execute_action,
)
from .models import ActionRequest, Agent, AgentSession, ApprovalRequest, AuditEvent
from .repository import (
    action_evidence,
    create_agent,
    get_agent,
    list_agents,
    list_approval_requests,
)
from .schemas import (
    AgentActionResponse,
    AgentActionsResponse,
    AgentCreate,
    AgentDetailResponse,
    AgentIncidentResponse,
    AgentIncidentsResponse,
    AgentListResponse,
    AgentMetricsResponse,
    AgentPatch,
    AgentResponse,
    ApprovalAction,
    ApprovalListResponse,
    ApprovalResponse,
    AuditEventListResponse,
    AuditEventResponse,
    ChatMonitorAnalyzeRequest,
    ChatMonitorAnalyzeResponse,
    ChatMonitorAuditEventListResponse,
    ChatMonitorEventListResponse,
    ChatMonitorSessionCreate,
    ChatMonitorSessionListResponse,
    ChatMonitorSessionResponse,
    DemoRunRequest,
    DemoTraceResponse,
    GatewayActionRequest,
    GatewayActionResponse,
    SessionCreate,
    SessionResponse,
)
from .security import redact_secrets
from .services import (
    approval_action_session,
    conditional_approval_update,
    expire_approval,
    get_audit_events,
    record_audit_event,
    start_session,
)


def create_app() -> FastAPI:
    """Create and configure the AgentShield API application."""
    app = FastAPI(title="AgentShield API", version="0.1.0")
    engine, session_factory = create_database()
    initialize_database(engine)
    app.state.session_factory = session_factory

    @app.middleware("http")
    async def request_limits(request: Request, call_next):
        if request.url.path.startswith("/api/v1/chat-monitor/"):
            expected = os.getenv("AGENTSHIELD_API_KEY")
            if expected or os.getenv(
                "AGENTSHIELD_DEMO_MODE", "true"
            ).casefold() not in {
                "1",
                "true",
                "yes",
            }:
                if not expected or not secrets.compare_digest(
                    request.headers.get("x-agentshield-api-key", "").encode(),
                    expected.encode(),
                ):
                    return JSONResponse(
                        {"detail": "Authentication required"}, status_code=401
                    )
            chunks = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > 256 * 1024:
                    return JSONResponse(
                        {"detail": "request body too large"}, status_code=413
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > 256 * 1024:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError):
        if request.url.path.startswith("/api/v1/chat-monitor/"):
            return JSONResponse(
                {"detail": "Invalid chat-monitor request"}, status_code=422
            )
        from fastapi.exception_handlers import request_validation_exception_handler

        return await request_validation_exception_handler(request, error)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            origin.strip()
            for origin in os.getenv(
                "AGENTSHIELD_CORS_ORIGINS",
                "http://localhost:5173,http://127.0.0.1:5173",
            ).split(",")
            if origin.strip()
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Return a basic service health response."""
        return {"status": "ok", "service": "agentshield-backend"}

    def db_dependency():
        yield from get_db(app.state.session_factory)

    @app.post("/sessions", response_model=SessionResponse, status_code=201)
    def create_session(request: SessionCreate, db=Depends(db_dependency)):
        row = start_session(db, request.agent_id, request.metadata)
        return SessionResponse(
            id=row.id,
            agent_id=row.agent_id,
            metadata=row.metadata_json,
            created_at=row.created_at,
        )

    def require_registry_auth(request: Request):
        """Use the existing minimal API-key boundary when demo mode is disabled."""
        expected = os.getenv("AGENTSHIELD_API_KEY")
        if expected:
            supplied = request.headers.get("x-agentshield-api-key", "")
            if not secrets.compare_digest(supplied.encode(), expected.encode()):
                raise HTTPException(
                    status_code=401, detail="Agent registry authentication required"
                )
            return
        if os.getenv("AGENTSHIELD_DEMO_MODE", "true").casefold() in {
            "1",
            "true",
            "yes",
        }:
            return
        raise HTTPException(
            status_code=401, detail="Agent registry authentication required"
        )

    def agent_response(row: Agent):
        return AgentResponse.model_validate(row, from_attributes=True)

    @app.post("/api/v1/agents", response_model=AgentResponse, status_code=201)
    def register_agent(
        request: AgentCreate, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        if (
            db.query(Agent)
            .filter(
                (Agent.name == request.name)
                | (Agent.external_agent_id == request.external_agent_id)
            )
            .first()
        ):
            raise HTTPException(status_code=409, detail="Agent already exists")
        row = create_agent(db, **request.model_dump())
        session = _agent_session(db, row.external_agent_id)
        record_audit_event(db, session.id, "agent_created", {"agent_id": row.id})
        return agent_response(row)

    @app.get("/api/v1/agents", response_model=AgentListResponse)
    def registered_agents(http_request: Request, db=Depends(db_dependency)):
        require_registry_auth(http_request)
        return AgentListResponse(
            agents=[agent_response(row) for row in list_agents(db)]
        )

    @app.get("/api/v1/agents/{agent_id}", response_model=AgentDetailResponse)
    def registered_agent(
        agent_id: str, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        actions = (
            db.query(ActionRequest)
            .filter(ActionRequest.agent_id == agent.external_agent_id)
            .all()
        )
        evidence = action_evidence(db, [row.id for row in actions])
        metrics = AgentMetricsResponse(
            actions=len(actions),
            incidents=sum(
                row.decision in {"block", "approval_required"} for row in actions
            ),
            blocked=sum(row.decision == "block" for row in actions),
            approval_required=sum(
                row.decision == "approval_required" for row in actions
            ),
            allowed=sum(
                row.decision in {"allow", "allow_with_warning"} for row in actions
            ),
            prompt_injection_incidents=sum(
                bool(item.get("prompt_injection", {}).get("detected"))
                for item in evidence.values()
            ),
            sensitive_data_incidents=sum(
                bool(item.get("sensitive_data", {}).get("detected"))
                for item in evidence.values()
            ),
            average_risk_score=sum(row.risk_score for row in actions) / len(actions)
            if actions
            else 0.0,
            pending_approvals=db.query(ApprovalRequest)
            .join(ActionRequest, ActionRequest.id == ApprovalRequest.action_request_id)
            .filter(
                ActionRequest.agent_id == agent.external_agent_id,
                ApprovalRequest.status == "pending",
                ApprovalRequest.expires_at > datetime.utcnow(),
            )
            .count(),
            last_activity_timestamp=max(
                (row.timestamp for row in actions), default=None
            ),
        )
        return AgentDetailResponse(
            **agent_response(agent).model_dump(), metrics=metrics
        )

    @app.patch("/api/v1/agents/{agent_id}", response_model=AgentResponse)
    def update_agent(
        agent_id: str,
        request: AgentPatch,
        http_request: Request,
        db=Depends(db_dependency),
    ):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        values = request.model_dump(exclude_unset=True)
        previous = {key: getattr(agent, key) for key in values}
        if (
            "name" in values
            and db.query(Agent)
            .filter(Agent.name == values["name"], Agent.id != agent.id)
            .first()
        ):
            raise HTTPException(status_code=409, detail="Agent name already exists")
        for key, value in values.items():
            setattr(agent, key, value)
        db.commit()
        db.refresh(agent)
        session = _agent_session(db, agent.external_agent_id)
        record_audit_event(
            db,
            session.id,
            "agent_config_changed",
            {
                "agent_id": agent.id,
                "fields": list(values),
                "before": previous,
                "after": values,
            },
        )
        return agent_response(agent)

    @app.post("/api/v1/agents/{agent_id}/pause", response_model=AgentResponse)
    def pause_agent(agent_id: str, http_request: Request, db=Depends(db_dependency)):
        return _set_agent_status(agent_id, "paused", http_request, db)

    @app.post("/api/v1/agents/{agent_id}/resume", response_model=AgentResponse)
    def resume_agent(agent_id: str, http_request: Request, db=Depends(db_dependency)):
        return _set_agent_status(agent_id, "active", http_request, db)

    def _set_agent_status(agent_id, status, http_request, db):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        if agent.status == "disabled":
            raise HTTPException(
                status_code=409, detail="Disabled agents require a configuration update"
            )
        agent.status = status
        db.commit()
        db.refresh(agent)
        session = _agent_session(db, agent.external_agent_id)
        if session:
            record_audit_event(
                db,
                session.id,
                "agent_status_changed",
                {"agent_id": agent.id, "status": status},
            )
        return agent_response(agent)

    def _agent_session(db, external_id):
        session = (
            db.query(AgentSession)
            .filter(AgentSession.agent_id == external_id)
            .order_by(AgentSession.created_at)
            .first()
        )
        if session is None:
            session = AgentSession(
                agent_id=external_id, metadata_json={"internal": "registry"}
            )
            db.add(session)
            db.commit()
            db.refresh(session)
        return session

    @app.get("/api/v1/agents/{agent_id}/actions", response_model=AgentActionsResponse)
    def agent_actions(agent_id: str, http_request: Request, db=Depends(db_dependency)):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        rows = (
            db.query(ActionRequest)
            .filter(ActionRequest.agent_id == agent.external_agent_id)
            .order_by(ActionRequest.timestamp)
            .all()
        )
        evidence = action_evidence(db, [row.id for row in rows])
        return AgentActionsResponse(
            actions=[
                AgentActionResponse(
                    **AgentActionResponse.model_validate(
                        row, from_attributes=True
                    ).model_dump(
                        exclude={
                            "prompt_injection",
                            "sensitive_data",
                            "matched_policies",
                        }
                    ),
                    prompt_injection=evidence.get(row.id, {}).get("prompt_injection"),
                    sensitive_data=evidence.get(row.id, {}).get("sensitive_data"),
                    matched_policies=evidence.get(row.id, {}).get(
                        "matched_policies", []
                    ),
                )
                for row in rows
            ]
        )

    @app.get(
        "/api/v1/agents/{agent_id}/incidents", response_model=AgentIncidentsResponse
    )
    def agent_incidents(
        agent_id: str, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        rows = (
            db.query(ActionRequest)
            .filter(
                ActionRequest.agent_id == agent.external_agent_id,
                ActionRequest.decision.in_(["block", "approval_required"]),
            )
            .order_by(ActionRequest.timestamp)
            .all()
        )
        return AgentIncidentsResponse(
            incidents=[
                AgentIncidentResponse(
                    id=row.id,
                    agent_id=row.agent_id,
                    session_id=row.session_id,
                    action_request_id=row.id,
                    severity="high" if row.decision == "block" else "medium",
                    decision=row.decision,
                    reasons=row.reasons,
                    created_at=row.timestamp,
                )
                for row in rows
            ]
        )

    @app.get(
        "/api/v1/agents/{agent_id}/audit-events", response_model=AuditEventListResponse
    )
    def agent_audit_events(
        agent_id: str, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        agent = get_agent(db, agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        sessions = db.query(AgentSession.id).filter(
            AgentSession.agent_id == agent.external_agent_id
        )
        events = (
            db.query(AuditEvent)
            .filter(AuditEvent.session_id.in_(sessions))
            .order_by(AuditEvent.created_at, AuditEvent.id)
            .all()
        )
        return AuditEventListResponse(
            events=[
                AuditEventResponse.model_validate(event, from_attributes=True)
                for event in events
            ]
        )

    @app.get(
        "/sessions/{session_id}/audit-events", response_model=AuditEventListResponse
    )
    def audit_events(session_id: str, db=Depends(db_dependency)):
        events = get_audit_events(db, session_id)
        return AuditEventListResponse(
            events=[
                AuditEventResponse.model_validate(event, from_attributes=True)
                for event in events
            ]
        )

    @app.post("/api/v1/check-action", response_model=GatewayActionResponse)
    def check_action(
        request: GatewayActionRequest, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        return gateway_check_action(db, request)

    @app.post("/api/v1/execute-action", response_model=GatewayActionResponse)
    def execute_action(
        request: GatewayActionRequest, http_request: Request, db=Depends(db_dependency)
    ):
        require_registry_auth(http_request)
        return gateway_execute_action(db, request)

    @app.post("/api/v1/demo/safe-run", response_model=DemoTraceResponse)
    def safe_demo_run(
        _request: DemoRunRequest = DemoRunRequest(), db=Depends(db_dependency)
    ):
        return persist_trace(db, build_trace("safe"))

    @app.post("/api/v1/demo/attack-run", response_model=DemoTraceResponse)
    def attack_demo_run(
        _request: DemoRunRequest = DemoRunRequest(), db=Depends(db_dependency)
    ):
        return persist_trace(db, build_trace("attack"))

    @app.get("/api/v1/demo/trace/{trace_id}", response_model=DemoTraceResponse)
    def demo_trace(trace_id: str, db=Depends(db_dependency)):
        trace = load_trace(db, trace_id)
        if trace is None:
            raise HTTPException(status_code=404, detail="Demo trace not found")
        return trace

    def chat_session_response(row):
        return ChatMonitorSessionResponse(
            id=row.id,
            source_type=row.source_type,
            url=row.source_url,
            metadata=row.metadata_json,
            status=row.status,
            created_at=row.created_at,
        )

    @app.post(
        "/api/v1/chat-monitor/sessions",
        response_model=ChatMonitorSessionResponse,
        status_code=201,
    )
    def create_chat_monitor_session(
        request: ChatMonitorSessionCreate, db=Depends(db_dependency)
    ):
        try:
            row = create_chat_session(
                db,
                request.source_type,
                request.url,
                request.pasted_text,
                request.metadata,
            )
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return chat_session_response(row)

    @app.get(
        "/api/v1/chat-monitor/sessions", response_model=ChatMonitorSessionListResponse
    )
    def chat_monitor_sessions(db=Depends(db_dependency)):
        return ChatMonitorSessionListResponse(
            sessions=[chat_session_response(row) for row in list_chat_sessions(db)]
        )

    @app.get(
        "/api/v1/chat-monitor/sessions/{session_id}",
        response_model=ChatMonitorSessionResponse,
    )
    def chat_monitor_session(session_id: str, db=Depends(db_dependency)):
        return chat_session_response(get_chat_session(db, session_id))

    @app.post(
        "/api/v1/chat-monitor/sessions/{session_id}/analyze",
        response_model=ChatMonitorAnalyzeResponse,
    )
    def analyze_chat_monitor_session(
        session_id: str,
        request: ChatMonitorAnalyzeRequest = ChatMonitorAnalyzeRequest(),
        db=Depends(db_dependency),
    ):
        row = get_chat_session(db, session_id)
        result = analyze_chat(db, row, request.pasted_text, request.fetch_consent)
        db.commit()
        return ChatMonitorAnalyzeResponse(session=chat_session_response(row), **result)

    @app.get(
        "/api/v1/chat-monitor/sessions/{session_id}/events",
        response_model=ChatMonitorEventListResponse,
    )
    def chat_monitor_events(session_id: str, db=Depends(db_dependency)):
        return ChatMonitorEventListResponse(events=list_chat_events(db, session_id))

    @app.get(
        "/api/v1/chat-monitor/sessions/{session_id}/audit-events",
        response_model=ChatMonitorAuditEventListResponse,
    )
    def chat_monitor_audit_events(session_id: str, db=Depends(db_dependency)):
        return ChatMonitorAuditEventListResponse(
            events=list_chat_audits(db, session_id)
        )

    def approval_response(row, db):
        action = db.get(ActionRequest, row.action_request_id)
        return ApprovalResponse(
            id=row.id,
            action_request_id=row.action_request_id,
            status=row.status,
            request_hash=row.request_hash,
            risk_score=row.risk_score,
            reasons=row.reasons,
            policy_context=row.policy_context,
            expires_at=row.expires_at,
            reviewer=row.reviewer,
            created_at=row.created_at,
            acted_at=row.acted_at,
            action={
                "session_id": action.session_id,
                "agent_id": action.agent_id,
                "tool_name": action.tool_name,
                "action_type": action.action_type,
                "arguments": redact_secrets(action.arguments),
                "source_trust_level": action.source_trust_level,
            },
        )

    def require_approval_auth(request: Request):
        if os.getenv("AGENTSHIELD_DEMO_MODE", "true").casefold() in {
            "1",
            "true",
            "yes",
        }:
            return
        expected = os.getenv("AGENTSHIELD_API_KEY")
        if not expected or request.headers.get("x-agentshield-api-key") != expected:
            raise HTTPException(
                status_code=401, detail="Approval API authentication required"
            )

    @app.get("/api/v1/approvals", response_model=ApprovalListResponse)
    def approvals(request: Request, db=Depends(db_dependency)):
        require_approval_auth(request)
        rows = list_approval_requests(db)
        for row in rows:
            expire_approval(db, row)
        return ApprovalListResponse(
            approvals=[approval_response(row, db) for row in rows]
        )

    @app.post(
        "/api/v1/approvals/{approval_id}/approve", response_model=ApprovalResponse
    )
    def approve(
        approval_id: str,
        request: ApprovalAction,
        http_request: Request,
        db=Depends(db_dependency),
    ):
        require_approval_auth(http_request)
        row = db.get(ApprovalRequest, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        if expire_approval(db, row):
            raise HTTPException(status_code=410, detail="Approval expired")
        if not conditional_approval_update(
            db, approval_id, "pending", "approved", request.reviewer
        ):
            raise HTTPException(status_code=409, detail="Approval is no longer pending")
        db.refresh(row)
        record_audit_event(
            db,
            approval_action_session(db, row),
            "approval_approved",
            {"approval_request_id": row.id, "reviewer": request.reviewer},
        )
        return approval_response(row, db)

    @app.post("/api/v1/approvals/{approval_id}/deny", response_model=ApprovalResponse)
    def deny(
        approval_id: str,
        request: ApprovalAction,
        http_request: Request,
        db=Depends(db_dependency),
    ):
        require_approval_auth(http_request)
        row = db.get(ApprovalRequest, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        if expire_approval(db, row):
            raise HTTPException(status_code=410, detail="Approval expired")
        if not conditional_approval_update(
            db, approval_id, "pending", "denied", request.reviewer
        ):
            raise HTTPException(status_code=409, detail="Approval is no longer pending")
        db.refresh(row)
        record_audit_event(
            db,
            approval_action_session(db, row),
            "approval_denied",
            {"approval_request_id": row.id, "reviewer": request.reviewer},
        )
        return approval_response(row, db)

    return app


app = create_app()
