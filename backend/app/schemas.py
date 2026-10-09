"""Strict API schemas."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @field_validator("arguments", "metadata", mode="before", check_fields=False)
    @classmethod
    def bounded_json(cls, value):
        def check(item, depth=0):
            if depth > 8:
                raise ValueError("JSON nesting is too deep")
            if isinstance(item, str) and len(item) > 16_384:
                raise ValueError("string value is too large")
            if isinstance(item, dict):
                if len(item) > 100:
                    raise ValueError("too many object fields")
                for key, child in item.items():
                    check(key, depth + 1)
                    check(child, depth + 1)
            elif isinstance(item, (list, tuple)):
                if len(item) > 100:
                    raise ValueError("collection is too large")
                for child in item:
                    check(child, depth + 1)

        check(value)
        return value


class SessionCreate(StrictModel):
    agent_id: str = Field(min_length=1, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionResponse(StrictModel):
    id: str
    agent_id: str
    metadata: dict[str, Any]
    created_at: datetime


class AuditEventResponse(StrictModel):
    id: str
    session_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime


class AuditEventListResponse(StrictModel):
    events: list[AuditEventResponse]


AgentStatus = Literal["active", "paused", "disabled"]
AgentEnvironment = Literal["development", "staging", "production"]


class AgentCreate(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    external_agent_id: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    environment: AgentEnvironment
    status: AgentStatus = "active"
    allowed_tools: list[str] = Field(default_factory=list, max_length=100)
    approved_domains: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("name", "external_agent_id", "environment")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("value must be nonblank without surrounding whitespace")
        return value

    @field_validator("allowed_tools", "approved_domains")
    @classmethod
    def validate_strings(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or len(item) > 255 for item in value):
            raise ValueError(
                "values must be non-empty strings of at most 255 characters"
            )
        if len(set(value)) != len(value):
            raise ValueError("values must be unique")
        return value

    @field_validator("approved_domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        normalized = [item.casefold() for item in value]
        for domain in normalized:
            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
                domain,
            ):
                raise ValueError("approved domains must be exact DNS hostnames")
        if len(set(normalized)) != len(normalized):
            raise ValueError("domains must be unique")
        return normalized


class AgentPatch(StrictModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    environment: Optional[AgentEnvironment] = None
    status: Optional[AgentStatus] = None
    allowed_tools: Optional[list[str]] = Field(default=None, max_length=100)
    approved_domains: Optional[list[str]] = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_patch(self):
        values = self.model_dump(exclude_unset=True)
        if not values or any(value is None for value in values.values()):
            raise ValueError("provide at least one non-null field")
        for field in ("name", "environment"):
            if field in values:
                AgentCreate.nonblank(values[field])
        if "approved_domains" in values:
            self.approved_domains = AgentCreate.validate_domains(
                values["approved_domains"]
            )
        return self

    @field_validator("allowed_tools", "approved_domains")
    @classmethod
    def validate_patch_strings(cls, value):
        if value is not None:
            return AgentCreate.validate_strings(value)
        return value


class AgentResponse(StrictModel):
    id: str
    name: str
    external_agent_id: str
    description: str
    environment: AgentEnvironment
    status: AgentStatus
    allowed_tools: list[str]
    approved_domains: list[str]
    created_at: datetime
    updated_at: datetime


class AgentListResponse(StrictModel):
    agents: list[AgentResponse]


class AgentActionResponse(StrictModel):
    id: str
    agent_id: str
    session_id: str
    tool_name: str
    action_type: str
    decision: str
    risk_score: float
    reasons: list[str]
    arguments: dict[str, Any]
    timestamp: datetime
    prompt_injection: Optional[dict[str, Any]] = None
    sensitive_data: Optional[dict[str, Any]] = None
    matched_policies: list[str] = Field(default_factory=list)


class AgentActionsResponse(StrictModel):
    actions: list[AgentActionResponse]


class AgentIncidentResponse(StrictModel):
    id: str
    agent_id: str
    session_id: str
    action_request_id: str
    severity: str
    decision: str
    reasons: list[str]
    created_at: datetime


class AgentIncidentsResponse(StrictModel):
    incidents: list[AgentIncidentResponse]


class AgentMetricsResponse(StrictModel):
    actions: int
    incidents: int
    blocked: int
    approval_required: int
    allowed: int
    prompt_injection_incidents: int
    sensitive_data_incidents: int
    average_risk_score: float
    pending_approvals: int
    last_activity_timestamp: Optional[datetime] = None


class AgentDetailResponse(AgentResponse):
    metrics: AgentMetricsResponse


class ActionRequestCreate(StrictModel):
    session_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1, max_length=255)
    tool_name: str = Field(min_length=1, max_length=255)
    action_type: str = Field(min_length=1, max_length=255)
    arguments: dict[str, Any] = Field(default_factory=dict)
    source_trust_level: str = Field(min_length=1, max_length=64)
    risk_score: float = Field(ge=0, le=100)
    decision: str = Field(min_length=1, max_length=64)
    reasons: list[str]

    @field_validator("reasons")
    @classmethod
    def reasons_are_strings(cls, value: list[str]) -> list[str]:
        return value


SimulatorAction = Literal[
    "read_public_document",
    "read_restricted_document",
    "http_get",
    "http_post",
    "run_shell_command",
    "send_email",
]


class GatewayActionRequest(StrictModel):
    session_id: str = Field(min_length=1, max_length=36)
    agent_id: str = Field(min_length=1, max_length=255)
    tool_name: str = Field(min_length=1, max_length=255)
    action_type: SimulatorAction
    arguments: dict[str, Any] = Field(default_factory=dict)
    source_trust_level: Literal["trusted", "untrusted", "user", "system", "unknown"] = (
        "unknown"
    )
    simulator_mode: Literal[True]
    action_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    idempotency_key: Optional[str] = Field(default=None, min_length=1, max_length=128)
    approval_request_id: Optional[str] = Field(
        default=None, min_length=1, max_length=36
    )


class GatewayActionResponse(StrictModel):
    action_request_id: str
    decision: Literal["allow", "block", "approval_required", "redact"]
    risk_score: float
    reasons: list[str]
    source_trust_level: str
    executed: bool
    result: Optional[dict[str, Any]] = None
    approval_request_id: Optional[str] = None


class ApprovalAction(StrictModel):
    reviewer: Optional[str] = Field(default=None, max_length=255)


class ApprovalResponse(StrictModel):
    id: str
    action_request_id: str
    status: Literal["pending", "approved", "denied", "expired", "consumed"]
    request_hash: str
    risk_score: float
    reasons: list[str]
    policy_context: dict[str, Any]
    expires_at: datetime
    reviewer: Optional[str] = None
    created_at: datetime
    acted_at: Optional[datetime] = None
    action: dict[str, Any]


class ApprovalListResponse(StrictModel):
    approvals: list[ApprovalResponse]


class DemoRunRequest(StrictModel):
    """The demo has fixed fixtures; callers cannot inject scenario content."""


class DemoDetectorFinding(StrictModel):
    detector: Literal["prompt_injection", "sensitive_data"]
    detected: bool
    indicators: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    severity: str = "none"
    confidence: float = Field(ge=0, le=1)
    redacted_preview: str = ""
    reasons: list[str] = Field(default_factory=list)


class DemoToolCall(StrictModel):
    tool_name: str
    action_type: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    executed: bool = False


class DemoRiskFactor(StrictModel):
    name: str
    weight: float
    reason: str


class DemoTraceEvent(StrictModel):
    sequence: int = Field(ge=1)
    event_id: str
    event_type: str
    description: str
    tool_call: Optional[DemoToolCall] = None
    detector_findings: list[DemoDetectorFinding] = Field(default_factory=list)
    risk_score: float = Field(ge=0, le=100)
    policy_matches: list[str] = Field(default_factory=list)
    risk_factors: list[DemoRiskFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    decision: Literal["allow", "block", "approval_required", "observed"]


class DemoTraceResponse(StrictModel):
    trace_id: str
    scenario: Literal["safe", "attack"]
    simulator_mode: Literal[True]
    final_decision: Literal["allow", "block"]
    explanation: str
    events: list[DemoTraceEvent]


ChatSourceType = Literal["pasted_text", "metadata_only", "chatgpt_share"]


class ChatMonitorSessionCreate(StrictModel):
    source_type: ChatSourceType
    url: Optional[str] = Field(default=None, max_length=2048)
    pasted_text: Optional[str] = Field(default=None, max_length=131072)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def nonempty_url(cls, value):
        if value is not None and not value.strip():
            raise ValueError("url must not be empty")
        return value


class ChatMonitorAnalyzeRequest(StrictModel):
    pasted_text: Optional[str] = Field(default=None, max_length=131072)
    fetch_consent: bool = False


class ChatMonitorSessionResponse(StrictModel):
    id: str
    source_type: ChatSourceType
    url: Optional[str] = None
    metadata: dict[str, Any]
    status: Literal["created", "evaluated", "not_evaluated", "analysis_failed"]
    created_at: datetime


class ChatMonitorSessionListResponse(StrictModel):
    sessions: list[ChatMonitorSessionResponse]


class ChatMonitorEventResponse(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, from_attributes=True)
    id: str
    session_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]
    redacted_text: Optional[str] = None
    created_at: datetime


class ChatMonitorEventListResponse(StrictModel):
    events: list[ChatMonitorEventResponse]


class ChatMonitorAuditEventResponse(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, from_attributes=True)
    id: str
    session_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime


class ChatMonitorAuditEventListResponse(StrictModel):
    events: list[ChatMonitorAuditEventResponse]


class ChatMonitorAnalyzeResponse(StrictModel):
    decision: Literal["allow", "redact", "approval_required", "block", "not_evaluated"]
    policy_matches: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommendation_scope: Literal["retrospective_analysis"] = "retrospective_analysis"
    runtime_enforced: Literal[False] = False
    content_sha256: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    session: ChatMonitorSessionResponse
    status: Literal["evaluated", "not_evaluated"]
    limitation: Optional[str] = None
    findings: list[DemoDetectorFinding] = Field(default_factory=list)
    urls_detected: list[str] = Field(default_factory=list)
    tool_call_instructions_detected: bool = False
    redacted_preview: str = ""
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    source_trust_level: Literal["untrusted"] = "untrusted"
    executed: Literal[False] = False
