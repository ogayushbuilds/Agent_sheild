"""Deterministic, explainable AgentShield action policy evaluation.

This module only classifies requests.  It never invokes tools, follows URLs, or
performs an action.  Inputs are copied into a small immutable adapter so ORM
objects, API dictionaries, and callers can use the same policy engine.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping
from urllib.parse import urlparse

from .detection import RuleBasedPromptInjectionDetector, RuleBasedSensitiveDataDetector
from .risk import RiskFactor, RiskScorer

Decision = Literal[
    "allow", "allow_with_warning", "block", "approval_required", "redact"
]


@dataclass(frozen=True)
class ActionInput:
    """The action facts used by policy matching (no executable callback)."""

    tool_name: str
    action_type: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    source_trust_level: str = "unknown"
    agent_id: str | None = None
    session_id: str | None = None


PolicyAction = ActionInput


@dataclass(frozen=True)
class PolicyEvaluation:
    """Stable policy output suitable for persistence and audit display."""

    decision: Decision
    risk_score: float
    reasons: list[str]
    matched_policies: list[str]
    redactions: list[str]
    risk_factors: list[RiskFactor] = field(default_factory=list)

    @property
    def factors(self) -> list[RiskFactor]:
        """Convenient stable alias for API and audit consumers."""
        return self.risk_factors


@dataclass(frozen=True)
class PolicyDefinition:
    """A pure custom rule.  ``matcher`` must not perform side effects."""

    name: str
    priority: int
    decision: Decision
    matcher: Callable[[ActionInput], bool]
    reason: str
    risk_score: float = 0.0
    redactions: tuple[str, ...] = ()


def adapt_action(value: ActionInput | Mapping[str, Any] | object) -> ActionInput:
    """Adapt an API mapping or ``ActionRequest``-like ORM object safely."""

    if isinstance(value, ActionInput):
        return value
    if isinstance(value, Mapping):
        get = value.get
    else:

        def get(key: str, default: Any = None) -> Any:
            return getattr(value, key, default)

    arguments = get("arguments", {})
    if not isinstance(arguments, Mapping):
        arguments = {}
    return ActionInput(
        tool_name=str(get("tool_name", "")),
        action_type=str(get("action_type", "")),
        arguments=dict(arguments),
        source_trust_level=str(get("source_trust_level", "unknown")),
        agent_id=get("agent_id"),
        session_id=get("session_id"),
    )


class AgentShieldPolicyEngine:
    """Evaluate actions with deterministic defaults and optional custom rules."""

    _DEFAULT_DOMAINS = frozenset({"example.com", "api.example.com", "www.example.com"})
    _DECISION_ORDER = {"allow": 0, "redact": 1, "approval_required": 2, "block": 3}
    _SHELL = frozenset({"shell", "terminal", "command", "subprocess"})
    _MESSAGING = frozenset({"email", "messaging", "slack", "chat", "sms"})
    _NETWORK_TYPES = frozenset(
        {"web_request", "http_request", "request", "browse", "http_get", "http_post"}
    )
    _UPLOAD_TYPES = frozenset({"upload", "send", "post", "http_post", "share"})

    def __init__(
        self,
        approved_domains: set[str] | frozenset[str] | None = None,
        policies: list[PolicyDefinition] | tuple[PolicyDefinition, ...] | None = None,
        prompt_detector: RuleBasedPromptInjectionDetector | None = None,
        sensitive_detector: RuleBasedSensitiveDataDetector | None = None,
        risk_weights: Mapping[str, float] | None = None,
    ) -> None:
        self.approved_domains = frozenset(
            domain.casefold().strip(".")
            for domain in (approved_domains or self._DEFAULT_DOMAINS)
        )
        self.prompt_detector = prompt_detector or RuleBasedPromptInjectionDetector()
        self.sensitive_detector = sensitive_detector or RuleBasedSensitiveDataDetector()
        self.policies = tuple(policies or ())
        self.risk_scorer = RiskScorer(risk_weights)

    def evaluate(
        self, value: ActionInput | Mapping[str, Any] | object
    ) -> PolicyEvaluation:
        action = adapt_action(value)
        matches = self._matches(action)
        facts = self._risk_facts(action)
        assessment = self.risk_scorer.score(facts)
        matched_names = [rule.name for rule in matches]
        reasons = [rule.reason for rule in matches]
        redactions = sorted({path for rule in matches for path in rule.redactions})

        if matches:
            # A deny is never weakened by a lower/higher priority approval or allow.
            blocks = [rule for rule in matches if rule.decision == "block"]
            selected = max(
                blocks or matches,
                key=lambda rule: (rule.priority, self._DECISION_ORDER[rule.decision]),
            )
            return PolicyEvaluation(
                selected.decision,
                100.0
                if any(rule.decision == "block" for rule in matches)
                else assessment.score,
                reasons,
                matched_names,
                redactions,
                assessment.factors,
            )

        # Unknown or malformed actions fail closed; recognized safe web requests
        # are allowed only after domain approval and detector inspection.
        return PolicyEvaluation(
            "block",
            100.0,
            ["Action type is unknown or has no applicable safe policy."],
            [],
            [],
            assessment.factors,
        )

    def _risk_facts(self, action: ActionInput) -> dict[str, bool]:
        tool = action.tool_name.casefold()
        action_type = action.action_type.casefold()
        text = self._text(action.arguments)
        injection = self.prompt_detector.detect(text)
        sensitive = self.sensitive_detector.detect(action.arguments)
        domain = self._destination_domain(action.arguments)
        valid_destination = self._valid_destination(action.arguments)
        network = action_type in self._NETWORK_TYPES
        upload = (
            action_type in self._UPLOAD_TYPES and tool not in self._MESSAGING
        ) or "upload" in tool
        approved = (
            valid_destination and domain is not None and domain in self.approved_domains
        )
        read_only = (
            network
            and approved
            and action_type in {"web_request", "http_get", "browse"}
            and tool not in self._UPLOAD_TYPES
        )
        secret = self._secret_access_attempt(action, injection)
        return {
            "untrusted_source": action.source_trust_level.casefold() == "untrusted",
            "prompt_injection_detected": injection.detected,
            "sensitive_data_detected": sensitive.detected,
            "unknown_destination": (network or upload) and not valid_destination,
            "external_upload": upload and not approved,
            "restricted_file_access": self._restricted_file(action),
            "shell_command": tool in self._SHELL
            or action_type in {"shell", "execute_command", "command"},
            "secret_access_attempt": secret,
            "approved_internal_destination": approved,
            "read_only_public_research": read_only,
        }

    @staticmethod
    def _secret_access_attempt(action: ActionInput, injection) -> bool:
        action_type = action.action_type.casefold()
        if action_type in {
            "get_secret",
            "read_secret",
            "secret_access",
            "access_token",
        }:
            return True
        if AgentShieldPolicyEngine._restricted_file(action):
            return True
        return bool(
            set(injection.indicators)
            & {
                "search_local_files",
                "reveal_system_prompt",
                "exfiltrate_confidential_data",
            }
        )

    def _matches(self, action: ActionInput) -> list[PolicyDefinition]:
        result: list[PolicyDefinition] = []
        for policy in self.policies:
            try:
                matched = policy.matcher(action)
            except Exception:
                # A broken custom classifier must not turn into an allow.
                result.append(
                    PolicyDefinition(
                        "policy_evaluation_failed",
                        10_000,
                        "block",
                        lambda _: True,
                        "A policy could not classify the action safely.",
                        100.0,
                    )
                )
                continue
            if matched:
                result.append(policy)
        tool = action.tool_name.casefold()
        action_type = action.action_type.casefold()
        text = self._text(action.arguments)
        injection = self.prompt_detector.detect(text)
        sensitive = self.sensitive_detector.detect(action.arguments)
        domain = self._destination_domain(action.arguments)
        valid_destination = self._valid_destination(action.arguments)

        def add(
            name: str,
            priority: int,
            decision: Decision,
            reason: str,
            score: float,
            redactions=(),
        ):
            result.append(
                PolicyDefinition(
                    name,
                    priority,
                    decision,
                    lambda _: True,
                    reason,
                    score,
                    tuple(redactions),
                )
            )

        if self._disables_agentshield(text, action):
            add(
                "never_disable_agentshield",
                1000,
                "block",
                "Disabling AgentShield is never permitted.",
                100.0,
            )
        if injection.detected and action.source_trust_level.casefold() == "untrusted":
            if any(
                indicator in injection.indicators
                for indicator in (
                    "search_local_files",
                    "exfiltrate_confidential_data",
                    "reveal_system_prompt",
                    "disable_security",
                )
            ):
                add(
                    "untrusted_content_secret_access",
                    950,
                    "block",
                    "Untrusted content attempts secret or protected-data access.",
                    100.0,
                )
            elif sensitive.detected:
                add(
                    "untrusted_content_secret_access",
                    950,
                    "block",
                    "Untrusted content attempts secret or protected-data access.",
                    100.0,
                )
        if self._restricted_file(action):
            add(
                "restricted_files",
                900,
                "block",
                "Access to restricted files is blocked.",
                100.0,
            )
        if action_type == "read_restricted_document":
            add(
                "restricted_document",
                900,
                "block",
                "Restricted documents cannot be accessed by the action gateway.",
                100.0,
            )
        if action_type == "read_public_document":
            add(
                "public_document_read",
                100,
                "allow",
                "Public document reads are safe in simulator mode.",
                5.0,
            )
        if tool in self._SHELL or action_type in {
            "shell",
            "execute_command",
            "command",
            "run_shell_command",
        }:
            add(
                "shell_requires_approval",
                500,
                "approval_required",
                "Shell commands require approval.",
                70.0,
            )
            command = action.arguments.get("command", "")
            if (
                not isinstance(command, str)
                or len(command) > 2048
                or re.search(
                    r"(?:[;&|`$<>]|\n|\r|\b(?:curl|wget|nc|rm|sudo|chmod)\b)",
                    command,
                    re.I,
                )
            ):
                add(
                    "unsafe_simulator_command",
                    950,
                    "block",
                    "Unsafe command arguments are blocked even in simulator mode.",
                    100.0,
                )
        if tool in self._MESSAGING or action_type in {
            "email",
            "message",
            "send_message",
            "send_email",
        }:
            add(
                "messaging_requires_approval",
                500,
                "approval_required",
                "Email and messaging actions require approval.",
                65.0,
            )
        if action_type in self._NETWORK_TYPES:
            if valid_destination and domain in self.approved_domains:
                add(
                    "approved_destination_domain",
                    100,
                    "allow",
                    "Destination domain is approved.",
                    10.0,
                )
            else:
                add(
                    "unapproved_destination_domain",
                    800,
                    "block",
                    "Destination domain is not approved.",
                    90.0,
                )
        if (
            action_type in self._UPLOAD_TYPES and tool not in self._MESSAGING
        ) or "upload" in tool:
            if not valid_destination or domain is None:
                add(
                    "unknown_upload_destination",
                    850,
                    "block",
                    "External upload destination cannot be classified.",
                    95.0,
                )
            elif domain not in self.approved_domains:
                add(
                    "unapproved_destination_domain",
                    800,
                    "block",
                    "Destination domain is not approved.",
                    90.0,
                )
            elif sensitive.detected:
                add(
                    "sensitive_external_upload",
                    875,
                    "block",
                    "Sensitive data cannot be uploaded externally.",
                    100.0,
                    sensitive.locations,
                )
            else:
                add(
                    "approved_destination_domain",
                    100,
                    "allow",
                    "Destination domain is approved.",
                    15.0,
                )
        return sorted(result, key=lambda rule: (-rule.priority, rule.name))

    @staticmethod
    def _score(base: float, action: ActionInput, decision: Decision) -> float:
        del action
        return round(max(base, 100.0 if decision == "block" else base), 2)

    @staticmethod
    def _text(arguments: Mapping[str, Any]) -> str:
        return " ".join(
            str(value)
            for value in arguments.values()
            if not (isinstance(value, str) and "://" in value)
        )

    @staticmethod
    def _destination_domain(arguments: Mapping[str, Any]) -> str | None:
        for key in ("url", "destination", "endpoint", "recipient"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                parsed = urlparse(value)
                return (
                    parsed.hostname.casefold().strip(".") if parsed.hostname else None
                )
        return None

    @staticmethod
    def _valid_destination(arguments: Mapping[str, Any]) -> bool:
        for key in ("url", "destination", "endpoint", "recipient"):
            value = arguments.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            try:
                parsed = urlparse(value)
                host = parsed.hostname
                if parsed.scheme.casefold() not in {"http", "https"} or not host:
                    return False
                if (
                    parsed.username is not None
                    or parsed.password is not None
                    or any(ord(c) < 32 for c in value)
                    or "\\" in value
                ):
                    return False
                if not re.fullmatch(r"[A-Za-z0-9.-]+", host) and ":" not in host:
                    return False
                try:
                    address = ipaddress.ip_address(host)
                    if (
                        address.is_private
                        or address.is_loopback
                        or address.is_link_local
                        or address.is_reserved
                        or address.is_multicast
                        or address.is_unspecified
                    ):
                        return False
                except ValueError:
                    labels = host.rstrip(".").split(".")
                    if (
                        any(
                            not label or label.startswith("-") or label.endswith("-")
                            for label in labels
                        )
                        or host.casefold() in {"localhost", "localhost.localdomain"}
                        or host.endswith(".local")
                    ):
                        return False
                return True
            except ValueError:
                return False
        return False

    @staticmethod
    def _restricted_file(action: ActionInput) -> bool:
        if action.tool_name.casefold() not in {
            "file",
            "filesystem",
            "fs",
        } and action.action_type.casefold() not in {
            "read_file",
            "write_file",
            "file_access",
        }:
            return False
        raw_path = str(action.arguments.get("path", ""))
        if raw_path.startswith(("/", "\\")) or ".." in raw_path.replace(
            "\\", "/"
        ).split("/"):
            return True
        path = raw_path.casefold()
        return any(
            token in path
            for token in (
                "/etc/",
                "/.ssh/",
                "/.env",
                "secret",
                "credential",
                "private_key",
            )
        )

    @staticmethod
    def _disables_agentshield(text: str, action: ActionInput) -> bool:
        lowered = text.casefold()
        return "agentshield" in lowered and any(
            word in lowered for word in ("disable", "turn off", "bypass", "remove")
        )


__all__ = [
    "ActionInput",
    "AgentShieldPolicyEngine",
    "Decision",
    "PolicyAction",
    "PolicyDefinition",
    "PolicyEvaluation",
    "adapt_action",
]
