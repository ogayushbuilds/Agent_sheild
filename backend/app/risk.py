"""Typed, explainable risk scoring for policy decisions.

Scores are deterministic decision aids.  They do not replace mandatory policy
controls and they are deliberately based on facts, with each factor counted at
most once per action.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Mapping, TypedDict


class RiskFacts(TypedDict, total=False):
    """Policy facts consumed by :class:`RiskScorer`."""

    untrusted_source: bool
    prompt_injection_detected: bool
    sensitive_data_detected: bool
    unknown_destination: bool
    external_upload: bool
    restricted_file_access: bool
    shell_command: bool
    secret_access_attempt: bool
    approved_internal_destination: bool
    read_only_public_research: bool


FACTOR_WEIGHTS: dict[str, float] = {
    "untrusted_source": 25.0,
    "prompt_injection_detected": 25.0,
    "sensitive_data_detected": 25.0,
    "unknown_destination": 20.0,
    "external_upload": 20.0,
    "restricted_file_access": 25.0,
    "shell_command": 20.0,
    "secret_access_attempt": 30.0,
    "approved_internal_destination": -15.0,
    "read_only_public_research": -10.0,
}

FACTOR_REASONS: dict[str, str] = {
    "untrusted_source": "The action originated from an untrusted source.",
    "prompt_injection_detected": "Prompt-injection indicators were detected.",
    "sensitive_data_detected": "Sensitive data was detected in the action.",
    "unknown_destination": "The destination could not be classified.",
    "external_upload": "The action uploads or sends data externally.",
    "restricted_file_access": "The action accesses a restricted file.",
    "shell_command": "The action executes a shell or command operation.",
    "secret_access_attempt": "The action attempts to access secrets or protected data.",
    "approved_internal_destination": (
        "The destination is on the approved internal list."
    ),
    "read_only_public_research": (
        "The action is read-only research on an approved destination."
    ),
}


@dataclass(frozen=True)
class RiskFactor:
    """One unique factor contributing to a score."""

    name: str
    weight: float
    reason: str


@dataclass(frozen=True)
class RiskAssessment:
    """Clamped score, threshold band, and its explainable contributions."""

    score: float
    level: str
    factors: list[RiskFactor]


class RiskScorer:
    """Score policy facts with defaults that can be overridden at runtime."""

    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        configured = self._environment_weights()
        configured.update(weights or {})
        unknown = set(configured) - set(FACTOR_WEIGHTS)
        if unknown:
            raise ValueError(f"Unknown risk factor(s): {sorted(unknown)}")
        self.weights = {**FACTOR_WEIGHTS, **configured}

    def score(self, facts: Mapping[str, bool]) -> RiskAssessment:
        factors: list[RiskFactor] = []
        seen: set[str] = set()
        for name in FACTOR_WEIGHTS:
            if name in seen or not facts.get(name, False):
                continue
            seen.add(name)
            factors.append(RiskFactor(name, self.weights[name], FACTOR_REASONS[name]))
        total = round(sum(factor.weight for factor in factors), 2)
        score = round(min(100.0, max(0.0, total)), 2)
        return RiskAssessment(score, self.level_for(score), factors)

    @staticmethod
    def level_for(score: float) -> str:
        if score < 30:
            return "allow"
        if score < 60:
            return "allow_with_warning"
        if score < 80:
            return "approval_required"
        return "block"

    @staticmethod
    def _environment_weights() -> dict[str, float]:
        raw = os.getenv("AGENTSHIELD_RISK_WEIGHTS", "")
        if not raw:
            return {}
        try:
            values = json.loads(raw)
            if not isinstance(values, dict):
                return {}
            return {str(name): float(weight) for name, weight in values.items()}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}


__all__ = [
    "FACTOR_REASONS",
    "FACTOR_WEIGHTS",
    "RiskAssessment",
    "RiskFactor",
    "RiskFacts",
    "RiskScorer",
]
