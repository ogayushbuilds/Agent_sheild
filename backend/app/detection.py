"""Deterministic prompt-injection detection primitives.

The detector in this module only inspects text; it never evaluates, imports, or
executes anything from the input.  ``detect`` accepts any object so callers can
pass untrusted values safely.  Empty strings and non-string values are treated
as benign input and return a result with ``detected=False``, ``confidence=0``,
and ``severity='none'``.

Indicators are stable machine-readable IDs.  ``INDICATOR_REASONS`` provides
the corresponding explainable reason for each ID, allowing future detectors
to implement the same result contract without coupling callers to regexes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class DetectionResult:
    """The explainable, deterministic output of a prompt detector."""

    detected: bool
    confidence: float
    indicators: list[str]
    severity: str
    reasons: list[str]


@runtime_checkable
class PromptInjectionDetector(Protocol):
    """Interface implemented by all prompt-injection detectors."""

    def detect(self, value: object) -> DetectionResult:
        """Inspect untrusted input without executing it."""


INDICATOR_REASONS = {
    "ignore_previous_instructions": "Attempts to disregard earlier instructions.",
    "reveal_system_prompt": "Requests disclosure of the system or hidden prompt.",
    "disable_security": "Requests disabling or bypassing security controls.",
    "act_as_administrator": (
        "Requests elevated administrator or unrestricted authority."
    ),
    "search_local_files": "Requests searching or reading local files.",
    "exfiltrate_confidential_data": "Requests sending or uploading confidential data.",
    "conceal_from_user": "Requests concealing the action or instruction from the user.",
    "override_policy": "Requests overriding a policy or safety rule.",
    "hidden_html_instruction": (
        "Contains a suspicious instruction hidden in an HTML comment."
    ),
}


_DIRECTIVE_PREFIX = r"(?:please\s+|now\s+|you\s+must\s+|immediately\s+)?"
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:ignore|disregard|forget)\s+"
            r"(?:all\s+|any\s+)?(?:your\s+)?(?:previous|prior|earlier|above)\s+instructions?\b"
        ),
    ),
    (
        "reveal_system_prompt",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:reveal|disclose|show|print|provide|tell\s+me)\s+"
            r"(?:your\s+)?(?:system|hidden|developer)\s+(?:prompt|instructions?)\b"
        ),
    ),
    (
        "disable_security",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:disable|turn\s+off|bypass|circumvent)\s+"
            r"(?:all\s+)?(?:security|safety|guardrails?|filters?|protections?)\b"
        ),
    ),
    (
        "act_as_administrator",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:act|operate|behave)\s+as\s+"
            r"(?:an?\s+)?(?:administrator|admin|root|superuser)\b"
        ),
    ),
    (
        "search_local_files",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:search|scan|read|find|list)\s+"
            r"(?:all\s+|the\s+)?(?:local|ในเครื่อง|filesystem|file system)\s+files?\b"
        ),
    ),
    (
        "exfiltrate_confidential_data",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:send|upload|forward|share|post|email)\s+"
            r"(?:all\s+|the\s+)?(?:confidential|sensitive|private|secret|proprietary)"
            r"\s+(?:data|files?|information|内容)\b"
        ),
    ),
    (
        "conceal_from_user",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:do\s+not|don't|never)\s+"
            r"(?:tell|inform|show|disclose)\s+(?:the\s+)?user\b"
        ),
    ),
    (
        "override_policy",
        re.compile(
            rf"\b{_DIRECTIVE_PREFIX}(?:ignore|override|bypass|disregard)\s+"
            r"(?:the\s+)?(?:security\s+)?(?:policy|policies|rules|safety\s+rules?)\b"
        ),
    ),
)

_HTML_COMMENT = re.compile(r"<!--(?P<body>.*?)-->", re.IGNORECASE | re.DOTALL)
_QUESTION_OR_EXPLANATION = re.compile(
    r"^\s*(?:what|why|how|when|where|can|could|would|is|are|does|define|explain)\b"
    r"|\b(?:means?|meaning|example|examples|definition|documentation)\b",
    re.IGNORECASE,
)


def _safe_result() -> DetectionResult:
    return DetectionResult(False, 0.0, [], "none", [])


class RuleBasedPromptInjectionDetector:
    """Case-insensitive, rule-based detector with stable output ordering."""

    def detect(self, value: object) -> DetectionResult:
        if not isinstance(value, str) or not value.strip():
            return _safe_result()

        text = value.casefold()
        indicators: list[str] = []
        explanatory = bool(_QUESTION_OR_EXPLANATION.search(text))
        for indicator, pattern in _PATTERNS:
            if pattern.search(text) and not (
                explanatory and not _has_directive_context(text)
            ):
                indicators.append(indicator)

        for comment in _HTML_COMMENT.finditer(text):
            body = comment.group("body")
            if any(pattern.search(body) for _, pattern in _PATTERNS):
                indicators.append("hidden_html_instruction")
                break

        if not indicators:
            return _safe_result()

        count = len(indicators)
        confidence = min(0.99, round(0.55 + 0.1 * (count - 1), 2))
        severity = "high" if count >= 2 else "medium"
        return DetectionResult(
            True,
            confidence,
            indicators,
            severity,
            [INDICATOR_REASONS[indicator] for indicator in indicators],
        )


@dataclass(frozen=True)
class SensitiveDataResult:
    """Safe, deterministic summary of sensitive data in an input value.

    Locations are JSON-style paths for structured values and non-sensitive text
    spans for strings.  Matched values are deliberately not retained anywhere
    in this result.
    """

    detected: bool
    categories: list[str]
    locations: list[str]
    redacted_preview: str
    confidence: float


@runtime_checkable
class SensitiveDataDetector(Protocol):
    """Interface for deterministic sensitive-data detectors."""

    def detect(self, value: object) -> SensitiveDataResult:
        """Inspect a string or JSON-like value without retaining its secrets."""


_EMAIL = re.compile(
    r"\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+\b", re.I
)
_PHONE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[ .-])?(?:\(?\d{3}\)?[ .-])\d{3}[ .-]\d{4}(?!\d)"
)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----.*?-----END [A-Z0-9 ]+ PRIVATE KEY-----",
    re.I | re.S,
)
_API_VALUE = re.compile(
    r"\b(?:sk|pk|rk|ghp|github_pat|xox[baprs]-)[A-Za-z0-9_-]{12,}\b", re.I
)
_PASSWORD_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]+)", re.I
)
_PATIENT_ID = re.compile(
    r"\b(?:patient|mrn|medical)[ _-]?"
    r"(?:id|number|no)?[ :#_-]*[A-Z]{0,4}[- ]?\d{3,12}\b",
    re.I,
)
_INTERNAL_LABEL = re.compile(
    r"\b(?:internal(?:[- ]only)?|confidential|proprietary|restricted|"
    r"for internal use only)\b",
    re.I,
)
_MEDICAL = re.compile(
    r"\b(?:diagnos(?:is|ed)|treatment|medication|prescription|symptoms?|"
    r"medical record|health record|patient|clinical|hipaa|病歴)\b",
    re.I,
)
_NAME_WITH_MEDICAL = re.compile(
    r"\b(?:patient\s+)?([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2})\b"
    r"(?=[^.!?]{0,100}\b(?:diagnos(?:is|ed)|treatment|medication|patient|clinical)\b)",
)
_SECRET_KEYS = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth(?:orization)?|secret|password|passwd|pwd|private[_-]?key|client[_-]?secret|session[_-]?token)",
    re.I,
)


def _luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        number = int(digit)
        if index % 2 == 1:
            number *= 2
            number = number - 9 if number > 9 else number
        total += number
    return total % 10 == 0


def _masked(value: str, category: str) -> str:
    if category == "email":
        return "[EMAIL_REDACTED]"
    if category == "phone":
        return "[PHONE_REDACTED]"
    if category == "credit_card":
        return "[CARD_REDACTED]"
    if category == "patient_id":
        return "[PATIENT_ID_REDACTED]"
    if category == "name_with_medical_context":
        return "[NAME_REDACTED]"
    if category == "internal_document":
        return "[INTERNAL_LABEL_REDACTED]"
    if category == "medical_information":
        return "[MEDICAL_TERM_REDACTED]"
    return "[REDACTED]"


class RuleBasedSensitiveDataDetector:
    """Composable regex/key detector for strings and JSON-like payloads."""

    def detect(self, value: object) -> SensitiveDataResult:
        categories: list[str] = []
        locations: list[str] = []
        if isinstance(value, str):
            preview = self._scan_text(value, "text", categories, locations)
        elif isinstance(value, (dict, list, tuple)):
            redacted = self._scan_structure(value, "$", categories, locations, set())
            try:
                preview = json.dumps(redacted, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                preview = "[UNSERIALIZABLE_REDACTED]"
        else:
            preview = "" if value is None else "[UNSUPPORTED_VALUE]"
        categories = list(dict.fromkeys(categories))
        return SensitiveDataResult(
            bool(categories),
            categories,
            locations,
            preview,
            self._confidence(categories),
        )

    def _scan_structure(
        self,
        value: object,
        path: str,
        categories: list[str],
        locations: list[str],
        seen: set[int],
    ) -> object:
        if isinstance(value, dict):
            if id(value) in seen:
                return "[CYCLE_REDACTED]"
            seen.add(id(value))
            result: dict[str, object] = {}
            for key, item in value.items():
                key_text = str(key)
                child = (
                    f"{path}.{key_text}"
                    if re.fullmatch(r"[A-Za-z_][\w-]*", key_text)
                    else f"{path}[{key_text!r}]"
                )
                if _SECRET_KEYS.search(key_text):
                    self._add(
                        categories,
                        locations,
                        "password"
                        if re.search(r"pass(word|wd)?|pwd", key_text, re.I)
                        else "api_key",
                        child,
                    )
                    result[key_text] = "[REDACTED]"
                else:
                    result[key_text] = self._scan_structure(
                        item, child, categories, locations, seen
                    )
            seen.remove(id(value))
            return result
        if isinstance(value, (list, tuple)):
            return [
                self._scan_structure(
                    item, f"{path}[{index}]", categories, locations, seen
                )
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            return self._scan_text(value, path, categories, locations)
        return value

    def _scan_text(
        self, text: str, path: str, categories: list[str], locations: list[str]
    ) -> str:
        replacements: list[tuple[int, int, str]] = []
        for category, pattern in (
            ("private_key", _PEM),
            ("email", _EMAIL),
            ("phone", _PHONE),
            ("api_key", _API_VALUE),
            ("password", _PASSWORD_ASSIGNMENT),
        ):
            for match in pattern.finditer(text):
                raw = match.group(0)
                if category == "phone" and len(re.sub(r"\D", "", raw)) < 7:
                    continue
                start, end = match.span()
                if category == "password":
                    start = match.start(1)
                replacements.append((start, end, _masked(raw, category)))
                self._add(categories, locations, category, f"{path}[{start}:{end}]")
        for match in _CARD.finditer(text):
            if _luhn(match.group(0)):
                replacements.append(
                    (*match.span(), _masked(match.group(0), "credit_card"))
                )
                self._add(
                    categories,
                    locations,
                    "credit_card",
                    f"{path}[{match.start()}:{match.end()}]",
                )
        if _PATIENT_ID.search(text):
            self._add(categories, locations, "patient_id", path)
        if _INTERNAL_LABEL.search(text):
            self._add(categories, locations, "internal_document", path)
        if _MEDICAL.search(text):
            self._add(categories, locations, "medical_information", path)
        if _NAME_WITH_MEDICAL.search(text):
            self._add(categories, locations, "name_with_medical_context", path)
        for category, pattern in (
            ("patient_id", _PATIENT_ID),
            ("name_with_medical_context", _NAME_WITH_MEDICAL),
            ("internal_document", _INTERNAL_LABEL),
            ("medical_information", _MEDICAL),
        ):
            for match in pattern.finditer(text):
                replacements.append((*match.span(), _masked(match.group(0), category)))
        selected: list[tuple[int, int, str]] = []
        for start, end, replacement in sorted(
            replacements, key=lambda item: (item[0], -(item[1] - item[0]))
        ):
            if any(
                start < other_end and end > other_start
                for other_start, other_end, _ in selected
            ):
                continue
            selected.append((start, end, replacement))
        for start, end, replacement in sorted(
            selected, key=lambda item: item[0], reverse=True
        ):
            text = text[:start] + replacement + text[end:]
        return text

    @staticmethod
    def _add(
        categories: list[str], locations: list[str], category: str, location: str
    ) -> None:
        if category not in categories:
            categories.append(category)
        if location not in locations:
            locations.append(location)

    @staticmethod
    def _confidence(categories: list[str]) -> float:
        if not categories:
            return 0.0
        high = {"private_key", "credit_card", "api_key", "password"}
        base = 0.97 if high.intersection(categories) else 0.82
        return min(0.99, round(base + 0.02 * max(0, len(categories) - 1), 2))


def _has_directive_context(text: str) -> bool:
    """Keep conceptual questions/articles benign unless they contain a directive."""

    return bool(
        re.search(
            r"(?:^|[.!]\s+)(?:please\s+|you\s+must\s+|immediately\s+|now\s+)?"
            r"(?:ignore|disregard|disable|reveal|show|send|upload|override|search|scan|act)\b",
            text,
            re.IGNORECASE,
        )
    )


__all__ = [
    "DetectionResult",
    "INDICATOR_REASONS",
    "PromptInjectionDetector",
    "RuleBasedPromptInjectionDetector",
    "SensitiveDataDetector",
    "SensitiveDataResult",
    "RuleBasedSensitiveDataDetector",
]
