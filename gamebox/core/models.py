"""Core data models shared across the framework."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class RequestClass(str, Enum):
    """Risk classification for an outbound request. Drives the safety gate."""

    READ_ONLY = "READ_ONLY"
    SAFE_TEST = "SAFE_TEST"
    STATE_CHANGING = "STATE_CHANGING"
    FINANCIAL = "FINANCIAL"
    DESTRUCTIVE = "DESTRUCTIVE"


class Category(str, Enum):
    """Functional category of a discovered endpoint (application map)."""

    AUTH = "AUTH"
    USER = "USER"
    PROFILE = "PROFILE"
    WALLET = "WALLET"
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"
    BETTING = "BETTING"
    GAME = "GAME"
    BONUS = "BONUS"
    REFERRAL = "REFERRAL"
    PAYMENT = "PAYMENT"
    ADMIN = "ADMIN"
    SUPPORT = "SUPPORT"
    NOTIFICATION = "NOTIFICATION"
    REPORTING = "REPORTING"
    OTHER = "OTHER"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    SUSPECTED = "SUSPECTED"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_rank(sev: Severity) -> int:
    return _SEVERITY_ORDER[sev]


def _now() -> float:
    return time.time()


def _short_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Endpoint:
    """A discovered endpoint on the target application map."""

    method: str
    url: str
    parameters: list[str] = field(default_factory=list)
    authentication_required: Optional[bool] = None
    content_type: str = ""
    response_type: str = ""
    state_changing: bool = False
    category: Category = Category.OTHER
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    notes: str = ""

    def key(self) -> str:
        return f"{self.method.upper()} {self.url}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class Evidence:
    """Captured, redacted proof for a finding or test step."""

    endpoint: str
    method: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_excerpt: str = ""
    state_before: str = ""
    state_after: str = ""
    test_account: str = ""
    timestamp: float = field(default_factory=_now)
    id: str = field(default_factory=_short_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A standardized security finding."""

    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    description: str
    endpoint: str = ""
    parameter: str = ""
    impact: str = ""
    reproduction: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    module: str = ""
    timestamp: float = field(default_factory=_now)
    id: str = field(default_factory=_short_id)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d
