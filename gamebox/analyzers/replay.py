"""Generic replay / idempotency testing framework.

Given a state-changing operation and a way to read the affected numeric state,
it submits the operation twice and reports whether the repeat was processed
(duplicate processing = missing idempotency).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .common import AccountSession

log = get_logger("replay")


@dataclass
class ReplayResult:
    operation: str
    first_status: int
    repeat_status: int
    state_before: float
    state_after_first: float
    state_after_repeat: float

    @property
    def duplicate_processed(self) -> bool:
        return (self.state_after_repeat - self.state_after_first) > 0 and \
            self.repeat_status < 400

    def report(self) -> str:
        return (f"REPLAY TEST\nOperation: {self.operation}\n"
                f"First request: {self.first_status}\n"
                f"Repeated request: {self.repeat_status}\n"
                f"State: {self.state_before} -> {self.state_after_first} -> "
                f"{self.state_after_repeat}\n"
                f"Potential issue: "
                f"{'Duplicate processing' if self.duplicate_processed else 'None observed'}")


class ReplayTester:
    def __init__(self, client: SafeHTTPClient, read_state: Callable[[], Optional[float]]):
        self.client = client
        self.read_state = read_state

    def test(self, name: str, method: str, url: str, *, headers=None,
             json_body=None) -> Optional[ReplayResult]:
        s0 = self.read_state()
        if s0 is None:
            return None
        try:
            r1, _ = self.client.request(method, url, headers=headers, json_body=json_body)
            s1 = self.read_state()
            r2, _ = self.client.request(method, url, headers=headers, json_body=json_body)
            s2 = self.read_state()
        except BlockedRequest as b:
            log.info("replay test '%s' skipped (blocked): %s", name, b.decision.reason)
            return None
        except Exception as exc:
            log.debug("replay test error: %s", exc)
            return None
        if s1 is None or s2 is None:
            return None
        return ReplayResult(name, r1.status_code, r2.status_code, s0, s1, s2)

    def as_finding(self, result: ReplayResult, endpoint: str,
                   session: AccountSession | None = None) -> list[Finding]:
        if not result.duplicate_processed:
            return []
        return [Finding(
            title=f"Replayable operation ({result.operation}) is not idempotent",
            category=Category.WALLET, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            description="Submitting the same operation twice was processed both times, "
            "changing state each time.",
            endpoint=endpoint,
            impact="Sensitive operations can be replayed for duplicate effect.",
            reproduction=result.report(),
            remediation="Require a server-generated idempotency key; enforce uniqueness and "
            "process inside a transaction.",
            cwe="CWE-837 (Improper Enforcement of a Single, Unique Action)",
            owasp="API6:2023 Business Logic", module="replay",
            evidence=[])]
