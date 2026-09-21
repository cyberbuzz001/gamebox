"""Structured security-test result for the Andar Bahar WebSocket tester."""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

from ..core.models import Category, Confidence, Finding, Severity

PASS = "PASS"
FAIL = "FAIL"
POTENTIAL = "POTENTIAL_VULNERABILITY"
CONFIRMED = "CONFIRMED_VULNERABILITY"


@dataclass
class SecurityResult:
    test: str
    message: str = ""
    field: str = ""
    expected: str = ""
    observed: str = ""
    impact: str = ""
    classification: str = PASS
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.SUSPECTED
    cwe: str = ""
    owasp: str = ""
    evidence: list = dc_field(default_factory=list)  # list of sanitized frame dicts

    @property
    def is_vuln(self) -> bool:
        return self.classification in (FAIL, POTENTIAL, CONFIRMED)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    def to_finding(self, finding_id: str = "") -> Finding | None:
        if not self.is_vuln:
            return None
        from ..core.models import Evidence
        ev = []
        for e in self.evidence[:4]:
            ev.append(Evidence(endpoint=e.get("message_type", "ws"),
                               method="WS", response_excerpt=str(e.get("payload", ""))[:400]))
        title = self.test if not self.message else f"{self.test} ({self.message})"
        f = Finding(
            title=title, category=Category.GAME, severity=self.severity,
            confidence=self.confidence,
            description=f"Expected: {self.expected}\nObserved: {self.observed}",
            endpoint=f"WS {self.message}", parameter=self.field,
            impact=self.impact,
            reproduction=f"Andar Bahar WS test '{self.test}' on field '{self.field}'.",
            remediation="", cwe=self.cwe, owasp=self.owasp,
            module="andar_bahar_ws", evidence=ev)
        if finding_id:
            f.id = finding_id
        return f
