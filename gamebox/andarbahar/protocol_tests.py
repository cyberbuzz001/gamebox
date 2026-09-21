"""Protocol-level tests: state machine, message-level authorization and
transport security."""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Confidence, RequestClass, Severity
from ..safety.controller import SafetyController
from .environment import EnvironmentPolicy
from .helpers import get_balance, settle
from .results import CONFIRMED, FAIL, PASS, POTENTIAL, SecurityResult
from .ws_client import SafeWebSocketClient

log = get_logger("ab.protocol_tests")


class StateMachineTest:
    """Andar Bahar state machine and invalid-transition tests."""

    STATES = ["WAITING", "ROUND_OPEN", "BETTING", "BETTING_CLOSED",
              "JOKER_REVEALED", "DEALING", "MATCH", "RESULT", "SETTLEMENT", "CLOSED"]

    def run(self, client: SafeWebSocketClient, user_id: int) -> list[SecurityResult]:
        results = []
        # 1. Settlement for a nonexistent round (RESULT/round never existed).
        b0 = get_balance(client, user_id)
        settle(client, round_id="ghost-round-xyz", user_id=user_id, winner="andar", payout=30)
        b1 = get_balance(client, user_id)
        if b0 is not None and b1 is not None and (b1 - b0) > 0:
            results.append(SecurityResult(
                test="Invalid transition: settlement for nonexistent round",
                message="SETTLE", field="round_id",
                expected="Settlement rejected for a round that was never created/resulted.",
                observed=f"settling an unknown round credited the wallet ({b0} -> {b1}).",
                impact="The server does not enforce the round lifecycle before settlement.",
                classification=FAIL, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                cwe="CWE-841 (Improper Enforcement of Behavioral Workflow)",
                owasp="OWASP WSTG business logic",
                evidence=[f.to_dict() for f in client.frames[-3:]]))
        # 2. Duplicate settlement of the same round.
        c0 = get_balance(client, user_id)
        settle(client, round_id="dup-round", user_id=user_id, winner="andar", payout=25)
        c1 = get_balance(client, user_id)
        settle(client, round_id="dup-round", user_id=user_id, winner="andar", payout=25)
        c2 = get_balance(client, user_id)
        if c1 is not None and c2 is not None and (c2 - c1) > 0:
            results.append(SecurityResult(
                test="Invalid transition: duplicate settlement", message="SETTLE",
                field="round_id",
                expected="A round settles at most once.",
                observed=f"the same round settled twice ({c0} -> {c1} -> {c2}).",
                impact="Duplicate settlement double-credits the wallet.",
                classification=FAIL, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                cwe="CWE-841", owasp="OWASP WSTG business logic",
                evidence=[f.to_dict() for f in client.frames[-3:]]))
        return results


class AuthorizationTest:
    """Message-level authorization: sensitive actions without authentication."""

    def __init__(self, url: str, controller: SafetyController, policy: EnvironmentPolicy,
                 origin: str = ""):
        self.url = url
        self.controller = controller
        self.policy = policy
        self.origin = origin

    def run(self, user_id: int) -> SecurityResult:
        # Fresh connection that never sends AUTH.
        client = SafeWebSocketClient(self.url, self.controller, self.policy, origin=self.origin)
        try:
            client.connect()
        except Exception as exc:
            return SecurityResult(test="Message-level authorization",
                                  observed=f"connect failed: {exc}", classification=PASS)
        try:
            b0 = get_balance(client, user_id)
            resp = settle(client, round_id="noauth-1", user_id=user_id,
                          winner="andar", payout=20)
            b1 = get_balance(client, user_id)
        finally:
            ev = [f.to_dict() for f in client.frames[-3:]]
            client.close()
        if resp is not None and b0 is not None and b1 is not None and (b1 - b0) > 0:
            return SecurityResult(
                test="Message-level authorization", message="SETTLE", field="(no AUTH)",
                expected="Sensitive actions require an authenticated, authorized session.",
                observed="SETTLE succeeded and credited the wallet with no prior AUTH.",
                impact="Possession of a socket is treated as authorization; unauthenticated "
                "clients can perform sensitive actions.",
                classification=CONFIRMED, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                cwe="CWE-306 (Missing Authentication for Critical Function)",
                owasp="OWASP WSTG message-level authorization", evidence=ev)
        return SecurityResult(
            test="Message-level authorization", message="SETTLE", field="(no AUTH)",
            expected="Auth required.", observed="unauthenticated action rejected.",
            classification=PASS, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            evidence=ev)


class TransportSecurity:
    def __init__(self, url: str, controller: SafetyController, policy: EnvironmentPolicy):
        self.url = url
        self.controller = controller
        self.policy = policy

    def run(self, handshake: dict) -> list[SecurityResult]:
        results = []
        secure = self.url.startswith("wss://")
        if not secure:
            results.append(SecurityResult(
                test="Transport security (WSS/TLS)", message="handshake", field="scheme",
                expected="Production WebSockets use wss:// (TLS).",
                observed=f"connection uses {self.url.split('://')[0]}:// (no TLS).",
                impact="Traffic and tokens can be intercepted/modified in transit.",
                classification=FAIL if self.policy.is_production else POTENTIAL,
                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                cwe="CWE-319 (Cleartext Transmission)", owasp="OWASP WSTG transport"))

        # Origin validation: connect with a bogus Origin and see if it is accepted.
        bogus = "http://evil.gamebox-probe.test"
        client = SafeWebSocketClient(self.url, self.controller, self.policy, origin=bogus)
        accepted = False
        try:
            client.connect()
            accepted = True
        except Exception:
            accepted = False
        finally:
            client.close()
        if accepted:
            results.append(SecurityResult(
                test="Origin validation", message="handshake", field="Origin",
                expected="The handshake rejects untrusted Origins (allowlist).",
                observed=f"handshake accepted with Origin: {bogus}.",
                impact="Cross-site WebSocket hijacking risk; any origin can connect.",
                classification=POTENTIAL, severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
                cwe="CWE-346 (Origin Validation Error)", owasp="OWASP WSTG origin allowlist"))
        return results
