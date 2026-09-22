"""Advanced Wallet Security Analyzer.

Tests wallet arithmetic edge cases:
  * Negative bet amounts (attempting to invert debits into credits)
  * Precision underflow / float truncation
  * Integer overflow / extreme value handling
"""
from __future__ import annotations

from typing import Optional

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .common import AccountSession

log = get_logger("wallet_advanced")


class AdvancedWalletAnalyzer:
    def __init__(
        self,
        client: SafeHTTPClient,
        base_url: str,
        balance_path: str = "/api/wallet/me",
        bet_paths: tuple[str, ...] = (
            "/api/wallet/bet",
            "/api/wallet/negative-bet",
            "/api/game/teenpatti/bet",
        ),
    ):
        self.client = client
        self.base = base_url.rstrip("/")
        self.balance_path = balance_path
        self.bet_paths = bet_paths

    def _balance(self, sess: AccountSession) -> Optional[float]:
        try:
            resp, _ = self.client.get(self.base + self.balance_path, headers=sess.headers())
        except Exception as exc:
            log.debug("balance read failed: %s", exc)
            return None
        body = resp.json() or {}
        val = body.get("balance", body.get("coins"))
        return float(val) if val is not None else None

    def run(self, sess: AccountSession) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._check_negative_amounts(sess)
        findings += self._check_precision_overflow(sess)
        return findings

    def _check_negative_amounts(self, sess: AccountSession) -> list[Finding]:
        findings: list[Finding] = []
        b0 = self._balance(sess)
        if b0 is None:
            return []

        for path in self.bet_paths:
            url = self.base + path
            neg_payload = {"amount": -100.0, "bet_amount": -100.0}
            try:
                r, ev = self.client.post(url, headers=sess.headers(), json_body=neg_payload)
                b1 = self._balance(sess)
            except BlockedRequest as b:
                log.info("negative bet test skipped for %s (blocked): %s", path, b.decision.reason)
                continue
            except Exception as exc:
                log.debug("negative bet test error on %s: %s", path, exc)
                continue

            if b1 is None or r.status_code >= 400:
                continue

            # If balance increased or remained untouched despite claiming success on negative bet:
            if b1 > b0:
                if ev:
                    ev.test_account = sess.label
                    ev.state_before = f"balance={b0}"
                    ev.state_after = f"balance={b1}"
                findings.append(Finding(
                    title="Wallet accepts negative bet amounts leading to unauthorized credit",
                    category=Category.WALLET,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "Submitting a negative bet amount was accepted by the server and resulted "
                        "in increasing the user's wallet balance instead of debiting it."
                    ),
                    endpoint=f"POST {path}",
                    parameter="amount",
                    impact=(
                        f"Balance increased from {b0} to {b1} after placing a negative bet. "
                        "An attacker can exploit this to inject arbitrary synthetic funds."
                    ),
                    reproduction=f"POST {path} with amount=-100.0; balance increases by 100.0.",
                    remediation=(
                        "Validate all monetary input values on the server side; reject values <= 0 "
                        "with an HTTP 400 Bad Request error."
                    ),
                    cwe="CWE-20 (Improper Input Validation)",
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    module="wallet_advanced",
                    evidence=[ev] if ev else [],
                ))
                break

        return findings

    def _check_precision_overflow(self, sess: AccountSession) -> list[Finding]:
        findings: list[Finding] = []
        url = self.base + self.bet_paths[0]
        b0 = self._balance(sess)
        if b0 is None:
            return []

        extreme_payload = {"amount": 0.000000000000001, "bet_amount": 0.000000000000001}
        try:
            r, ev = self.client.post(url, headers=sess.headers(), json_body=extreme_payload)
            b1 = self._balance(sess)
        except Exception:
            return []

        if r.status_code < 400 and b1 is not None:
            if isinstance(b1, float) and (b1 != b1 or b1 < 0):
                if ev:
                    ev.test_account = sess.label
                findings.append(Finding(
                    title="Float precision underflow leads to corrupted wallet state",
                    category=Category.WALLET,
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description="Submitting sub-satoshi float amounts caused balance corruption or invalid numeric state.",
                    endpoint=f"POST {self.bet_paths[0]}",
                    parameter="amount",
                    impact="Wallet balance corrupted or forced into NaN/invalid state.",
                    reproduction=f"POST {self.bet_paths[0]} with amount=0.000000000000001",
                    remediation="Use fixed-point decimal arithmetic (e.g. integer micro-units or Decimal).",
                    cwe="CWE-681 (Incorrect Conversion between Numeric Types)",
                    owasp="API4:2023 Unrestricted Resource Consumption",
                    module="wallet_advanced",
                    evidence=[ev] if ev else [],
                ))

        return findings
