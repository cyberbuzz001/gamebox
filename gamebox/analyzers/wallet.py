"""Wallet security analyzer.

Builds a virtual ledger for a test account and checks for integrity failures:
  * replayable credits / missing idempotency (bonus claimed twice)
  * duplicate settlement (same round settled twice)

All operations use synthetic TEST_COINS against an authorized sandbox account.
The analyzer never performs real financial operations; deposit/withdrawal/
payment endpoints are classified FINANCIAL and remain blocked by default.
"""
from __future__ import annotations

from typing import Optional

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .common import AccountSession

log = get_logger("wallet")


class Ledger:
    """A minimal expected-balance model: opening + credits - debits."""

    def __init__(self, opening: float):
        self.opening = opening
        self.credits = 0.0
        self.debits = 0.0

    def credit(self, amount: float) -> None:
        self.credits += amount

    def debit(self, amount: float) -> None:
        self.debits += amount

    @property
    def expected(self) -> float:
        return self.opening + self.credits - self.debits


class WalletAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 balance_path: str = "/api/wallet/me",
                 bonus_path: str = "/api/bonus/claim",
                 settlement_path: str = "/api/game/settlement"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.balance_path = balance_path
        self.bonus_path = bonus_path
        self.settlement_path = settlement_path

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
        findings += self._check_replayable_bonus(sess)
        findings += self._check_duplicate_settlement(sess)
        return findings

    def _check_replayable_bonus(self, sess: AccountSession) -> list[Finding]:
        b0 = self._balance(sess)
        if b0 is None:
            return []
        ledger = Ledger(b0)
        url = self.base + self.bonus_path
        try:
            # Read the balance BETWEEN the two claims so each delta is isolated:
            # b0 -> claim -> b1 -> (identical) claim -> b2.
            r1, ev1 = self.client.post(url, headers=sess.headers(), json_body={})
            b1 = self._balance(sess)
            r2, ev2 = self.client.post(url, headers=sess.headers(), json_body={})
            b2 = self._balance(sess)
        except BlockedRequest as b:
            log.info("bonus replay test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception as exc:
            log.debug("bonus test error: %s", exc)
            return []

        if b1 is None or b2 is None:
            return []
        gained_first = b1 - b0
        if gained_first > 0:
            ledger.credit(gained_first)  # one legitimate claim
        gained_second = b2 - b1

        if gained_second > 0 and r2.status_code < 400:
            if ev1:
                ev1.test_account = sess.label
                ev1.state_before = f"balance={b0}"
                ev1.state_after = f"balance={b1}"
            if ev2:
                ev2.test_account = sess.label
                ev2.state_before = f"balance={b1}"
                ev2.state_after = f"balance={b2}"
            return [Finding(
                title="Replayable bonus claim leads to duplicate TEST_COINS credit",
                category=Category.BONUS, severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The bonus claim endpoint credits the wallet on every call with no "
                    "idempotency key, nonce, or server-side already-claimed check. Two "
                    "identical requests both succeeded and each increased the balance."
                ),
                endpoint=f"POST {self.bonus_path}",
                impact=(
                    f"Expected balance after one legitimate claim: {ledger.expected}. "
                    f"Observed after a duplicate claim: {b2}. An attacker could repeat the "
                    "call to inflate the balance without limit (demonstrated on TEST_COINS)."
                ),
                reproduction=(
                    f"1. GET {self.balance_path} -> {b0}\n"
                    f"2. POST {self.bonus_path} -> {b1}\n"
                    f"3. POST {self.bonus_path} (identical) -> {b2}"
                ),
                remediation=(
                    "Require a server-generated idempotency key per claim; enforce a unique "
                    "constraint on (user, bonus_id, period); make the claim atomic within a "
                    "database transaction and reject repeat claims."
                ),
                cwe="CWE-837 (Improper Enforcement of a Single, Unique Action)",
                owasp="API4:2023 Unrestricted Resource Consumption / Business Logic",
                module="wallet", evidence=[e for e in (ev1, ev2) if e],
            )]
        return []

    def _check_duplicate_settlement(self, sess: AccountSession) -> list[Finding]:
        b0 = self._balance(sess)
        if b0 is None:
            return []
        url = self.base + self.settlement_path
        payload = {"round_id": "gamebox-safe-probe-round-1", "result": "win"}
        try:
            r1, ev1 = self.client.post(url, headers=sess.headers(), json_body=payload)
            b1 = self._balance(sess)
            r2, ev2 = self.client.post(url, headers=sess.headers(), json_body=payload)
            b2 = self._balance(sess)
        except BlockedRequest as b:
            log.info("settlement test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception as exc:
            log.debug("settlement test error: %s", exc)
            return []
        if b1 is None or b2 is None:
            return []
        if (b1 - b0) > 0 and (b2 - b1) > 0 and r2.status_code < 400:
            for e in (ev1, ev2):
                if e:
                    e.test_account = sess.label
            return [Finding(
                title="Duplicate settlement credits the same game round more than once",
                category=Category.GAME, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    "Submitting the settlement request twice for the same round_id credited "
                    "the wallet each time. The settlement endpoint is not idempotent on "
                    "round_id and has no state machine preventing re-settlement."
                ),
                endpoint=f"POST {self.settlement_path}", parameter="round_id",
                impact=(
                    f"Balance grew {b0} -> {b1} -> {b2} by re-sending one round settlement "
                    "(TEST_COINS). On a live system this is direct monetary integrity loss."
                ),
                reproduction=(
                    f"POST {self.settlement_path} with the same round_id twice; both credited."
                ),
                remediation=(
                    "Model round state as SETTLED/UNSETTLED; enforce a unique constraint on "
                    "round_id; settle inside a transaction; reject settlement of an already "
                    "settled round."
                ),
                cwe="CWE-841 (Improper Enforcement of Behavioral Workflow)",
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                module="wallet", evidence=[e for e in (ev1, ev2) if e],
            )]
        return []
