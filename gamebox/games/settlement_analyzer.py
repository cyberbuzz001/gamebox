"""Modules 3/4/5 - outcome authority, bet integrity and settlement security
for HTTP games.

Determines whether the server recalculates settlement values or trusts
client-supplied payout/result. Uses synthetic TEST_COINS on an authorized
sandbox account only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("games.settlement")

SERVER_AUTHORITATIVE = "SERVER_AUTHORITATIVE"
CLIENT_INPUT = "CLIENT_INPUT"
DERIVED = "DERIVED"
UNKNOWN = "UNKNOWN"

_PROBE_PAYOUT = 1234


@dataclass
class SettlementResult:
    result_authority: str = UNKNOWN
    settlement_authority: str = UNKNOWN
    bet_integrity: dict = field(default_factory=dict)
    duplicate_settlement: bool = False
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class SettlementAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 bet_path: str, settlement_path: str, wallet_path: str):
        self.client = client
        self.base = base_url.rstrip("/")
        self.bet_path = bet_path
        self.settlement_path = settlement_path
        self.wallet_path = wallet_path

    def _balance(self, sess: AccountSession) -> Optional[float]:
        try:
            resp, _ = self.client.get(self.base + self.wallet_path, headers=sess.headers())
        except Exception:
            return None
        body = resp.json() or {}
        v = body.get("balance", body.get("coins"))
        return float(v) if v is not None else None

    def run(self, sess: AccountSession) -> SettlementResult:
        res = SettlementResult()
        self._bet_integrity(sess, res)
        self._duplicate_settlement(sess, res)
        return res

    def _bet_integrity(self, sess: AccountSession, res: SettlementResult) -> None:
        if not self.bet_path:
            return
        b0 = self._balance(sess)
        if b0 is None:
            return
        bet_amount = 1
        try:
            resp, ev = self.client.post(
                self.base + self.bet_path, headers=sess.headers(),
                json_body={"bet_amount": bet_amount, "payout": _PROBE_PAYOUT,
                           "result": "win"})
        except BlockedRequest as b:
            log.info("bet integrity skipped (blocked): %s", b.decision.reason)
            return
        except Exception:
            return
        b1 = self._balance(sess)
        if b1 is None:
            return
        actual_payout = (b1 - b0) + bet_amount
        client_trusted = abs(actual_payout - _PROBE_PAYOUT) < 0.5
        res.bet_integrity = {
            "balance_before": b0, "bet_amount": bet_amount,
            "client_supplied_payout": _PROBE_PAYOUT,
            "server_calculated_payout": "unknown (server did not recompute)"
            if client_trusted else actual_payout,
            "actual_payout": actual_payout, "balance_after": b1,
            "expected_if_server_authoritative": f"{b0} - {bet_amount} + server_payout",
        }
        if client_trusted:
            res.result_authority = CLIENT_INPUT
            res.settlement_authority = CLIENT_INPUT
            if ev:
                ev.test_account = sess.label
            res.findings.append(Finding(
                title="Client-controlled payout accepted (settlement not recalculated)",
                category=Category.GAME, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description="The bet/settlement endpoint credited the client-supplied payout "
                "instead of recomputing it server-side.",
                endpoint=f"POST {self.bet_path}", parameter="payout",
                impact=f"A client set payout={_PROBE_PAYOUT}; balance moved {b0} -> {b1}. The "
                "client is authoritative over winnings (demonstrated on TEST_COINS).",
                reproduction=f"POST {self.bet_path} with bet_amount={bet_amount} and "
                f"payout={_PROBE_PAYOUT}; the credited amount matches the client value.",
                remediation="Compute result and payout server-side from a server seed; ignore "
                "client payout/result/multiplier fields.",
                cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                owasp="API6:2023 / game integrity", module="win_integrity",
                evidence=[ev] if ev else []))
        else:
            res.result_authority = SERVER_AUTHORITATIVE
            res.settlement_authority = SERVER_AUTHORITATIVE

    def _duplicate_settlement(self, sess: AccountSession, res: SettlementResult) -> None:
        if not self.settlement_path:
            return
        b0 = self._balance(sess)
        if b0 is None:
            return
        payload = {"round_id": "win-integrity-probe-1", "result": "win"}
        try:
            self.client.post(self.base + self.settlement_path, headers=sess.headers(),
                             json_body=payload)
            b1 = self._balance(sess)
            r2, ev = self.client.post(self.base + self.settlement_path, headers=sess.headers(),
                                      json_body=payload)
            b2 = self._balance(sess)
        except BlockedRequest as b:
            log.info("duplicate settlement skipped (blocked): %s", b.decision.reason)
            return
        except Exception:
            return
        if b1 is None or b2 is None:
            return
        if (b1 - b0) > 0 and (b2 - b1) > 0:
            res.duplicate_settlement = True
            res.settlement_authority = CLIENT_INPUT
            if ev:
                ev.test_account = sess.label
            res.findings.append(Finding(
                title="Duplicate settlement credits the same round twice",
                category=Category.GAME, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description="Re-sending the settlement for the same round_id credited the "
                "wallet again (no idempotency / no round state machine).",
                endpoint=f"POST {self.settlement_path}", parameter="round_id",
                impact=f"Balance grew {b0} -> {b1} -> {b2} by re-sending one settlement.",
                reproduction=f"POST {self.settlement_path} with the same round_id twice.",
                remediation="Enforce a unique constraint on round_id; settle inside a "
                "transaction; reject already-settled rounds.",
                cwe="CWE-841 (Improper Enforcement of Behavioral Workflow)",
                owasp="API6:2023", module="win_integrity", evidence=[ev] if ev else []))
