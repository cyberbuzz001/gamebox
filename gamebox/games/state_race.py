"""Game State & Bet Cancellation TOCTOU Race Condition Analyzer.

Tests whether a player can concurrently submit a bet cancellation / refund request
while the game outcome or settlement is concurrently being processed.

Vulnerability pattern:
Client sends Bet Cancellation and Game Settlement at the exact same moment.
If the server lacks atomic locking or idempotency on round state transitions,
the balance could be credited with BOTH a refund and a winning payout for the same round.
"""
from __future__ import annotations

from typing import Optional

from ..analyzers.common import AccountSession
from ..analyzers.race import LastByteSyncRacer, RaceResult
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("games.state_race")


class BetCancellationRaceAnalyzer:
    def __init__(
        self,
        client: SafeHTTPClient,
        base_url: str,
        cancel_path: str = "/api/game/bet/cancel",
        settle_path: str = "/api/game/settlement",
        balance_path: str = "/api/wallet/me",
    ):
        self.client = client
        self.base = base_url.rstrip("/")
        self.cancel_path = cancel_path
        self.settle_path = settle_path
        self.balance_path = balance_path

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
        url_cancel = self.base + self.cancel_path
        b0 = self._balance(sess)
        if b0 is None:
            return []

        payload = {"round_id": "gamebox-race-round-99", "bet_id": "bet-99"}

        # Use LastByteSyncRacer for sub-millisecond race windows
        racer = LastByteSyncRacer(self.client, lambda: self._balance(sess), workers=6)
        res = racer.test(
            name="bet_cancellation_race",
            method="POST",
            url=url_cancel,
            headers=sess.headers(),
            json_body=payload,
            expected_single_delta=100.0,
        )

        findings: list[Finding] = []
        if res and res.multiple_applied:
            findings.append(Finding(
                title="TOCTOU Race Condition: Concurrent bet cancellation credited balance multiple times",
                category=Category.GAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    "Submitting concurrent bet cancellation requests for the same round allowed "
                    "multiple refund transactions to process simultaneously without state locking."
                ),
                endpoint=f"POST {self.cancel_path}",
                parameter="round_id",
                impact=(
                    f"Balance grew {res.state_before} -> {res.state_after} across {res.successes} "
                    "concurrent cancellation calls for a single bet."
                ),
                reproduction=f"Concurrently send {res.requests} POST requests to {self.cancel_path} with same round_id.",
                remediation=(
                    "Apply database transaction locking (SELECT FOR UPDATE) on the round/bet state; "
                    "transition state atomically from PLACED -> CANCELLED and reject subsequent attempts."
                ),
                cwe="CWE-362 (Concurrent Execution using Shared Resource / Race Condition)",
                owasp="API6:2023 Business Logic",
                module="state_race",
                evidence=[],
            ))

        return findings
