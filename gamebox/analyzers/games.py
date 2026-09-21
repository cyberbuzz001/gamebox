"""Game integrity / client-trust analyzer.

Determines whether the client can influence values that must be server
authoritative (payout, win amount, result). It does this by sending a bounded,
controlled TEST_COINS bet that also includes a client-supplied payout field and
observing whether the server trusts it. The injected value is deliberately small
and bounded so the probe stays a SAFE-scoped sandbox test.
"""
from __future__ import annotations

from typing import Optional

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .common import AccountSession

log = get_logger("games")

# Bounded, obviously-synthetic marker value for the injected payout probe.
_PROBE_PAYOUT = 4242


class GameIntegrityAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 bet_path: str = "/api/game/teenpatti/bet",
                 balance_path: str = "/api/wallet/me"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.bet_path = bet_path
        self.balance_path = balance_path

    def _balance(self, sess: AccountSession) -> Optional[float]:
        try:
            resp, _ = self.client.get(self.base + self.balance_path, headers=sess.headers())
        except Exception:
            return None
        body = resp.json() or {}
        val = body.get("balance", body.get("coins"))
        return float(val) if val is not None else None

    def run(self, sess: AccountSession) -> list[Finding]:
        return self._check_client_controlled_payout(sess)

    def _check_client_controlled_payout(self, sess: AccountSession) -> list[Finding]:
        b0 = self._balance(sess)
        if b0 is None:
            return []
        url = self.base + self.bet_path
        # A minimal bet that also smuggles a client-supplied payout/win_amount.
        payload = {
            "bet_amount": 1,
            "payout": _PROBE_PAYOUT,
            "win_amount": _PROBE_PAYOUT,
            "result": "win",
        }
        try:
            resp, ev = self.client.post(url, headers=sess.headers(), json_body=payload)
        except BlockedRequest as b:
            log.info("game payout test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception as exc:
            log.debug("game test error: %s", exc)
            return []
        b1 = self._balance(sess)
        if b1 is None:
            return []
        gained = b1 - b0
        body = resp.json() or {}

        # The server trusted the client payout if the net gain matches the
        # injected value (minus the 1-coin stake), or the response echoes it.
        trusted = (
            abs(gained - (_PROBE_PAYOUT - 1)) < 0.5
            or body.get("payout") == _PROBE_PAYOUT
            or body.get("win_amount") == _PROBE_PAYOUT
        )
        if trusted and resp.status_code < 400:
            if ev:
                ev.test_account = sess.label
                ev.state_before = f"balance={b0}"
                ev.state_after = f"balance={b1}"
            return [Finding(
                title="Game payout is client-controlled (server trusts client-supplied win amount)",
                category=Category.GAME, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The bet/settlement endpoint accepts a client-supplied payout/win_amount "
                    "and credits it to the wallet instead of computing the result server-side. "
                    "A crafted request set the payout to a chosen value and the balance changed "
                    "to match it (TEST_COINS)."
                ),
                endpoint=f"POST {self.bet_path}", parameter="payout/win_amount",
                impact=(
                    f"Injected payout={_PROBE_PAYOUT}; balance moved {b0} -> {b1}. The client "
                    "can name its own winnings, fully breaking game-money integrity."
                ),
                reproduction=(
                    f"POST {self.bet_path} with bet_amount=1 and payout={_PROBE_PAYOUT}; "
                    "the credited amount matches the client-supplied payout."
                ),
                remediation=(
                    "Never accept payout/result/multiplier from the client. Compute the outcome "
                    "and payout server-side from a server-generated seed; ignore any client "
                    "monetary fields; validate bet_amount against balance server-side."
                ),
                cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                owasp="API6:2023 / Business Logic; game integrity",
                module="games", evidence=[ev] if ev else [],
            )]
        return []
