"""Integrity tests: replay protection, round/session binding and wallet
settlement integrity."""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Confidence, Severity
from .helpers import get_balance, place_bet, settle
from .results import CONFIRMED, FAIL, PASS, SecurityResult
from .ws_client import SafeWebSocketClient

log = get_logger("ab.integrity")


class ReplayTester:
    def run(self, client: SafeWebSocketClient, user_id: int) -> SecurityResult:
        place_bet(client, user_id, round_id="replay-1", side="andar", amount=5)
        b0 = get_balance(client, user_id)
        settle(client, round_id="replay-1", user_id=user_id, winner="andar", payout=50)
        b1 = get_balance(client, user_id)
        # Replay the identical settlement.
        settle(client, round_id="replay-1", user_id=user_id, winner="andar", payout=50)
        b2 = get_balance(client, user_id)
        ev = [f.to_dict() for f in client.frames[-4:]]
        if b0 is not None and b1 is not None and b2 is not None and (b2 - b1) > 0:
            return SecurityResult(
                test="Replay protection", message="SETTLE", field="(message identity)",
                expected="A previously accepted settlement cannot be processed again "
                "(nonce/idempotency key/message id).",
                observed=f"replaying the same SETTLE credited again ({b1} -> {b2}); no "
                "idempotency observed.",
                impact="Captured settlement frames can be replayed to inflate balances.",
                classification=FAIL, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                cwe="CWE-294 (Authentication Bypass by Capture-replay)",
                owasp="OWASP WSTG WebSocket replay protection", evidence=ev)
        return SecurityResult(
            test="Replay protection", message="SETTLE", field="(message identity)",
            expected="Replay rejected.", observed="replay was not credited.",
            classification=PASS, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            evidence=ev)


class RoundBindingTest:
    def run(self, client: SafeWebSocketClient, attacker_user: int,
            victim_user: int) -> SecurityResult:
        vb0 = get_balance(client, victim_user)
        # Attacker (authenticated as attacker_user) settles for the victim's id.
        settle(client, round_id="binding-1", user_id=victim_user, winner="andar", payout=40)
        vb1 = get_balance(client, victim_user)
        ev = [f.to_dict() for f in client.frames[-3:]]
        if vb0 is not None and vb1 is not None and (vb1 - vb0) > 0:
            return SecurityResult(
                test="Round/session binding", message="SETTLE", field="user_id",
                expected="Settlement is bound to the authenticated connection; a user cannot "
                "settle another user's round.",
                observed=f"user {attacker_user} settled for user {victim_user}; victim balance "
                f"{vb0} -> {vb1}.",
                impact="Actions are not bound to the session; one account can affect another.",
                classification=CONFIRMED, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                cwe="CWE-639 (Authorization Bypass Through User-Controlled Key)",
                owasp="OWASP WSTG message-level authorization", evidence=ev)
        return SecurityResult(
            test="Round/session binding", message="SETTLE", field="user_id",
            expected="Bound to session.", observed="cross-user settlement rejected.",
            classification=PASS, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            evidence=ev)


class WalletIntegrity:
    def run(self, client: SafeWebSocketClient, user_id: int) -> tuple[SecurityResult, dict]:
        opening = get_balance(client, user_id) or 0
        bet = 10
        r = place_bet(client, user_id, round_id="wallet-1", side="andar", amount=bet)
        server_winner = r.get("server_winner", "")
        fair_payout = 2 * bet if server_winner == "andar" else 0
        inflated = 9999
        settle(client, round_id="wallet-1", user_id=user_id, winner="andar", payout=inflated)
        closing = get_balance(client, user_id) or 0
        expected = opening - bet + fair_payout
        analysis = {
            "opening_balance": opening, "bet": bet, "server_winner": server_winner,
            "fair_payout": fair_payout, "client_payout": inflated,
            "expected_balance": expected, "actual_balance": closing,
            "mismatch": closing - expected,
        }
        ev = [f.to_dict() for f in client.frames[-4:]]
        if closing != expected:
            return SecurityResult(
                test="Wallet/settlement integrity", message="SETTLE", field="payout",
                expected=f"balance == opening - bet + fair_payout = {expected}",
                observed=f"balance == {closing} (client-controlled payout accepted; "
                f"mismatch {closing - expected}).",
                impact="Client-controlled payout breaks wallet integrity.",
                classification=CONFIRMED, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                cwe="CWE-840 (Business Logic Errors)",
                owasp="OWASP WSTG game/wallet integrity", evidence=ev), analysis
        return SecurityResult(
            test="Wallet/settlement integrity", message="SETTLE", field="payout",
            expected=f"balance == {expected}", observed=f"balance == {closing} (consistent).",
            classification=PASS, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            evidence=ev), analysis
