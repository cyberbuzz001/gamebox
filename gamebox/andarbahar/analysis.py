"""Primary outcome-trust tests: client-trust classification, server-authority,
safe mutation and randomness."""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Confidence, Severity
from .helpers import get_balance, place_bet, settle
from .results import CONFIRMED, FAIL, PASS, POTENTIAL, SecurityResult
from .ws_client import SafeWebSocketClient

log = get_logger("ab.analysis")

# Sensitive fields and whether they must be server-authoritative.
_OUTCOME_FIELDS = ["winner", "winning_side", "result", "round_result", "payout",
                   "multiplier", "card", "card_value", "joker", "side",
                   "random_seed", "deck", "shuffle", "balance", "settlement"]


def classify_field_trust(protocol_map: dict) -> dict:
    """Classify each sensitive field as SERVER_AUTHORITATIVE / CLIENT_INPUT /
    DERIVED / UNKNOWN based on who generates the message that carries it."""
    classification: dict[str, str] = {}
    for mtype, spec in protocol_map.get("messages", {}).items():
        for f in spec.get("sensitive_fields", []):
            client_gen = spec.get("client_generated")
            server_gen = spec.get("server_generated")
            if client_gen and not server_gen:
                verdict = "CLIENT_INPUT"
            elif server_gen and not client_gen:
                verdict = "SERVER_AUTHORITATIVE"
            elif client_gen and server_gen:
                verdict = "UNKNOWN"
            else:
                verdict = "UNKNOWN"
            key = f"{mtype}.{f}"
            classification[key] = verdict
    return classification


class ClientTrustAnalyzer:
    def run(self, protocol_map: dict) -> list[SecurityResult]:
        results: list[SecurityResult] = []
        cls = classify_field_trust(protocol_map)
        for key, verdict in cls.items():
            mtype, field = key.split(".", 1)
            if verdict == "CLIENT_INPUT" and field.lower() in _OUTCOME_FIELDS:
                results.append(SecurityResult(
                    test="High-risk client trust", message=mtype, field=field,
                    expected=f"'{field}' must be server-authoritative",
                    observed=f"client sends '{field}' in {mtype} (CLIENT_INPUT)",
                    impact="A game-critical value is supplied by the client; if the server "
                    "trusts it, outcomes/payouts can be forged.",
                    classification=POTENTIAL, severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                    owasp="OWASP WSTG WebSocket / game integrity"))
        return results


class ServerAuthorityTest:
    """The core test: does the server accept a client-declared outcome/payout?"""

    def run(self, client: SafeWebSocketClient, user_id: int) -> SecurityResult:
        b0 = get_balance(client, user_id)
        bet = place_bet(client, user_id, round_id="authority-1", side="andar", amount=10)
        server_winner = bet.get("server_winner", "")
        # Claim the OPPOSITE of the server's winner and a chosen payout.
        claimed = "bahar" if server_winner == "andar" else "andar"
        chosen_payout = 5000
        resp = settle(client, round_id="authority-1", user_id=user_id,
                      winner=claimed, payout=chosen_payout, mutation=True)
        b1 = get_balance(client, user_id)
        ev = [f.to_dict() for f in client.frames[-6:]]

        accepted = (resp is not None and b0 is not None and b1 is not None
                    and (b1 - (b0 - 10)) >= chosen_payout - 1)
        if accepted and (resp or {}).get("server_verified") is not True:
            return SecurityResult(
                test="Client-controlled game outcome", message="SETTLE",
                field="winner/payout",
                expected="Server independently determines the winner and payout and ignores "
                "client-supplied values.",
                observed=f"server returned winner='{server_winner}' but SETTLE with "
                f"winner='{claimed}' and payout={chosen_payout} was credited "
                f"(balance {b0} -> {b1}).",
                impact="An authenticated client can dictate the game outcome and settlement "
                "amount (demonstrated on TEST_COINS).",
                classification=CONFIRMED, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                owasp="OWASP WSTG-BUSL / game integrity", evidence=ev)
        return SecurityResult(
            test="Server-authoritative settlement", message="SETTLE", field="winner/payout",
            expected="Server determines outcome/payout.",
            observed="client-supplied outcome/payout was not credited.",
            classification=PASS, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            evidence=ev)


class SafeMutator:
    """SAFE_MUTATION: clone a settle message and mutate one field at a time."""

    def run(self, client: SafeWebSocketClient, user_id: int) -> list[SecurityResult]:
        results: list[SecurityResult] = []
        place_bet(client, user_id, round_id="mutate-1", side="andar", amount=5)
        mutations = [("winner", "andar"), ("side", "andar"),
                     ("payout", 777), ("multiplier", 99)]
        for field, value in mutations:
            b0 = get_balance(client, user_id)
            msg = {"type": "SETTLE", "round_id": "mutate-1", "user_id": user_id,
                   "winner": "andar", "payout": 1, field: value}
            resp = client.request(msg, wait_types={"SETTLEMENT"}, mutation=True,
                                  timeout=1.5)
            settlement = next((m for m in resp if m.get("type") == "SETTLEMENT"), None)
            b1 = get_balance(client, user_id)
            if settlement is None:
                behavior, cls, sev = "REJECTS", PASS, Severity.INFO
            elif field == "payout" and b1 is not None and b0 is not None and (b1 - b0) == value:
                behavior, cls, sev = "ACCEPTS", FAIL, Severity.CRITICAL
            elif settlement.get(field) == value:
                behavior, cls, sev = "ACCEPTS", FAIL, Severity.HIGH
            else:
                behavior, cls, sev = "IGNORES/NORMALIZES", PASS, Severity.INFO
            results.append(SecurityResult(
                test="Safe field mutation", message="SETTLE", field=field,
                expected="Server ignores/validates client-supplied outcome fields.",
                observed=f"mutating '{field}' -> {value}: server {behavior}.",
                impact="Client can influence settlement." if cls == FAIL else "",
                classification=cls, severity=sev,
                confidence=Confidence.CONFIRMED if cls == FAIL else Confidence.SUSPECTED,
                cwe="CWE-602", owasp="OWASP WSTG game integrity",
                evidence=[f.to_dict() for f in client.frames[-3:]]))
        return results


class RandomnessAnalysis:
    def run(self, client: SafeWebSocketClient, user_id: int,
            rounds: int = 30) -> SecurityResult:
        winners = {"andar": 0, "bahar": 0, "other": 0}
        for i in range(rounds):
            r = place_bet(client, user_id, round_id=f"rng-{i}", side="andar", amount=1)
            w = r.get("server_winner", "other")
            winners[w if w in winners else "other"] += 1
        total = max(1, winners["andar"] + winners["bahar"])
        andar_pct = winners["andar"] / total
        skewed = andar_pct < 0.2 or andar_pct > 0.8
        return SecurityResult(
            test="Outcome randomness (server RNG)", message="ROUND_RESULT", field="winner",
            expected="Server-generated outcomes with no gross bias.",
            observed=f"{rounds} rounds: andar={winners['andar']} bahar={winners['bahar']} "
            f"(andar={andar_pct:.0%}). Outcomes are server-generated (recv only).",
            impact="Gross bias would indicate a weak/biased RNG." if skewed else "",
            classification=POTENTIAL if skewed else PASS,
            severity=Severity.MEDIUM if skewed else Severity.INFO,
            confidence=Confidence.SUSPECTED,
            cwe="CWE-330" if skewed else "", owasp="game integrity")
