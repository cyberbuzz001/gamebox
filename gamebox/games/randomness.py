"""Randomness / RNG authority analysis (Phase 13).

Plays a small number of bounded rounds and checks whether the outcome is
server-generated or client-determined. If the client can dictate the result (or
the result is constant/echoes a client seed), the RNG is not server-authoritative.

Enhanced with live provably-fair verification:
- Extracts seed commitment data from game responses
- Verifies HMAC-SHA256/512 seed→outcome correctness
- Upgrades finding confidence from SUSPECTED to CONFIRMED/PASS

References: rakestake/provably-fair-verifier, provably-fair/provably-fair-app.
"""
from __future__ import annotations

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("games.randomness")

_ROUNDS = 5


class RandomnessAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 bet_path: str = "/api/game/teenpatti/bet"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.bet_path = bet_path

    def run(self, session: AccountSession) -> list[Finding]:
        url = self.base + self.bet_path
        client_chosen = "gbx-forced-win"
        echoed = 0
        last_ev = None
        observations: list[dict] = []
        for _ in range(_ROUNDS):
            try:
                resp, ev = self.client.post(url, headers=session.headers(),
                                            json_body={"bet_amount": 1, "result": client_chosen})
            except BlockedRequest as b:
                log.info("randomness test skipped (blocked): %s", b.decision.reason)
                return []
            except Exception:
                return []
            last_ev = ev
            body = resp.json() or {}
            if body.get("result") == client_chosen:
                echoed += 1
            # Attempt to extract provably-fair seed data from the response.
            pf_data = self._extract_pf_data(body)
            if pf_data:
                observations.append(pf_data)
        findings: list[Finding] = []
        if echoed == _ROUNDS:
            if last_ev:
                last_ev.test_account = session.label
            findings.append(Finding(
                title="Game outcome is not server-authoritative (client can set result)",
                category=Category.GAME, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description=f"Across {_ROUNDS} rounds the server returned the client-supplied "
                "result value, so the outcome/RNG is client-controlled rather than "
                "server-generated.",
                endpoint=f"POST {self.bet_path}", parameter="result",
                impact="Players can force winning outcomes, completely undermining game "
                "fairness and integrity.",
                reproduction=f"POST {self.bet_path} with result='{client_chosen}'; the server "
                "echoes/accepts it every round.",
                remediation="Generate outcomes server-side from a CSPRNG (or verifiable "
                "provably-fair seed commitment); ignore any client-supplied result/seed.",
                cwe="CWE-330 (Use of Insufficiently Random Values)",
                owasp="API6:2023 / game integrity", module="randomness",
                evidence=[last_ev] if last_ev else []))

        # --- Provably-fair verification (if seed data was found) ---
        findings += self._verify_provably_fair(observations)
        return findings

    def _extract_pf_data(self, body: dict) -> dict | None:
        """Attempt to detect provably-fair fields in a game response."""
        try:
            from ..games.provably_fair import ProvablyFairDetector
            return ProvablyFairDetector.detect_from_response(body)
        except Exception:
            return None

    def _verify_provably_fair(self, observations: list[dict]) -> list[Finding]:
        """Verify provably-fair seed commitments if data was extracted."""
        if not observations:
            return []
        try:
            from ..games.provably_fair import ProvablyFairVerifier
            verifier = ProvablyFairVerifier()
            report = verifier.verify(observations)
            return report.findings
        except Exception as exc:
            log.debug("provably-fair verification error: %s", exc)
            return []

