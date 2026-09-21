"""Authorization analyzer (BOLA / IDOR).

Uses two explicitly-authorized test accounts. It checks whether account A can
read account B's wallet by object id. Only the two configured test accounts are
ever referenced -- the analyzer never enumerates or touches arbitrary real users.
"""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .common import AccountSession

log = get_logger("authorization")


class AuthorizationAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 wallet_by_id_path: str = "/api/wallet/{id}"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.wallet_by_id_path = wallet_by_id_path

    def run(self, attacker: AccountSession, victim: AccountSession) -> list[Finding]:
        if victim.wallet_id is None or attacker.wallet_id is None:
            log.info("BOLA test skipped: wallet ids for both test accounts required")
            return []
        if attacker.wallet_id == victim.wallet_id:
            return []

        victim_url = self.base + self.wallet_by_id_path.format(id=victim.wallet_id)
        try:
            resp, ev = self.client.get(victim_url, headers=attacker.headers())
        except BlockedRequest as b:
            log.info("BOLA test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception as exc:
            log.debug("BOLA test error: %s", exc)
            return []

        body = resp.json() or {}
        # Confirmed if attacker gets 200 and the body clearly belongs to the victim.
        belongs_to_victim = (
            body.get("wallet_id") == victim.wallet_id
            or body.get("user_id") == victim.user_id
        )
        if resp.status_code == 200 and belongs_to_victim:
            if ev:
                ev.test_account = f"{attacker.label} accessing {victim.label}"
            return [Finding(
                title="Broken object-level authorization (IDOR) on wallet lookup",
                category=Category.WALLET, severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=(
                    "A wallet can be read by its numeric id without an ownership check. "
                    f"Test account '{attacker.label}' successfully read the wallet of test "
                    f"account '{victim.label}' (wallet_id={victim.wallet_id})."
                ),
                endpoint=f"GET {self.wallet_by_id_path}", parameter="id",
                impact=(
                    "Any authenticated user can read other users' wallet balances and details "
                    "by incrementing the id. Confirmed between two authorized test accounts only."
                ),
                reproduction=(
                    f"Authenticate as {attacker.label}; GET {self.wallet_by_id_path.format(id=victim.wallet_id)}; "
                    "response returns the other account's wallet with HTTP 200."
                ),
                remediation=(
                    "Enforce ownership on every object access: derive the wallet from the "
                    "authenticated session, or verify wallet.owner == current_user before "
                    "returning. Prefer non-enumerable identifiers (UUIDs) as defense in depth."
                ),
                cwe="CWE-639 (Authorization Bypass Through User-Controlled Key)",
                owasp="API1:2023 Broken Object Level Authorization",
                module="authorization", evidence=[ev] if ev else [],
            )]
        return []
