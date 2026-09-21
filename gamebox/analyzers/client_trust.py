"""Client-trust analysis (static).

Inspects served JavaScript for references to values that should be
server-authoritative (balance, payout, multiplier, result, amount, user_id,
wallet_id). Reports them for manual review as an informational map. Confirmed
client-control is proven separately by the game/wallet analyzers.
"""
from __future__ import annotations

import re

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("client_trust")

_SENSITIVE_FIELDS = [
    "balance", "payout", "win_amount", "multiplier", "result", "amount",
    "bet_amount", "user_id", "wallet_id", "transaction_id", "seed", "round_id",
]


class ClientTrustAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 js_paths: list[str] | None = None):
        self.client = client
        self.base = base_url.rstrip("/")
        self.js_paths = js_paths or ["/static/app.js"]

    def run(self) -> list[Finding]:
        found: set[str] = set()
        last_ev = None
        for path in self.js_paths:
            try:
                resp, ev = self.client.get(self.base + path)
            except Exception:
                continue
            last_ev = ev
            for field in _SENSITIVE_FIELDS:
                if re.search(rf"\b{re.escape(field)}\b", resp.text):
                    found.add(field)
        if found:
            return [Finding(
                title="Sensitive, server-authoritative fields referenced in client code",
                category=Category.GAME, severity=Severity.INFO, confidence=Confidence.SUSPECTED,
                description="Client code references fields that must be enforced server-side: "
                + ", ".join(sorted(found)) + ". Verify none can be set by the client.",
                endpoint="GET " + ", ".join(self.js_paths),
                impact="If any of these are accepted from the client, game/wallet integrity "
                "can be broken (see confirmed findings for specifics).",
                reproduction="Review the referenced JavaScript for client-set values.",
                remediation="Ensure balance/payout/result/multiplier/ids are derived and "
                "validated server-side; never trust client-supplied copies.",
                cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                owasp="API6:2023 Business Logic", module="client_trust",
                evidence=[last_ev] if last_ev else [])]
        return []
