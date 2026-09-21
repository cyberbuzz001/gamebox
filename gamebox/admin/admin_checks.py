"""Administrative attack-surface checks.

Discovers admin-looking endpoints and tests function-level authorization: can an
admin API be reached with no (or a non-admin) authentication token? Only the
configured test accounts are used; no persistence or configuration changes are
made.
"""
from __future__ import annotations

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("admin")


class AdminAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 admin_paths: list[str] | None = None):
        self.client = client
        self.base = base_url.rstrip("/")
        self.admin_paths = admin_paths or ["/api/admin/users", "/api/admin/config"]

    def run(self, low_priv: AccountSession | None = None) -> list[Finding]:
        out: list[Finding] = []
        for path in self.admin_paths:
            out += self._check(path, low_priv)
        return out

    def _check(self, path: str, low_priv: AccountSession | None) -> list[Finding]:
        url = self.base + path
        # 1. Completely unauthenticated access.
        try:
            resp_anon, ev_anon = self.client.get(url)
        except Exception:
            return []
        if resp_anon.status_code == 200 and resp_anon.text.strip():
            sev = Severity.CRITICAL if "config" in path or "user" in path else Severity.HIGH
            return [Finding(
                title=f"Broken function-level authorization on {path}",
                category=Category.ADMIN, severity=sev, confidence=Confidence.CONFIRMED,
                description=f"The admin endpoint {path} returned data with no authentication "
                "or authorization.",
                endpoint=f"GET {path}",
                impact="Unauthenticated users can access administrative data/functions "
                "(user lists, configuration, secrets).",
                reproduction=f"GET {path} with no Authorization header returns HTTP 200 data.",
                remediation="Require authentication and an explicit admin-role check on every "
                "admin route; deny by default.",
                cwe="CWE-862 (Missing Authorization)",
                owasp="API5:2023 Broken Function Level Authorization", module="admin",
                evidence=[ev_anon] if ev_anon else [])]

        # 2. Access with a low-privileged (non-admin) token.
        if low_priv:
            try:
                resp_low, ev_low = self.client.get(url, headers=low_priv.headers())
            except Exception:
                return []
            if resp_low.status_code == 200 and resp_low.text.strip():
                if ev_low:
                    ev_low.test_account = low_priv.label
                return [Finding(
                    title=f"Privilege escalation: non-admin can reach {path}",
                    category=Category.ADMIN, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    description=f"A low-privileged account accessed admin endpoint {path}.",
                    endpoint=f"GET {path}",
                    impact="Regular users can perform administrative actions.",
                    reproduction=f"GET {path} with a non-admin token returns HTTP 200.",
                    remediation="Enforce role-based authorization server-side on every admin "
                    "route.",
                    cwe="CWE-863 (Incorrect Authorization)",
                    owasp="API5:2023 Broken Function Level Authorization", module="admin",
                    evidence=[ev_low] if ev_low else [])]
        return []
