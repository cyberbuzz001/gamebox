"""API misconfiguration checks: security headers, CORS, excessive data
exposure and mass assignment."""
from __future__ import annotations

from typing import Optional

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("api.misconfig")

_SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Strict-Transport-Security", "Referrer-Policy",
]
# Keys that should never appear in a normal wallet/profile response.
_SENSITIVE_KEYS = ["password", "hash", "secret", "is_admin", "ssn", "token",
                   "internal", "role"]
_EVIL_ORIGIN = "https://evil.gamebox-probe.test"


class MisconfigAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 me_path: str = "/api/wallet/me",
                 profile_update_path: str = "/api/profile/update"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.me_path = me_path
        self.profile_update_path = profile_update_path

    def run(self, session: Optional[AccountSession] = None) -> list[Finding]:
        out: list[Finding] = []
        out += self._headers_and_cors()
        if session:
            out += self._excessive_data(session)
            out += self._mass_assignment(session)
        return out

    def _headers_and_cors(self) -> list[Finding]:
        out: list[Finding] = []
        try:
            resp, ev = self.client.get(self.base + "/", headers={"Origin": _EVIL_ORIGIN})
        except Exception as exc:
            log.debug("header probe failed: %s", exc)
            return out

        missing = [h for h in _SECURITY_HEADERS if h not in resp.headers]
        if missing:
            out.append(Finding(
                title="Missing security response headers",
                category=Category.OTHER, severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                description=f"The application does not set: {', '.join(missing)}.",
                endpoint="GET /", impact="Weaker defense-in-depth against clickjacking, "
                "MIME sniffing, mixed content and information leakage.",
                reproduction="GET / and inspect response headers.",
                remediation="Set CSP, X-Frame-Options=DENY, X-Content-Type-Options=nosniff, "
                "HSTS, and a Referrer-Policy.",
                cwe="CWE-693 (Protection Mechanism Failure)",
                owasp="API8:2023 Security Misconfiguration", module="api",
                evidence=[ev] if ev else []))

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == _EVIL_ORIGIN and acac == "true":
            out.append(Finding(
                title="Permissive CORS reflects arbitrary Origin with credentials",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="The server reflected an attacker-supplied Origin in "
                "Access-Control-Allow-Origin and set Access-Control-Allow-Credentials=true.",
                endpoint="GET /", parameter="Origin",
                impact="Any origin can make credentialed cross-origin requests and read "
                "responses, enabling theft of authenticated data.",
                reproduction=f"Send Origin: {_EVIL_ORIGIN}; it is reflected with credentials.",
                remediation="Allow-list exact trusted origins; never reflect Origin while "
                "Allow-Credentials is true.",
                cwe="CWE-942 (Permissive Cross-domain Policy)",
                owasp="API8:2023 Security Misconfiguration", module="api",
                evidence=[ev] if ev else []))
        return out

    def _excessive_data(self, session: AccountSession) -> list[Finding]:
        try:
            resp, ev = self.client.get(self.base + self.me_path, headers=session.headers())
        except Exception:
            return []
        body = resp.json()
        if not isinstance(body, dict):
            return []
        leaked = sorted({k for k in body
                         for s in _SENSITIVE_KEYS if s in k.lower()})
        if leaked:
            if ev:
                ev.test_account = session.label
            return [Finding(
                title="Excessive data exposure in wallet/profile response",
                category=Category.USER, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                description=f"The response includes sensitive fields: {', '.join(leaked)}.",
                endpoint=f"GET {self.me_path}",
                impact="Internal/sensitive fields (e.g. password hashes, admin flags) are "
                "returned to the client and can aid account takeover or privilege discovery.",
                reproduction=f"GET {self.me_path} as an authenticated user.",
                remediation="Return an explicit whitelist DTO; never serialize the full user "
                "record. Keep secrets server-side.",
                cwe="CWE-213 (Exposure of Sensitive Information)",
                owasp="API3:2023 Broken Object Property Level Authorization", module="api",
                evidence=[ev] if ev else [])]
        return []

    def _mass_assignment(self, session: AccountSession) -> list[Finding]:
        url = self.base + self.profile_update_path
        try:
            resp, ev = self.client.post(url, headers=session.headers(),
                                        json_body={"display_name": "gbx",
                                                   "is_admin": True, "role": "admin"})
        except BlockedRequest as b:
            log.info("mass-assignment test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        body = resp.json() or {}
        elevated = resp.status_code < 400 and (body.get("is_admin") is True
                                               or body.get("role") == "admin")
        # Restore the test account's attributes so later modules see a clean state.
        try:
            self.client.post(url, headers=session.headers(),
                             json_body={"is_admin": False, "role": "user"})
        except Exception:
            pass
        if elevated:
            if ev:
                ev.test_account = session.label
            return [Finding(
                title="Mass assignment allows privilege-controlling fields to be set",
                category=Category.PROFILE, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="The profile update endpoint bound client-supplied is_admin/role "
                "fields, granting elevated attributes.",
                endpoint=f"POST {self.profile_update_path}", parameter="is_admin/role",
                impact="A user can escalate privileges or set protected attributes (role, "
                "is_admin, balance) that should be server-controlled.",
                reproduction=f"POST {self.profile_update_path} with is_admin=true; response "
                "confirms is_admin=true.",
                remediation="Bind only an explicit allow-list of editable fields; never map "
                "the whole request body onto the model.",
                cwe="CWE-915 (Improperly Controlled Modification of Object Attributes)",
                owasp="API6:2023 / API3:2023", module="api",
                evidence=[ev] if ev else [])]
        return []
