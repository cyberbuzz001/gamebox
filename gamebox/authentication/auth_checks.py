"""Authentication security checks: username enumeration and insecure
password-reset flows."""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("authentication")


class AuthAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 login_path: str = "/api/auth/login",
                 forgot_path: str = "/api/auth/forgot"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.login_path = login_path
        self.forgot_path = forgot_path

    def run(self, known_username: str) -> list[Finding]:
        out: list[Finding] = []
        out += self._enumeration(known_username)
        out += self._password_reset(known_username)
        return out

    def _enumeration(self, known_username: str) -> list[Finding]:
        url = self.base + self.login_path
        try:
            r_unknown, ev1 = self.client.post(
                url, json_body={"username": "gbx-no-such-user", "password": "x"})
            r_known, ev2 = self.client.post(
                url, json_body={"username": known_username, "password": "definitely-wrong"})
        except BlockedRequest as b:
            log.info("enumeration test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        # Different status codes or bodies for unknown vs known user => enumeration.
        different = (r_unknown.status_code != r_known.status_code) or \
                    (r_unknown.text.strip() != r_known.text.strip())
        if different:
            return [Finding(
                title="Username enumeration via login responses",
                category=Category.AUTH, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                description="The login endpoint returns distinguishable responses for unknown "
                f"users (HTTP {r_unknown.status_code}) vs valid users with a wrong password "
                f"(HTTP {r_known.status_code}).",
                endpoint=f"POST {self.login_path}", parameter="username",
                impact="Attackers can enumerate valid accounts, improving credential-stuffing "
                "and phishing.",
                reproduction="Compare responses for a non-existent user vs a valid user with a "
                "wrong password.",
                remediation="Return a single generic error and identical status/timing for all "
                "failed logins.",
                cwe="CWE-204 (Observable Response Discrepancy)",
                owasp="API2:2023 Broken Authentication", module="authentication",
                evidence=[e for e in (ev1, ev2) if e])]
        return []

    def _password_reset(self, known_username: str) -> list[Finding]:
        url = self.base + self.forgot_path
        try:
            resp, ev = self.client.post(url, json_body={"username": known_username})
        except BlockedRequest as b:
            log.info("reset test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        body = resp.json() or {}
        token = body.get("reset_token")
        if resp.status_code < 400 and token:
            return [Finding(
                title="Insecure password reset: token returned in response and predictable",
                category=Category.AUTH, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="The reset endpoint returns the reset token directly in its "
                "response body (it should be delivered out-of-band) and the token appears "
                "structured/predictable.",
                endpoint=f"POST {self.forgot_path}", parameter="reset_token",
                impact="Anyone who can trigger a reset can obtain (or predict) the token and "
                "take over the account.",
                reproduction=f"POST {self.forgot_path} with a valid username; the response body "
                "contains a reset_token.",
                remediation="Send a high-entropy, single-use, short-lived token out-of-band "
                "(email/SMS); never return it in the API response.",
                cwe="CWE-640 (Weak Password Recovery Mechanism)",
                owasp="API2:2023 Broken Authentication", module="authentication",
                evidence=[ev] if ev else [])]
        return []
