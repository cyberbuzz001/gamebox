"""Rate-limiting check on the authentication endpoint.

Sends a small, bounded burst of failed logins for a known test account and
checks whether the server ever throttles (HTTP 429 / Retry-After). Bounded to a
handful of requests to avoid any load impact.
"""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("api.rate_limit")

_ATTEMPTS = 8


class RateLimitAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 login_path: str = "/api/auth/login"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.login_path = login_path

    def run(self, username: str) -> list[Finding]:
        url = self.base + self.login_path
        statuses: list[int] = []
        last_ev = None
        for _ in range(_ATTEMPTS):
            try:
                resp, ev = self.client.post(
                    url, json_body={"username": username, "password": "wrong-pw-probe"})
            except BlockedRequest as b:
                log.info("rate-limit test skipped (blocked): %s", b.decision.reason)
                return []
            except Exception:
                break
            statuses.append(resp.status_code)
            last_ev = ev
        if statuses and not any(s == 429 for s in statuses):
            return [Finding(
                title="No rate limiting on authentication endpoint",
                category=Category.AUTH, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                description=f"{len(statuses)} rapid failed logins were all processed with no "
                "throttling (no HTTP 429).",
                endpoint=f"POST {self.login_path}",
                impact="Enables credential stuffing / brute force and OTP guessing.",
                reproduction=f"Send {_ATTEMPTS} rapid failed logins; none are rate limited.",
                remediation="Apply per-account and per-IP rate limiting with backoff and "
                "lockout; add CAPTCHA/MFA after repeated failures.",
                cwe="CWE-307 (Improper Restriction of Excessive Authentication Attempts)",
                owasp="API4:2023 Unrestricted Resource Consumption", module="authentication",
                evidence=[last_ev] if last_ev else [])]
        return []
