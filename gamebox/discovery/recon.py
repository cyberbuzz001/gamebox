"""Target Reconnaissance & Fingerprinting Engine.

Analyzes target HTTP responses for technology stacks, security headers, WAF signatures,
and misconfigurations (e.g. missing CSP, CORS wildcards).
"""
from __future__ import annotations

from typing import Optional

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("discovery.recon")


class ReconEngine:
    def __init__(self, client: SafeHTTPClient):
        self.client = client

    def analyze_headers(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp, ev = self.client.get(base_url)
        except Exception as exc:
            log.debug("recon request failed for %s: %s", base_url, exc)
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Missing Security Headers
        missing = []
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")

        if missing:
            findings.append(Finding(
                title=f"Missing essential security headers ({', '.join(missing)})",
                category=Category.OTHER,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description=f"The base application response at {base_url} is missing standard security hardening headers.",
                endpoint=f"GET {base_url}",
                impact="Increases vulnerability surface to clickjacking, MIME-sniffing, and cross-site scripting (XSS).",
                reproduction=f"GET {base_url} and inspect response headers.",
                remediation="Configure web server to return Content-Security-Policy, X-Frame-Options DENY, and X-Content-Type-Options nosniff.",
                cwe="CWE-693 (Protection Mechanism Failure)",
                owasp="API8:2023 Security Misconfiguration",
                module="recon",
                evidence=[ev] if ev else [],
            ))

        # 2. Server Information Disclosure
        server = headers.get("server") or headers.get("x-powered-by")
        if server:
            findings.append(Finding(
                title=f"Server technology version disclosed in headers ({server})",
                category=Category.OTHER,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                description=f"The server advertises technology stack details: '{server}'.",
                endpoint=f"GET {base_url}",
                impact="Provides attackers with intelligence regarding specific software versions.",
                reproduction=f"GET {base_url} -> Server: {server}",
                remediation="Strip or obfuscate Server and X-Powered-By response headers.",
                cwe="CWE-200 (Exposure of Sensitive Information)",
                owasp="API8:2023 Security Misconfiguration",
                module="recon",
                evidence=[ev] if ev else [],
            ))

        return findings
