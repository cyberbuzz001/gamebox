"""Injection-family safe indicators: reflected XSS, SQL-injection error
signals, path traversal, SSRF, template-injection, blind SQLi, and CRLF
injection.

All probes are bounded and non-destructive. SSRF uses a benign, obviously-fake
canary host (never a cloud-metadata IP or a real internal address) and relies on
the app echoing that it would fetch an unvalidated target.

Enhanced with:
- PayloadsAllTheThings integration when external.payloads_path is configured
- Polyglot probes (multi-injection-type in one payload)
- Blind SQLi time-based detection
- CRLF injection probe

Reference: swisskyrepo/PayloadsAllTheThings.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("api.injection")

# Built-in probes (always available).
_XSS_MARKER = "<gbx-xss>alert(1)</gbx-xss>"
_SQLI_PROBE = "1'"
_TRAVERSAL_PROBE = "../../etc/passwd"
_SSTI_PROBE = "{{7*7}}"
_SSRF_CANARY = "http://gamebox-ssrf-canary.invalid/probe"
_CRLF_PROBE = "gbx%0d%0aInjected-Header:%20true"
_BLIND_SQLI_PROBE = "1' AND SLEEP(2)-- "
_POLYGLOT = "'-\"-->]]>*/</script><gbx-xss>{{7*7}}"

# PayloadsAllTheThings paths (relative to payloads_path root).
_PAYLOAD_FILES = {
    "xss": "XSS Injection/Intruders/IntrudersXSS.txt",
    "sqli": "SQL Injection/Intruders/SQL-Injection.txt",
    "ssti": "Server Side Template Injection/Intruders/SST-Injection.txt",
    "traversal": "Directory Traversal/Intruders/Traversals.txt",
}

# Max external payloads per category (prevent excessive probing).
_MAX_PAYLOADS = 20


def _load_payloads(category: str, payloads_path: str) -> list[str]:
    """Load payloads from PayloadsAllTheThings for a given category."""
    if not payloads_path:
        return []
    rel = _PAYLOAD_FILES.get(category, "")
    if not rel:
        return []
    fp = Path(payloads_path) / rel
    if not fp.is_file():
        return []
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")][:_MAX_PAYLOADS]
    except Exception:
        return []


class InjectionAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 search_path: str = "/api/search",
                 user_path: str = "/api/user",
                 file_path: str = "/api/file",
                 ssrf_path: str = "/api/avatar/fetch",
                 payloads_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.search_path = search_path
        self.user_path = user_path
        self.file_path = file_path
        self.ssrf_path = ssrf_path
        self.payloads_path = payloads_path

    def run(self, session: AccountSession | None = None) -> list[Finding]:
        out: list[Finding] = []
        out += self._xss()
        out += self._ssti()
        out += self._sqli()
        out += self._traversal()
        out += self._ssrf(session)
        # --- Enhanced checks ---
        out += self._polyglot()
        out += self._blind_sqli()
        out += self._crlf()
        out += self._extended_payloads()
        return out

    def _get(self, path: str, params: dict):
        try:
            return self.client.get(self.base + path, params=params)
        except Exception as exc:
            log.debug("probe %s failed: %s", path, exc)
            return None, None

    def _xss(self) -> list[Finding]:
        resp, ev = self._get(self.search_path, {"q": _XSS_MARKER})
        if resp and _XSS_MARKER in resp.text:
            return [Finding(
                title="Reflected Cross-Site Scripting (XSS)",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="User input is reflected into the HTML response without encoding.",
                endpoint=f"GET {self.search_path}", parameter="q",
                impact="An attacker can execute script in a victim's browser session "
                "(session theft, action forgery).",
                reproduction=f"GET {self.search_path}?q={_XSS_MARKER}; the marker is reflected "
                "verbatim in an HTML context.",
                remediation="Contextually output-encode all user input; set a strict CSP.",
                cwe="CWE-79 (Cross-site Scripting)", owasp="API8:2023 / injection",
                module="api", evidence=[ev] if ev else [])]
        return []

    def _ssti(self) -> list[Finding]:
        resp, ev = self._get(self.search_path, {"q": _SSTI_PROBE})
        # Only fires if the template expression is actually evaluated (49).
        if resp and "49" in resp.text and _SSTI_PROBE not in resp.text:
            return [Finding(
                title="Server-Side Template Injection (SSTI) indicator",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.LIKELY,
                description="A template expression was evaluated server-side.",
                endpoint=f"GET {self.search_path}", parameter="q",
                impact="SSTI can lead to remote code execution.",
                reproduction=f"GET {self.search_path}?q={_SSTI_PROBE}; response contains 49.",
                remediation="Never render user input as a template; use logic-less templates "
                "and sandboxing.",
                cwe="CWE-1336 (Server-Side Template Injection)", owasp="injection",
                module="api", evidence=[ev] if ev else [])]
        return []

    def _sqli(self) -> list[Finding]:
        resp, ev = self._get(self.user_path, {"id": _SQLI_PROBE})
        if resp and resp.status_code >= 500 and "sql" in resp.text.lower():
            return [Finding(
                title="SQL injection error-based indicator",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.LIKELY,
                description="A single quote in a parameter produced a database error, "
                "indicating unparameterized SQL.",
                endpoint=f"GET {self.user_path}", parameter="id",
                impact="Potential data exfiltration or authentication bypass via SQL injection.",
                reproduction=f"GET {self.user_path}?id={_SQLI_PROBE} returns a SQL error.",
                remediation="Use parameterized queries / prepared statements; never build SQL "
                "by string concatenation; suppress DB error details.",
                cwe="CWE-89 (SQL Injection)", owasp="injection", module="api",
                evidence=[ev] if ev else [])]
        return []

    def _traversal(self) -> list[Finding]:
        resp, ev = self._get(self.file_path, {"name": _TRAVERSAL_PROBE})
        if resp and "root:x:0:0" in resp.text:
            return [Finding(
                title="Path traversal / arbitrary file read",
                category=Category.OTHER, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description="A traversal sequence returned the contents of a system file.",
                endpoint=f"GET {self.file_path}", parameter="name",
                impact="Arbitrary files on the server can be read (secrets, source, config).",
                reproduction=f"GET {self.file_path}?name={_TRAVERSAL_PROBE} returns passwd-style "
                "content.",
                remediation="Resolve and canonicalize paths against a fixed base dir; reject "
                "'..'; prefer opaque IDs over file names.",
                cwe="CWE-22 (Path Traversal)", owasp="injection", module="api",
                evidence=[ev] if ev else [])]
        return []

    def _ssrf(self, session: AccountSession | None) -> list[Finding]:
        url = self.base + self.ssrf_path
        headers = session.headers() if session else None
        try:
            resp, ev = self.client.post(url, headers=headers, json_body={"url": _SSRF_CANARY})
        except BlockedRequest as b:
            log.info("ssrf test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        body = resp.json() or {}
        if resp.status_code < 400 and body.get("fetched") and body.get("url") == _SSRF_CANARY:
            return [Finding(
                title="Server-Side Request Forgery (SSRF) indicator",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.SUSPECTED,
                description="The server accepted an arbitrary, unvalidated fetch target. "
                "Confirmed only that validation is absent (no out-of-band callback was used).",
                endpoint=f"POST {self.ssrf_path}", parameter="url",
                impact="An attacker may coerce the server into requesting internal services or "
                "cloud metadata endpoints.",
                reproduction=f"POST {self.ssrf_path} with url={_SSRF_CANARY}; the server reports "
                "it would fetch it without validation.",
                remediation="Allow-list destination hosts/schemes; resolve and block private/"
                "link-local ranges; disable redirects; use an egress proxy.",
                cwe="CWE-918 (Server-Side Request Forgery)", owasp="API7:2023 / SSRF",
                module="api", evidence=[ev] if ev else [])]
        return []

    # --- Enhanced probes ---

    def _polyglot(self) -> list[Finding]:
        """Send a polyglot payload that tests XSS + SSTI + SQLi simultaneously."""
        resp, ev = self._get(self.search_path, {"q": _POLYGLOT})
        if not resp:
            return []
        findings: list[Finding] = []
        text = resp.text
        if "<gbx-xss>" in text:
            findings.append(Finding(
                title="Polyglot XSS: multi-context injection reflected",
                category=Category.OTHER, severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description="A polyglot payload containing XSS, SSTI, and SQLi markers "
                "was reflected without sanitization.",
                endpoint=f"GET {self.search_path}", parameter="q",
                impact="Cross-site scripting in multiple rendering contexts.",
                reproduction=f"GET {self.search_path}?q={_POLYGLOT}",
                remediation="Contextually encode all user input.",
                cwe="CWE-79 (Cross-site Scripting)", owasp="injection",
                module="api", evidence=[ev] if ev else []))
        return findings

    def _blind_sqli(self) -> list[Finding]:
        """Time-based blind SQL injection: if SLEEP(2) causes measurable delay."""
        t0 = time.monotonic()
        resp, ev = self._get(self.user_path, {"id": _BLIND_SQLI_PROBE})
        elapsed = time.monotonic() - t0
        if resp and elapsed >= 1.8:  # conservative threshold
            return [Finding(
                title="Blind SQL injection (time-based) indicator",
                category=Category.OTHER, severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED,
                description=f"A SLEEP(2) payload caused a {elapsed:.1f}s response delay, "
                "suggesting time-based blind SQL injection.",
                endpoint=f"GET {self.user_path}", parameter="id",
                impact="Data exfiltration via time-based inference.",
                reproduction=f"GET {self.user_path}?id={_BLIND_SQLI_PROBE}; response delayed "
                f"{elapsed:.1f}s.",
                remediation="Use parameterized queries; never build SQL by concatenation.",
                cwe="CWE-89 (SQL Injection)", owasp="injection",
                module="api", evidence=[ev] if ev else [])]
        return []

    def _crlf(self) -> list[Finding]:
        """CRLF injection: check if %0d%0a injects response headers."""
        resp, ev = self._get(self.search_path, {"q": _CRLF_PROBE})
        if resp:
            # Check if our injected header appears in the response headers.
            for key in resp.headers:
                if "injected-header" in key.lower():
                    return [Finding(
                        title="CRLF Injection (HTTP Response Splitting)",
                        category=Category.OTHER, severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description="CRLF characters in input were passed through to "
                        "response headers, enabling HTTP response splitting.",
                        endpoint=f"GET {self.search_path}", parameter="q",
                        impact="Attacker can inject arbitrary HTTP headers, enabling "
                        "cache poisoning, XSS, or session fixation.",
                        reproduction=f"GET {self.search_path}?q={_CRLF_PROBE}; "
                        "'Injected-Header' appears in response headers.",
                        remediation="Sanitize CRLF characters in all user input used "
                        "in HTTP headers or redirects.",
                        cwe="CWE-113 (HTTP Response Splitting)",
                        owasp="injection", module="api",
                        evidence=[ev] if ev else [])]
        return []

    def _extended_payloads(self) -> list[Finding]:
        """Run PayloadsAllTheThings payloads when configured."""
        if not self.payloads_path:
            return []

        findings: list[Finding] = []

        # Extended XSS payloads.
        for payload in _load_payloads("xss", self.payloads_path):
            resp, ev = self._get(self.search_path, {"q": payload})
            if resp and payload in resp.text and "<" in payload:
                findings.append(Finding(
                    title=f"Extended XSS payload reflected: {payload[:50]}...",
                    category=Category.OTHER, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=f"PayloadsAllTheThings XSS payload reflected: {payload[:80]}",
                    endpoint=f"GET {self.search_path}", parameter="q",
                    impact="Cross-site scripting.",
                    remediation="Contextually encode all user input.",
                    cwe="CWE-79 (Cross-site Scripting)", owasp="injection",
                    module="api", evidence=[ev] if ev else []))
                break  # One confirmed XSS is enough.

        # Extended SQLi payloads.
        for payload in _load_payloads("sqli", self.payloads_path):
            resp, ev = self._get(self.user_path, {"id": payload})
            if resp and resp.status_code >= 500 and "sql" in resp.text.lower():
                findings.append(Finding(
                    title=f"Extended SQLi payload triggered error: {payload[:50]}...",
                    category=Category.OTHER, severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description=f"PayloadsAllTheThings SQLi payload caused error: {payload[:80]}",
                    endpoint=f"GET {self.user_path}", parameter="id",
                    impact="SQL injection.",
                    remediation="Use parameterized queries.",
                    cwe="CWE-89 (SQL Injection)", owasp="injection",
                    module="api", evidence=[ev] if ev else []))
                break

        return findings

