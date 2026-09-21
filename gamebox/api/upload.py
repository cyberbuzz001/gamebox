"""Unsafe file-upload check.

Attempts to upload a dangerous file type (a benign, inert marker payload) and
checks whether the server accepts it without type/extension validation.
"""
from __future__ import annotations

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("api.upload")

# Inert marker content -- not executable payload, just enough to test acceptance.
_PROBE = {"filename": "gbx-probe.php", "content_type": "application/x-httpd-php",
          "content": "GAMEBOX-UPLOAD-PROBE (inert)"}


class UploadAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str, path: str = "/api/upload"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.path = path

    def run(self, session: AccountSession) -> list[Finding]:
        url = self.base + self.path
        try:
            resp, ev = self.client.post(url, headers=session.headers(), json_body=_PROBE)
        except BlockedRequest as b:
            log.info("upload test skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        body = resp.json() or {}
        if resp.status_code < 400 and body.get("stored"):
            if ev:
                ev.test_account = session.label
            return [Finding(
                title="Unrestricted file upload (dangerous type accepted)",
                category=Category.OTHER, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="A .php file with an executable content-type was accepted with no "
                "extension/content-type validation.",
                endpoint=f"POST {self.path}", parameter="filename",
                impact="Uploading executable content can lead to remote code execution or "
                "stored XSS depending on how files are served.",
                reproduction=f"POST {self.path} with filename=gbx-probe.php; response reports "
                "it was stored.",
                remediation="Validate against an allow-list of extensions/MIME types, store "
                "outside the web root, randomize names, and serve with a safe content type.",
                cwe="CWE-434 (Unrestricted Upload of File with Dangerous Type)",
                owasp="API8:2023 / injection", module="api", evidence=[ev] if ev else [])]
        return []
