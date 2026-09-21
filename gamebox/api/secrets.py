"""Source / JavaScript intelligence: scan served JS and responses for exposed
secrets (API keys, tokens). Discovered secret values are classified sensitive
and are never printed in full -- only a redacted fingerprint is stored.
"""
from __future__ import annotations

import re

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("api.secrets")

# (label, pattern). Patterns match common secret shapes.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Stripe secret key", re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{6,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API key assignment",
     re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]")),
    ("JWT secret", re.compile(r"(?i)jwt[_-]?secret\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("Bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
]


def _fingerprint(secret: str) -> str:
    """A safe, non-reversible hint: first 3 chars + length, never the value."""
    head = secret[:3]
    return f"{head}...(len={len(secret)})"


class SecretsAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 paths: list[str] | None = None):
        self.client = client
        self.base = base_url.rstrip("/")
        self.paths = paths or ["/static/app.js"]

    def run(self) -> list[Finding]:
        out: list[Finding] = []
        for path in self.paths:
            try:
                resp, ev = self.client.get(self.base + path)
            except Exception:
                continue
            hits: list[str] = []
            for label, pat in _PATTERNS:
                for m in pat.findall(resp.text):
                    value = m if isinstance(m, str) else m[0]
                    hits.append(f"{label} [{_fingerprint(value)}]")
            if hits:
                # ev.response_excerpt is already redacted by the HTTP client.
                out.append(Finding(
                    title="Secret exposed in client-served source",
                    category=Category.OTHER, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="Secret-like values were found in served JavaScript/source: "
                    + "; ".join(sorted(set(hits))) + " (values redacted).",
                    endpoint=f"GET {path}",
                    impact="Hardcoded keys/tokens shipped to clients can be extracted and "
                    "abused against backend or third-party services.",
                    reproduction=f"GET {path} and grep for secret patterns.",
                    remediation="Remove secrets from client bundles; move to server-side "
                    "config; rotate any exposed credential immediately.",
                    cwe="CWE-798 (Use of Hard-coded Credentials)",
                    owasp="API8:2023 Security Misconfiguration", module="api",
                    evidence=[ev] if ev else []))
        return out
