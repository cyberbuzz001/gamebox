"""WebSocket authorization review.

Real WebSocket exploitation is context-specific and often requires manual
follow-up, so this analyzer stays read-only: it locates ws://|wss:// references
in served JavaScript and flags endpoints that carry no token/auth parameter for
manual authorization review.
"""
from __future__ import annotations

import re

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("api.websocket")

_WS_RE = re.compile(r"(wss?://[a-zA-Z0-9_.:\-/{}]+)")
_AUTH_HINTS = ("token", "auth", "jwt", "sid", "session", "apikey", "api_key")


class WebSocketAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 js_paths: list[str] | None = None):
        self.client = client
        self.base = base_url.rstrip("/")
        self.js_paths = js_paths or ["/static/app.js"]

    def run(self) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for path in self.js_paths:
            try:
                resp, ev = self.client.get(self.base + path)
            except Exception:
                continue
            for ws in set(_WS_RE.findall(resp.text)):
                if ws in seen:
                    continue
                seen.add(ws)
                if not any(h in ws.lower() for h in _AUTH_HINTS):
                    out.append(Finding(
                        title="WebSocket endpoint without an authentication parameter",
                        category=Category.OTHER, severity=Severity.MEDIUM,
                        confidence=Confidence.SUSPECTED,
                        description=f"Referenced WebSocket URL {ws} carries no token/auth "
                        "parameter. Authorization must be verified manually.",
                        endpoint=ws,
                        impact="If the socket does not authenticate/authorize each message, "
                        "clients may access or influence other users' game state.",
                        reproduction=f"Found {ws} referenced in {path} with no auth hint.",
                        remediation="Authenticate the WebSocket handshake, bind the connection "
                        "to a verified principal, and authorize every inbound message.",
                        cwe="CWE-306 (Missing Authentication for Critical Function)",
                        owasp="API2:2023 Broken Authentication", module="api",
                        evidence=[ev] if ev else []))
        return out
