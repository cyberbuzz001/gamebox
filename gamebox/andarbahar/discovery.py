"""WebSocket discovery for the Andar Bahar tester.

Records the configured WebSocket URL, connection handshake metadata and the
authentication approach, without exposing credentials. Optionally mines ws://|
wss:// references from served JavaScript when an HTTP base URL is available.

Enhanced with STEWS-inspired checks:
- Upgrade header validation during handshake
- Known WebSocket library CVE fingerprinting
- Cross-origin policy testing for unauthorized origins

References: PalindromeLabs/STEWS, doyensec/wsrepl.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity

log = get_logger("ab.discovery")

_WS_RE = re.compile(r"(wss?://[a-zA-Z0-9_.:\-/{}]+)")

# Known WS library fingerprints -> CVE lookups (STEWS-style).
# Maps server header substrings to (CVE, description, severity).
_KNOWN_WS_CVES: list[tuple[str, str, str, Severity]] = [
    ("websocket/7.", "CVE-2021-32640",
     "ws (Node.js <7.4.6): ReDoS in Sec-WebSocket-Protocol header parsing.",
     Severity.MEDIUM),
    ("websocket/6.", "CVE-2021-32640",
     "ws (Node.js <6.2.2): ReDoS in Sec-WebSocket-Protocol header parsing.",
     Severity.MEDIUM),
    ("Cowboy", "CVE-2020-11080",
     "Cowboy (Erlang) HTTP/2 SETTINGS flood DoS.",
     Severity.MEDIUM),
    ("sockjs", "CVE-2020-7693",
     "sockjs <0.3.20: XSS via improper escaping of user input.",
     Severity.HIGH),
    ("socket.io/2.", "CVE-2022-21676",
     "socket.io parser <4.2.1: large packet memory exhaustion DoS.",
     Severity.MEDIUM),
    ("Jetty/9.4", "CVE-2023-26048",
     "Jetty 9.4.x: multipart request DoS via excessive memory consumption.",
     Severity.MEDIUM),
]

# Suspicious / malicious origins to test cross-origin policy.
_TEST_ORIGINS = [
    "https://evil.example.com",
    "null",
    "http://localhost:9999",
]


@dataclass
class WebSocketTarget:
    url: str
    scheme: str = ""
    secure: bool = False
    host: str = ""
    port: int = 0
    discovered_via: str = "config"
    origin: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class HandshakeInfo:
    """Parsed upgrade response metadata."""

    status_code: int = 0
    server_header: str = ""
    upgrade_header: str = ""
    connection_header: str = ""
    sec_websocket_accept: str = ""
    sec_websocket_extensions: str = ""
    sec_websocket_protocol: str = ""
    raw_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__


class WebSocketDiscovery:
    @staticmethod
    def from_url(url: str, origin: str = "", via: str = "config") -> WebSocketTarget:
        p = urlparse(url)
        return WebSocketTarget(
            url=url, scheme=p.scheme, secure=(p.scheme == "wss"),
            host=p.hostname or "", port=p.port or (443 if p.scheme == "wss" else 80),
            discovered_via=via, origin=origin)

    @staticmethod
    def mine_js(text: str) -> list[str]:
        return sorted(set(_WS_RE.findall(text or "")))

    # -- STEWS-inspired handshake checks ------------------------------------

    @staticmethod
    def check_upgrade_headers(handshake: HandshakeInfo) -> list[Finding]:
        """Validate Sec-WebSocket-* headers from the upgrade response."""
        findings: list[Finding] = []
        if not handshake.sec_websocket_accept:
            findings.append(Finding(
                title="WebSocket upgrade response missing Sec-WebSocket-Accept header",
                category=Category.OTHER, severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description="The server's 101 Switching Protocols response did not include "
                "the Sec-WebSocket-Accept header, which is required by RFC 6455 §4.2.2.",
                endpoint="WS handshake",
                impact="Non-compliant implementations may be vulnerable to cross-protocol "
                "attacks or downgrade scenarios.",
                remediation="Ensure the server returns a valid Sec-WebSocket-Accept header "
                "derived from the client's Sec-WebSocket-Key.",
                cwe="CWE-693 (Protection Mechanism Failure)",
                owasp="transport security", module="ws_discovery"))
        if handshake.upgrade_header.lower() not in ("websocket", ""):
            findings.append(Finding(
                title=f"Unexpected Upgrade header value: '{handshake.upgrade_header}'",
                category=Category.OTHER, severity=Severity.LOW,
                confidence=Confidence.SUSPECTED,
                description="The Upgrade header in the handshake response contained an "
                f"unexpected value '{handshake.upgrade_header}' instead of 'websocket'.",
                endpoint="WS handshake",
                impact="May indicate a proxy or middleware intercepting the connection.",
                remediation="Verify the upgrade path is clean and terminates at the "
                "intended WebSocket server.",
                cwe="CWE-693 (Protection Mechanism Failure)",
                owasp="transport security", module="ws_discovery"))
        return findings

    @staticmethod
    def detect_known_cves(handshake: HandshakeInfo) -> list[Finding]:
        """Fingerprint the WS server header against known CVEs."""
        findings: list[Finding] = []
        server = handshake.server_header.lower()
        for fingerprint, cve, desc, severity in _KNOWN_WS_CVES:
            if fingerprint.lower() in server:
                findings.append(Finding(
                    title=f"Known WebSocket CVE detected: {cve}",
                    category=Category.OTHER, severity=severity,
                    confidence=Confidence.SUSPECTED,
                    description=f"Server header '{handshake.server_header}' matches a known "
                    f"vulnerable library fingerprint. {desc}",
                    endpoint="WS handshake",
                    impact="Potential exploitation depending on the specific CVE.",
                    reproduction=f"Server header: {handshake.server_header}",
                    remediation=f"Upgrade the WebSocket library to a version that patches {cve}.",
                    cwe="CWE-1035 (OWASP Top Ten 2017 — A9 Using Components with Known Vulns)",
                    owasp="API10:2023 Unsafe Consumption of APIs",
                    module="ws_discovery"))
        return findings

    @staticmethod
    def check_cross_origin(
        ws_url: str, accepted_origins: Optional[list[str]] = None
    ) -> list[Finding]:
        """Test whether the WS endpoint accepts connections from unauthorized origins.

        This is a passive check — it attempts to connect with suspicious Origin
        headers and records whether the handshake succeeds. The connection is
        immediately closed after the check.
        """
        findings: list[Finding] = []
        origins = accepted_origins or _TEST_ORIGINS
        try:
            from websockets.sync.client import connect
        except ImportError:
            log.info("websockets not available; skipping cross-origin check")
            return findings

        for origin in origins:
            try:
                ws = connect(ws_url, additional_headers={"Origin": origin},
                             open_timeout=3.0)
                ws.__enter__()
                try:
                    ws.__exit__(None, None, None)
                except Exception:
                    pass
                # If we get here, connection was accepted with a rogue origin.
                findings.append(Finding(
                    title=f"WebSocket accepts connection from unauthorized origin: {origin}",
                    category=Category.OTHER, severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description=f"The WebSocket endpoint at {ws_url} accepted a connection "
                    f"with Origin header set to '{origin}'. This may allow cross-site "
                    "WebSocket hijacking (CSWSH).",
                    endpoint=ws_url,
                    impact="An attacker can establish a WebSocket connection from a "
                    "malicious page, potentially reading or writing game state.",
                    reproduction=f"Connect to {ws_url} with Origin: {origin}; handshake "
                    "succeeds.",
                    remediation="Validate the Origin header during the WebSocket handshake "
                    "and reject connections from untrusted origins.",
                    cwe="CWE-346 (Origin Validation Error)",
                    owasp="API2:2023 Broken Authentication", module="ws_discovery"))
            except Exception:
                # Connection rejected — correct behavior.
                pass
        return findings

