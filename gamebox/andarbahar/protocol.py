"""Infer a protocol specification from captured WebSocket frames."""
from __future__ import annotations

from dataclasses import dataclass, field

from .ws_client import WSFrame

# Fields whose presence marks a message as security-sensitive.
_SENSITIVE = {"winner", "winning_side", "result", "round_result", "payout",
              "multiplier", "balance", "settlement", "card", "card_value",
              "joker", "random_seed", "deck", "shuffle", "side", "credited"}


def _py_type(v) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "object"
    return "string"


@dataclass
class MessageSpec:
    message_type: str
    directions: set = field(default_factory=set)
    fields: dict = field(default_factory=dict)      # name -> type
    server_generated: bool = False
    client_generated: bool = False
    sensitive_fields: set = field(default_factory=set)

    @property
    def security_sensitivity(self) -> str:
        return "HIGH" if self.sensitive_fields else "LOW"

    def to_dict(self) -> dict:
        return {
            "message": self.message_type,
            "direction": "both" if len(self.directions) > 1 else next(iter(self.directions), "?"),
            "fields": self.fields,
            "server_generated": self.server_generated,
            "client_generated": self.client_generated,
            "sensitive_fields": sorted(self.sensitive_fields),
            "security_sensitivity": self.security_sensitivity,
        }


class ProtocolMapper:
    def build(self, frames: list[WSFrame]) -> dict:
        specs: dict[str, MessageSpec] = {}
        order: list[str] = []
        for fr in frames:
            spec = specs.get(fr.message_type)
            if spec is None:
                spec = MessageSpec(message_type=fr.message_type)
                specs[fr.message_type] = spec
                if fr.message_type not in order:
                    order.append(fr.message_type)
            spec.directions.add(fr.direction)
            if fr.direction == "recv":
                spec.server_generated = True
            else:
                spec.client_generated = True
            for k, v in fr.payload.items():
                spec.fields.setdefault(k, _py_type(v))
                if k.lower() in _SENSITIVE:
                    spec.sensitive_fields.add(k)
        return {
            "messages": {t: specs[t].to_dict() for t in specs},
            "graph": order,
        }

    @staticmethod
    def transport_metadata(handshake: dict) -> dict:
        """Extract transport-layer security metadata from the handshake dict.

        Records compression (permessage-deflate), subprotocol, and extensions
        from the WebSocket handshake for the protocol map.
        """
        extensions = handshake.get("extensions", "") or ""
        return {
            "secure": handshake.get("secure", False),
            "scheme": handshake.get("scheme", ""),
            "compression": "permessage-deflate" in extensions.lower(),
            "subprotocol": handshake.get("subprotocol") or "(none)",
            "extensions": extensions,
            "origin_sent": handshake.get("origin_sent", "(none)"),
        }

    @staticmethod
    def security_assessment(handshake: dict) -> dict:
        """Assess handshake for common transport-layer security issues.

        Flags:
        - Missing WSS (unencrypted WebSocket transport)
        - Missing authentication token in the connection URL/headers
        - Overly permissive CORS/origin acceptance
        """
        issues: list[dict] = []
        severity_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        # 1. Unencrypted transport.
        if not handshake.get("secure", False):
            issues.append({
                "check": "transport_encryption",
                "severity": "HIGH",
                "message": "WebSocket connection uses ws:// (unencrypted). "
                           "Game data, bets, and auth tokens are transmitted in plaintext.",
                "remediation": "Use wss:// (TLS) for all WebSocket connections.",
            })

        # 2. No auth token in the connection.
        url = handshake.get("url", "")
        auth_hints = ("token", "auth", "jwt", "sid", "session", "apikey", "api_key")
        has_url_auth = any(h in url.lower() for h in auth_hints)
        origin = handshake.get("origin_sent", "")
        # Check if subprotocol carries auth (some implementations use this).
        subproto = handshake.get("subprotocol") or ""
        has_subproto_auth = any(h in subproto.lower() for h in auth_hints)
        if not has_url_auth and not has_subproto_auth:
            issues.append({
                "check": "connection_auth",
                "severity": "MEDIUM",
                "message": "No authentication token detected in the WebSocket URL or "
                           "subprotocol. If auth is handled at a different layer, verify "
                           "it is enforced per-message.",
                "remediation": "Authenticate the WebSocket handshake with a token and "
                               "authorize every inbound message.",
            })

        # 3. Origin acceptance.
        if origin and origin.lower() == "(none)":
            issues.append({
                "check": "origin_policy",
                "severity": "LOW",
                "message": "No Origin header was sent during the handshake. "
                           "Cross-site WebSocket hijacking cannot be ruled out.",
                "remediation": "Always send an Origin header and validate it server-side.",
            })

        # Overall rating.
        max_sev = max((severity_map.get(i["severity"], 0) for i in issues), default=0)
        rating_map = {3: "INSECURE", 2: "WEAK", 1: "ADVISORY", 0: "OK"}
        return {
            "issues": issues,
            "issue_count": len(issues),
            "overall_rating": rating_map.get(max_sev, "UNKNOWN"),
        }

