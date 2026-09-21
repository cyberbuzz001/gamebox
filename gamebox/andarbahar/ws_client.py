"""Safety-aware WebSocket client for the Andar Bahar tester.

Every outbound frame is authorized by the SafetyController (scope + request
class + hard deny-list) before it is sent, and mutation frames are additionally
gated by the EnvironmentPolicy (refused in production). Captured frames are
redacted. The client never sends real financial operations.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.logger import get_logger, redact
from ..core.models import RequestClass
from ..safety.controller import SafetyController
from .environment import EnvironmentPolicy, MutationBlocked

log = get_logger("ab.ws")

# Fields we never store in captured payloads.
_REDACT_FIELDS = {"token", "access_token", "password", "authorization", "cookie",
                  "session", "secret", "api_key"}


@dataclass
class WSFrame:
    direction: str            # "send" | "recv"
    message_type: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    round_id: str = ""
    game_id: str = ""

    def to_dict(self) -> dict:
        return {"direction": self.direction, "message_type": self.message_type,
                "round_id": self.round_id, "game_id": self.game_id,
                "timestamp": self.timestamp, "payload": self.payload}


def sanitize(payload: dict) -> dict:
    out = {}
    for k, v in payload.items():
        if k.lower() in _REDACT_FIELDS:
            out[k] = "***REDACTED***"
        elif isinstance(v, str):
            out[k] = redact(v)
        else:
            out[k] = v
    return out


class SafeWebSocketClient:
    def __init__(self, url: str, controller: SafetyController,
                 policy: EnvironmentPolicy, origin: Optional[str] = None,
                 open_timeout: float = 5.0):
        self.url = url
        self.controller = controller
        self.policy = policy
        self.origin = origin
        self.open_timeout = open_timeout
        self._ws = None
        self.frames: list[WSFrame] = []
        self.handshake: dict = {}

    # ---- connection ------------------------------------------------------
    def connect(self) -> None:
        from websockets.sync.client import connect
        # Scope check on the WebSocket host before connecting.
        decision = self.controller.authorize("WS-CONNECT", self.url, declared=RequestClass.READ_ONLY)
        if not decision.allowed:
            raise ConnectionError(f"WS connect blocked: {decision.reason}")
        headers = {"Origin": self.origin} if self.origin else None
        conn = connect(self.url, additional_headers=headers, open_timeout=self.open_timeout)
        # Enter the connection's context-manager protocol (websockets>=14 expects
        # this); we keep it open and exit it explicitly in close().
        conn.__enter__()
        self._ws = conn
        self.handshake = {
            "url": self.url,
            "scheme": self.url.split("://", 1)[0],
            "secure": self.url.startswith("wss://"),
            "origin_sent": self.origin or "(none)",
            "subprotocol": getattr(self._ws, "subprotocol", None),
        }
        log.info("WS connected: %s (secure=%s)", self.url, self.handshake["secure"])

    def close(self) -> None:
        if self._ws is not None:
            try:
                self._ws.__exit__(None, None, None)
            except Exception:
                try:
                    self._ws.close()
                except Exception:
                    pass
            self._ws = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- messaging -------------------------------------------------------
    def send(self, message: dict, *, mutation: bool = False,
             declared: Optional[RequestClass] = None) -> None:
        if self._ws is None:
            raise RuntimeError("not connected")
        body = json.dumps(message)
        mtype = message.get("type", "?")

        if mutation and not self.policy.allow_mutation:
            raise MutationBlocked(
                f"mutation frame {mtype} refused in environment "
                f"'{self.policy.environment}' (production is read-only)")

        decision = self.controller.authorize("WS-SEND", self.url, body,
                                             declared=declared or (
                                                 RequestClass.SAFE_TEST if mutation else None))
        if not decision.allowed:
            from ..http.client import BlockedRequest
            raise BlockedRequest(decision)

        self._ws.send(body)
        self.frames.append(WSFrame("send", mtype, sanitize(message),
                                   round_id=str(message.get("round_id", "")),
                                   game_id=str(message.get("game_id", ""))))

    def recv(self, timeout: float = 2.0) -> Optional[dict]:
        if self._ws is None:
            raise RuntimeError("not connected")
        try:
            raw = self._ws.recv(timeout=timeout)
        except TimeoutError:
            return None
        except Exception:
            return None
        try:
            msg = json.loads(raw)
        except Exception:
            return None
        self.frames.append(WSFrame("recv", msg.get("type", "?"), sanitize(msg),
                                   round_id=str(msg.get("round_id", "")),
                                   game_id=str(msg.get("game_id", ""))))
        return msg

    def drain(self, timeout: float = 0.6, max_messages: int = 60) -> list[dict]:
        """Collect messages until a short idle timeout."""
        out: list[dict] = []
        while len(out) < max_messages:
            msg = self.recv(timeout=timeout)
            if msg is None:
                break
            out.append(msg)
        return out

    def request(self, message: dict, wait_types: set[str] | None = None,
                *, mutation: bool = False, declared=None,
                timeout: float = 1.5) -> list[dict]:
        """Send then collect responses (optionally until a wanted type appears)."""
        self.send(message, mutation=mutation, declared=declared)
        got: list[dict] = []
        deadline = time.time() + timeout
        while time.time() < deadline and len(got) < 60:
            msg = self.recv(timeout=timeout)
            if msg is None:
                break
            got.append(msg)
            if wait_types and msg.get("type") in wait_types:
                break
        return got

    def send_mutated(self, message: dict, strategy: str = "all",
                     *, declared=None, timeout: float = 1.5
                     ) -> list[tuple[str, dict, list[dict]]]:
        """Apply mutation strategies to *message* and send each variant.

        Returns a list of (strategy_name, mutated_msg, server_responses).
        All mutations are gated by EnvironmentPolicy (refused in production).

        Reference: andresriancho/websocket-fuzzer mutation strategies.
        """
        results: list[tuple[str, dict, list[dict]]] = []
        mutator = SafeMutator()
        variants = mutator.generate(message, strategy)
        for name, variant in variants:
            try:
                self.send(variant, mutation=True, declared=declared)
                responses = self.drain(timeout=timeout, max_messages=10)
                results.append((name, variant, responses))
            except (MutationBlocked, Exception) as exc:
                log.debug("mutation '%s' blocked/failed: %s", name, exc)
        return results


class SafeMutator:
    """WebSocket message mutation engine (websocket-fuzzer inspired).

    Generates mutated variants of a WS message to test server-side
    input validation. Strategies:
    - field_delete: remove each field one at a time
    - type_confuse: swap value types (string <-> int, etc.)
    - boundary: extreme numeric values
    - oversize: very large string payloads
    - unicode: unicode edge-case characters

    Reference: andresriancho/websocket-fuzzer.
    """

    _BOUNDARY_INTS = [0, -1, 1, 2**31 - 1, -(2**31), 2**53, 999999999999]
    _UNICODE_PROBES = [
        "\x00",                    # null byte
        "\ud800",                  # lone surrogate (invalid)
        "A" * 10000,              # oversized
        "\r\n\r\n",               # CRLF
        "{{7*7}}",                # SSTI
        "<script>x</script>",     # XSS
        "'; DROP TABLE--",        # SQLi
    ]

    def generate(self, message: dict, strategy: str = "all"
                 ) -> list[tuple[str, dict]]:
        """Return a list of (strategy_name, mutated_message) pairs."""
        variants: list[tuple[str, dict]] = []
        strategies = {
            "field_delete": self._field_delete,
            "type_confuse": self._type_confuse,
            "boundary": self._boundary,
            "oversize": self._oversize,
            "unicode": self._unicode,
        }
        if strategy == "all":
            for name, fn in strategies.items():
                variants.extend(fn(message))
        elif strategy in strategies:
            variants.extend(strategies[strategy](message))
        return variants

    def _field_delete(self, msg: dict) -> list[tuple[str, dict]]:
        """Remove each field one at a time."""
        out = []
        for key in list(msg.keys()):
            m = dict(msg)
            del m[key]
            out.append((f"field_delete:{key}", m))
        return out

    def _type_confuse(self, msg: dict) -> list[tuple[str, dict]]:
        """Swap value types: str->int, int->str, bool->str."""
        out = []
        for key, val in msg.items():
            m = dict(msg)
            if isinstance(val, str):
                m[key] = 99999
                out.append((f"type_confuse:{key}:str->int", m))
            elif isinstance(val, (int, float)) and not isinstance(val, bool):
                m[key] = str(val) + "FUZZ"
                out.append((f"type_confuse:{key}:num->str", m))
            elif isinstance(val, bool):
                m[key] = "true_string"
                out.append((f"type_confuse:{key}:bool->str", m))
        return out

    def _boundary(self, msg: dict) -> list[tuple[str, dict]]:
        """Inject extreme numeric values into numeric fields."""
        out = []
        for key, val in msg.items():
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                for bv in self._BOUNDARY_INTS:
                    m = dict(msg)
                    m[key] = bv
                    out.append((f"boundary:{key}:{bv}", m))
        return out

    def _oversize(self, msg: dict) -> list[tuple[str, dict]]:
        """Replace string fields with very large payloads."""
        out = []
        for key, val in msg.items():
            if isinstance(val, str):
                m = dict(msg)
                m[key] = "A" * 100_000
                out.append((f"oversize:{key}", m))
        return out

    def _unicode(self, msg: dict) -> list[tuple[str, dict]]:
        """Inject unicode edge-case characters into string fields."""
        out = []
        for key, val in msg.items():
            if isinstance(val, str):
                for i, probe in enumerate(self._UNICODE_PROBES):
                    m = dict(msg)
                    m[key] = probe
                    out.append((f"unicode:{key}:{i}", m))
        return out

