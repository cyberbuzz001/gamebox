"""Module 2 - WebSocket outcome-authority analysis for realtime games.

Adapter over the Andar Bahar WebSocket assessment: runs it and maps the result
into the win-integrity authority model (result vs settlement authority, replay,
round binding, randomness). Non-destructive in production (the underlying
assessment refuses mutation there).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..andarbahar.assessment import AndarBaharAssessment
from ..core.config import Config
from ..core.logger import get_logger

log = get_logger("games.ws_analyzer")


@dataclass
class WebSocketGameResult:
    connected: bool = False
    result_authority: str = "UNKNOWN"
    settlement_authority: str = "UNKNOWN"
    replay_protection: str = "UNKNOWN"
    round_binding: str = "UNKNOWN"
    randomness: str = "UNKNOWN"
    client_controlled_result: bool = False
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class WebSocketGameAnalyzer:
    def __init__(self, config: Config):
        self.config = config

    def run(self, out_dir: str | Path) -> WebSocketGameResult:
        if not self.config.websocket.url:
            return WebSocketGameResult(connected=False)
        assessment = AndarBaharAssessment(self.config)
        summary = assessment.run(out_dir)
        res = WebSocketGameResult(connected=summary.get("connected", False), summary=summary)
        if not res.connected:
            return res
        # The server deals the round (ROUND_RESULT is server-generated), but
        # settlement is what pays out.
        res.result_authority = "SERVER_AUTHORITATIVE"
        client_controlled = summary.get("client_controlled_result") == "YES"
        res.client_controlled_result = client_controlled
        res.settlement_authority = "CLIENT_INPUT" if client_controlled else "SERVER_AUTHORITATIVE"
        res.replay_protection = summary.get("replay_protection", "UNKNOWN")
        res.round_binding = summary.get("round_binding", "UNKNOWN")
        res.randomness = "SERVER"
        return res
