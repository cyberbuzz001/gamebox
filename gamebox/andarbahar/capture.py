"""Capture the Andar Bahar message lifecycle for several test rounds.

Drives a legitimate flow (AUTH -> JOIN_GAME -> PLACE_BET -> ... -> ROUND_RESULT)
using the configured test account and records every frame. PLACE_BET is normal
gameplay (STATE_CHANGING, TEST_COINS); it is gated by the safety controller, not
the mutation policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.logger import get_logger
from .ws_client import SafeWebSocketClient, WSFrame

log = get_logger("ab.capture")


@dataclass
class RoundCapture:
    round_id: str
    frames: list[WSFrame] = field(default_factory=list)
    server_winner: str = ""
    joker: str = ""
    bet_side: str = ""
    bet_amount: int = 0

    def to_dict(self) -> dict:
        return {"round_id": self.round_id, "server_winner": self.server_winner,
                "joker": self.joker, "bet_side": self.bet_side,
                "bet_amount": self.bet_amount,
                "frames": [f.to_dict() for f in self.frames]}


class MessageCapture:
    def __init__(self, client: SafeWebSocketClient):
        self.client = client

    def authenticate(self, user_id: int, token: str = "test-token") -> dict | None:
        got = self.client.request({"type": "AUTH", "user_id": user_id, "token": token},
                                  wait_types={"AUTH_OK", "ERROR"})
        for m in got:
            if m.get("type") == "AUTH_OK":
                return m
        return None

    def join(self) -> None:
        self.client.request({"type": "JOIN_GAME"}, wait_types={"GAME_JOINED"})

    def play_round(self, user_id: int, round_id: str, side: str = "andar",
                   amount: int = 10) -> RoundCapture:
        start = len(self.client.frames)
        msgs = self.client.request(
            {"type": "PLACE_BET", "user_id": user_id, "round_id": round_id,
             "side": side, "amount": amount},
            wait_types={"ROUND_RESULT"}, timeout=2.0)
        cap = RoundCapture(round_id=round_id, bet_side=side, bet_amount=amount)
        cap.frames = self.client.frames[start:]
        for m in msgs:
            if m.get("type") == "ROUND_RESULT":
                cap.server_winner = m.get("winner", "")
            if m.get("type") == "JOKER_DEALT":
                cap.joker = m.get("card", "")
        return cap

    def capture_rounds(self, user_id: int, count: int = 3) -> list[RoundCapture]:
        self.authenticate(user_id)
        self.join()
        out = []
        for i in range(count):
            out.append(self.play_round(user_id, round_id=f"cap-{user_id}-{i}",
                                       side="andar" if i % 2 == 0 else "bahar"))
        return out
