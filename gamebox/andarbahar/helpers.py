"""Protocol-specific helpers shared by the Andar Bahar tests."""
from __future__ import annotations

from typing import Optional

from ..core.models import RequestClass
from .environment import MutationBlocked
from .ws_client import SafeWebSocketClient


def _safe_request(client: SafeWebSocketClient, *args, **kwargs) -> list[dict]:
    """Send a request, returning [] if the safety controller or environment
    policy blocks it (so callers degrade gracefully in read-only environments)."""
    from ..http.client import BlockedRequest
    try:
        return client.request(*args, **kwargs)
    except (BlockedRequest, MutationBlocked):
        return []
    except Exception:
        return []


def get_balance(client: SafeWebSocketClient, user_id: int) -> Optional[int]:
    msgs = _safe_request(client, {"type": "GET_BALANCE", "user_id": user_id},
                         wait_types={"BALANCE"}, declared=RequestClass.READ_ONLY,
                         timeout=1.5)
    for m in msgs:
        if m.get("type") == "BALANCE":
            return int(m.get("balance", 0))
    return None


def place_bet(client: SafeWebSocketClient, user_id: int, round_id: str,
              side: str = "andar", amount: int = 10) -> dict:
    msgs = _safe_request(
        client, {"type": "PLACE_BET", "user_id": user_id, "round_id": round_id,
                 "side": side, "amount": amount},
        wait_types={"ROUND_RESULT"}, timeout=2.0)
    result = {"round_id": round_id, "server_winner": ""}
    for m in msgs:
        if m.get("type") == "ROUND_RESULT":
            result["server_winner"] = m.get("winner", "")
    return result


def settle(client: SafeWebSocketClient, *, round_id: str, user_id: int,
           winner: str, payout: int, mutation: bool = True) -> Optional[dict]:
    msgs = _safe_request(
        client, {"type": "SETTLE", "round_id": round_id, "user_id": user_id,
                 "winner": winner, "payout": payout},
        wait_types={"SETTLEMENT"}, mutation=mutation,
        declared=RequestClass.SAFE_TEST, timeout=1.5)
    for m in msgs:
        if m.get("type") == "SETTLEMENT":
            return m
    return None
