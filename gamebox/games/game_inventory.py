"""Module 1 - Game inventory.

Enumerates games across HTTP (from the discovered endpoint inventory) and
WebSocket (from configuration), recording endpoints and which fields appear
client- vs server-controlled.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import Endpoint
from .discovery import GameDiscovery

log = get_logger("games.inventory")

# Known game name hints -> friendly label.
_GAME_LABELS = {
    "teenpatti": "Teen Patti", "teen-patti": "Teen Patti", "rummy": "Rummy",
    "poker": "Poker", "roulette": "Roulette", "dice": "Dice", "crash": "Crash",
    "slot": "Slots", "blackjack": "Blackjack", "baccarat": "Baccarat",
    "andarbahar": "Andar Bahar", "andar-bahar": "Andar Bahar",
}


@dataclass
class GameRecord:
    game_id: str
    name: str
    transport: str                 # "http" | "ws"
    bet_endpoint: str = ""
    result_endpoint: str = ""
    settlement_endpoint: str = ""
    wallet_endpoint: str = ""
    ws_url: str = ""
    client_fields: list = field(default_factory=list)
    server_fields: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


class GameInventory:
    def __init__(self, config: Config):
        self.config = config
        base = config.base_urls[0].rstrip("/") if config.base_urls else ""
        self.base = base

    def discover(self, endpoints: list[Endpoint]) -> list[GameRecord]:
        games: list[GameRecord] = []
        games += self._http_games(endpoints)
        games += self._ws_games()
        log.info("game inventory: %d games", len(games))
        return games

    def _http_games(self, endpoints: list[Endpoint]) -> list[GameRecord]:
        urls = {e.url for e in endpoints}
        # Group by game name detected in bet/game endpoints.
        profiles = GameDiscovery().analyze(endpoints)
        out: list[GameRecord] = []
        seen_bets: set[str] = set()
        settlement = next((u for u in urls if "settlement" in u.lower()), "")
        wallet = next((u for u in urls if u.lower().endswith("/api/wallet/me")), "")
        # Prefer specific game names; process known games first.
        profiles = sorted(profiles, key=lambda p: p.name not in _GAME_LABELS)
        for p in profiles:
            if p.name in ("settlement", "game", "result", "round"):  # not games themselves
                continue
            bet = next((u for u in urls if p.name in u.lower() and "bet" in u.lower()),
                       (p.action_endpoints[0].split(" ", 1)[-1] if p.action_endpoints else ""))
            if bet and bet in seen_bets:      # de-dupe games sharing a bet endpoint
                continue
            seen_bets.add(bet)
            out.append(GameRecord(
                game_id=f"http:{p.name}", name=_GAME_LABELS.get(p.name, p.name.title()),
                transport="http", bet_endpoint=bet, settlement_endpoint=settlement,
                wallet_endpoint=wallet,
                client_fields=sorted(set(p.client_fields) | {"bet_amount", "payout"}),
                server_fields=["result", "payout(should be)", "balance"]))
        if not out and any("/api/game" in u for u in urls):
            # Fallback: at least register a generic HTTP game if game endpoints exist.
            bet = next((u for u in urls if "/api/game" in u.lower() and "bet" in u.lower()), "")
            out.append(GameRecord(game_id="http:game", name="Card Game", transport="http",
                                  bet_endpoint=bet, settlement_endpoint=settlement,
                                  wallet_endpoint=wallet,
                                  client_fields=["bet_amount", "payout"],
                                  server_fields=["result", "balance"]))
        return out

    def _ws_games(self) -> list[GameRecord]:
        url = self.config.websocket.url
        if not url:
            return []
        return [GameRecord(
            game_id="ws:andarbahar", name="Andar Bahar", transport="ws",
            ws_url=url, bet_endpoint="WS PLACE_BET", result_endpoint="WS ROUND_RESULT",
            settlement_endpoint="WS SETTLE", wallet_endpoint="WS GET_BALANCE",
            client_fields=["side", "amount", "winner", "payout", "multiplier"],
            server_fields=["ROUND_RESULT.winner", "matched_card"])]
