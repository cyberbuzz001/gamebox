from gamebox.core.config import Config
from gamebox.core.models import Category, Endpoint
from gamebox.games.game_inventory import GameInventory


def _cfg(ws=True):
    d = {"base_urls": ["http://127.0.0.1:5099/"],
         "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]}}
    if ws:
        d["websocket"] = {"url": "ws://127.0.0.1:8765"}
    return Config.from_dict(d)


def _endpoints():
    return [
        Endpoint(method="POST", url="http://127.0.0.1:5099/api/game/teenpatti/bet",
                 parameters=["bet_amount", "payout"], category=Category.BETTING),
        Endpoint(method="POST", url="http://127.0.0.1:5099/api/game/settlement",
                 parameters=["round_id"], category=Category.GAME),
        Endpoint(method="GET", url="http://127.0.0.1:5099/api/wallet/me",
                 category=Category.WALLET),
    ]


def test_http_and_ws_games_discovered():
    games = GameInventory(_cfg()).discover(_endpoints())
    names = {g.name for g in games}
    transports = {g.transport for g in games}
    assert "Teen Patti" in names
    assert "Andar Bahar" in names
    assert transports == {"http", "ws"}


def test_no_ws_when_unconfigured():
    games = GameInventory(_cfg(ws=False)).discover(_endpoints())
    assert all(g.transport == "http" for g in games)
    tp = next(g for g in games if g.name == "Teen Patti")
    assert "payout" in tp.client_fields
    assert tp.settlement_endpoint.endswith("/api/game/settlement")
