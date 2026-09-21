"""End-to-end Win-Integrity engine across the HTTP and WS demos."""
import tempfile
from pathlib import Path

from gamebox.core.config import Config
from gamebox.core.database import Database
from gamebox.discovery.crawler import Crawler
from gamebox.games.win_integrity import (CONF_SETTLE, WinIntegrityEngine)
from gamebox.http.client import SafeHTTPClient
from gamebox.safety.controller import SafetyController
from gamebox.safety.scope import ScopeManager


def _config(http_base, ws_url):
    return Config.from_dict({
        "target": {"name": "win-demo", "environment": "sandbox"},
        "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
        "environment": "demo",
        "base_urls": [http_base + "/"],
        "websocket": {"url": ws_url, "user_id": 1, "victim_user_id": 2},
        "testing": {"max_requests_per_second": 0, "accounts": [
            {"label": "A", "username": "alice", "password": "alice-test-pw"},
            {"label": "B", "username": "bob", "password": "bob-test-pw"},
        ]},
        "safety": {"allow_state_changes": True, "allow_financial_operations": True},
    })


def _run(http_base, ws_url, tmp):
    cfg = _config(http_base, ws_url)
    db = Database(Path(tmp) / "db.sqlite3")
    client = SafeHTTPClient(SafetyController(cfg), rps=0)
    for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
        db.upsert_endpoint(ep)
    result = WinIntegrityEngine(cfg, db).run(Path(tmp) / "wi")
    return cfg, db, result


def test_engine_flags_client_controlled_outcome(demo_server, demo_ws_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, result = _run(demo_server, demo_ws_server["url"], tmp)
        assert result["games_assessed"] >= 2
        assert result["can_client_influence_outcome_or_settlement"] == "YES"
        assert result["overall_verdict"] == CONF_SETTLE

        games = {g["game"]["name"]: g for g in result["game_reports"]}
        tp = games["Teen Patti"]
        assert tp["result_authority"] == "CLIENT_INPUT"
        assert tp["settlement_authority"] == "CLIENT_INPUT"
        assert tp["verdict"] in (CONF_SETTLE, "CONFIRMED CLIENT-CONTROLLED OUTCOME")

        ab = games["Andar Bahar"]
        assert ab["websocket"] is True
        assert ab["result_authority"] == "SERVER_AUTHORITATIVE"
        assert ab["settlement_authority"] == "CLIENT_INPUT"
        assert ab["replay_protection"] == "FAIL"
        db.close()


def test_reports_written(demo_server, demo_ws_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, result = _run(demo_server, demo_ws_server["url"], tmp)
        wi = Path(tmp) / "wi"
        for name in ("game-inventory.json", "win-integrity.json", "report.md", "report.html"):
            assert (wi / name).exists(), f"missing {name}"
        db.close()
