"""End-to-end: run discovery + analyzers against the local vulnerable demo."""
import threading

import pytest
from werkzeug.serving import make_server

from gamebox.analyzers.authorization import AuthorizationAnalyzer
from gamebox.analyzers.common import authenticate
from gamebox.analyzers.games import GameIntegrityAnalyzer
from gamebox.analyzers.wallet import WalletAnalyzer
from gamebox.core.config import Config
from gamebox.discovery.crawler import Crawler
from gamebox.http.client import BlockedRequest, SafeHTTPClient
from gamebox.safety.controller import SafetyController
from gamebox.safety.scope import ScopeManager
from tests.fixtures.demo_game.app import create_app


@pytest.fixture(scope="module")
def demo_server():
    app = create_app()
    srv = make_server("127.0.0.1", 0, app)  # port 0 => OS picks a free port
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _config(base):
    return Config.from_dict({
        "target": {"name": "demo", "environment": "sandbox"},
        "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
        "base_urls": [base + "/"],
        "testing": {"max_requests_per_second": 0, "accounts": [
            {"label": "A", "username": "alice", "password": "alice-test-pw"},
            {"label": "B", "username": "bob", "password": "bob-test-pw"},
        ]},
        "safety": {"allow_state_changes": True},
    })


def _client(cfg):
    ctrl = SafetyController(cfg)
    return SafeHTTPClient(ctrl, rps=0), ctrl


def test_discovery_finds_api_surface(demo_server):
    cfg = _config(demo_server)
    client, _ = _client(cfg)
    eps = Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls)
    urls = {e.url for e in eps}
    assert any("/api/wallet" in u for u in urls)
    assert any("/api/game" in u for u in urls)
    cats = {e.category.value for e in eps}
    assert "WALLET" in cats and "GAME" in cats


def test_wallet_replay_and_settlement(demo_server):
    cfg = _config(demo_server)
    client, _ = _client(cfg)
    sess = authenticate(client, demo_server, cfg.testing.accounts[0])
    assert sess and sess.token
    findings = WalletAnalyzer(client, demo_server).run(sess)
    titles = " ".join(f.title.lower() for f in findings)
    assert "bonus" in titles          # replayable bonus
    assert "settlement" in titles     # duplicate settlement


def test_client_controlled_payout(demo_server):
    cfg = _config(demo_server)
    client, _ = _client(cfg)
    sess = authenticate(client, demo_server, cfg.testing.accounts[0])
    findings = GameIntegrityAnalyzer(client, demo_server).run(sess)
    assert any("payout" in f.title.lower() for f in findings)
    assert all(f.confidence.value == "CONFIRMED" for f in findings)


def test_idor_between_two_accounts(demo_server):
    cfg = _config(demo_server)
    client, _ = _client(cfg)
    a = authenticate(client, demo_server, cfg.testing.accounts[0])
    b = authenticate(client, demo_server, cfg.testing.accounts[1])
    findings = AuthorizationAnalyzer(client, demo_server).run(a, b)
    assert any("idor" in f.title.lower() or "object-level" in f.title.lower()
               for f in findings)


def test_financial_operation_is_blocked(demo_server):
    # Even in the sandbox, a real withdrawal must be blocked by the safety gate.
    cfg = _config(demo_server)
    client, ctrl = _client(cfg)
    with pytest.raises(BlockedRequest):
        client.post(demo_server + "/api/wallet/withdraw", json_body={"amount": 1})
