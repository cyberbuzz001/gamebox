"""Unit tests for Game Security Lab extension modules: wallet_advanced, state_race, recon."""
from __future__ import annotations

from gamebox.analyzers.common import AccountSession
from gamebox.analyzers.wallet_advanced import AdvancedWalletAnalyzer
from gamebox.discovery.recon import ReconEngine
from gamebox.games.state_race import BetCancellationRaceAnalyzer
from gamebox.http.client import SafeHTTPClient
from gamebox.safety.controller import SafetyController
from gamebox.core.config import Config


class DummyResponse:
    def __init__(self, status_code: int = 200, json_data: dict = None, headers: dict = None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}

    def json(self):
        return self._json


def test_recon_headers_detection(monkeypatch):
    cfg = Config()
    controller = SafetyController(cfg)
    client = SafeHTTPClient(controller)

    def dummy_get(url, **kwargs):
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        return DummyResponse(200, {}, headers), None

    monkeypatch.setattr(client, "get", dummy_get)
    engine = ReconEngine(client)
    findings = engine.analyze_headers("http://127.0.0.1:5099")

    titles = [f.title for f in findings]
    assert any("Missing essential security headers" in t for t in titles)
    assert any("Server technology version disclosed" in t for t in titles)


def test_wallet_advanced_negative_bet(monkeypatch):
    cfg = Config()
    cfg.safety.allow_state_changes = True
    controller = SafetyController(cfg)
    client = SafeHTTPClient(controller)

    balances = [1000.0, 1100.0]
    call_count = 0

    def dummy_get(url, **kwargs):
        nonlocal call_count
        val = balances[min(call_count, len(balances) - 1)]
        call_count += 1
        return DummyResponse(200, {"balance": val}), None

    def dummy_post(url, **kwargs):
        return DummyResponse(200, {"balance": 1100.0}), None

    monkeypatch.setattr(client, "get", dummy_get)
    monkeypatch.setattr(client, "post", dummy_post)

    analyzer = AdvancedWalletAnalyzer(client, "http://127.0.0.1:5099")
    sess = AccountSession(label="TEST_USER", token="test_token")
    findings = analyzer.run(sess)

    assert len(findings) >= 1
    assert "negative bet amounts" in findings[0].title.lower()
