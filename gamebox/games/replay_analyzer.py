"""Module 6 - replay testing for a game's settlement/bonus (HTTP).

Wraps the generic ReplayTester to determine whether a sensitive game operation
can be processed twice. TEST_COINS only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..analyzers.common import AccountSession
from ..analyzers.replay import ReplayTester
from ..analyzers.wallet import WalletAnalyzer
from ..core.logger import get_logger
from ..core.models import Finding
from ..http.client import SafeHTTPClient

log = get_logger("games.replay")


@dataclass
class ReplayResult:
    protected: bool = True
    findings: list = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    def to_dict(self) -> dict:
        return {"replay_protection": "PASS" if self.protected else "FAIL",
                "findings": [f.to_dict() for f in self.findings]}


class GameReplayAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 settlement_path: str, wallet_path: str = "/api/wallet/me"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.settlement_path = settlement_path
        self.wallet_path = wallet_path

    def run(self, sess: AccountSession) -> ReplayResult:
        if not self.settlement_path:
            return ReplayResult(protected=True)
        wa = WalletAnalyzer(self.client, self.base, balance_path=self.wallet_path)
        tester = ReplayTester(self.client, lambda: wa._balance(sess))
        url = self.base + self.settlement_path
        res = tester.test("game settlement", "POST", url, headers=sess.headers(),
                          json_body={"round_id": "wi-replay-1", "result": "win"})
        if res is None:
            return ReplayResult(protected=True)
        findings = tester.as_finding(res, f"POST {self.settlement_path}", sess)
        for f in findings:
            f.module = "win_integrity"
        return ReplayResult(protected=not res.duplicate_processed, findings=findings)
