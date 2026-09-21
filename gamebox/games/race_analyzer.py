"""Module 7 - race-condition testing for game/wallet operations (HTTP).

Wraps the generic RaceTester to fire a bounded burst of concurrent identical
operations and detect duplicate application. TEST_COINS only.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..analyzers.common import AccountSession
from ..analyzers.race import RaceTester
from ..analyzers.wallet import WalletAnalyzer
from ..core.logger import get_logger
from ..http.client import SafeHTTPClient

log = get_logger("games.race")


@dataclass
class RaceResult:
    consistent: bool = True
    findings: list = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    def to_dict(self) -> dict:
        return {"race_state": "PASS" if self.consistent else "FAIL",
                "findings": [f.to_dict() for f in self.findings]}


class GameRaceAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 op_path: str = "/api/bonus/claim", unit_delta: float = 100,
                 wallet_path: str = "/api/wallet/me"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.op_path = op_path
        self.unit_delta = unit_delta
        self.wallet_path = wallet_path

    def run(self, sess: AccountSession) -> RaceResult:
        wa = WalletAnalyzer(self.client, self.base, balance_path=self.wallet_path)
        tester = RaceTester(self.client, lambda: wa._balance(sess))
        url = self.base + self.op_path
        res = tester.test("game operation", "POST", url, headers=sess.headers(),
                          json_body={}, expected_single_delta=self.unit_delta)
        if res is None:
            return RaceResult(consistent=True)
        findings = tester.as_finding(res, f"POST {self.op_path}")
        for f in findings:
            f.module = "win_integrity"
        return RaceResult(consistent=not res.multiple_applied, findings=findings)
