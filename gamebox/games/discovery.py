"""Game discovery (Phase 7).

Builds per-game metadata from the discovered endpoint inventory: which endpoints
look like actions vs settlement, and which fields appear client- vs
server-controlled. Produces GameProfile records and an informational finding
summarizing risk indicators.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Endpoint, Finding, Severity

log = get_logger("games.discovery")

_GAME_NAMES = ["teenpatti", "teen-patti", "rummy", "poker", "roulette", "dice",
               "crash", "slot", "blackjack", "baccarat", "jackpot", "spin"]
_CLIENT_FIELD_HINTS = ["bet_amount", "stake", "wager", "amount", "payout",
                       "win_amount", "multiplier", "result", "seed"]


@dataclass
class GameProfile:
    name: str
    action_endpoints: list[str] = field(default_factory=list)
    settlement_endpoints: list[str] = field(default_factory=list)
    client_fields: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


class GameDiscovery:
    def analyze(self, endpoints: list[Endpoint]) -> list[GameProfile]:
        profiles: dict[str, GameProfile] = {}
        for ep in endpoints:
            low = ep.url.lower()
            if ep.category not in (Category.GAME, Category.BETTING):
                if not any(g in low for g in _GAME_NAMES):
                    continue
            name = self._game_name(low)
            prof = profiles.setdefault(name, GameProfile(name=name))
            if any(k in low for k in ("settle", "settlement", "result", "payout")):
                prof.settlement_endpoints.append(ep.key())
            else:
                prof.action_endpoints.append(ep.key())
            for f in ep.parameters:
                if f in _CLIENT_FIELD_HINTS and f not in prof.client_fields:
                    prof.client_fields.append(f)
        for prof in profiles.values():
            self._score(prof)
        return list(profiles.values())

    @staticmethod
    def _game_name(url: str) -> str:
        for g in _GAME_NAMES:
            if g in url:
                return g.replace("-", "")
        m = re.search(r"/game/([a-z0-9\-]+)", url)
        return m.group(1) if m else "game"

    @staticmethod
    def _score(prof: GameProfile) -> None:
        if prof.settlement_endpoints:
            prof.risk_indicators.append("separate settlement endpoint (verify idempotency)")
        for f in ("payout", "win_amount", "multiplier", "result"):
            if f in prof.client_fields:
                prof.risk_indicators.append(f"client field '{f}' must be server-authoritative")
        if any(f in prof.client_fields for f in ("bet_amount", "stake", "wager")):
            prof.risk_indicators.append("client-controlled wager (validate server-side)")

    def as_findings(self, profiles: list[GameProfile]) -> list[Finding]:
        out: list[Finding] = []
        for p in profiles:
            if not p.risk_indicators:
                continue
            out.append(Finding(
                title=f"Game risk indicators detected: {p.name}",
                category=Category.GAME, severity=Severity.INFO, confidence=Confidence.SUSPECTED,
                description="Discovery flagged risk indicators for manual verification: "
                + "; ".join(p.risk_indicators) + ".",
                endpoint=", ".join(p.action_endpoints + p.settlement_endpoints) or p.name,
                impact="These characteristics commonly accompany game-integrity flaws; "
                "confirm with the game/wallet analyzers.",
                reproduction="Derived from the discovered endpoint inventory.",
                remediation="Ensure server-authoritative outcomes and idempotent settlement.",
                cwe="CWE-807 (Reliance on Untrusted Inputs)", owasp="API6:2023",
                module="game_discovery", evidence=[]))
        return out
