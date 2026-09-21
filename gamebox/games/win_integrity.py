"""Win-Integrity Assessment Engine.

Answers: "Can a client influence the game outcome or settlement without the
server independently validating it?" -- per game and overall -- by combining the
HTTP settlement/replay/race/authorization checks with the WebSocket outcome
analysis. TEST_COINS / authorized sandbox only.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import Config
from ..core.database import Database
from ..core.logger import get_logger
from ..core.models import Finding, Severity, severity_rank
from .game_inventory import GameInventory, GameRecord
from .settlement_analyzer import CLIENT_INPUT, SettlementAnalyzer
from .websocket_analyzer import WebSocketGameAnalyzer

log = get_logger("games.win_integrity")

# Final-question verdicts, worst first.
SECURE = "SECURE"
POTENTIAL = "POTENTIAL CLIENT TRUST ISSUE"
CONF_OUTCOME = "CONFIRMED CLIENT-CONTROLLED OUTCOME"
CONF_SETTLE = "CONFIRMED SETTLEMENT INTEGRITY FAILURE"
CONF_REPLAY = "CONFIRMED REPLAY VULNERABILITY"
CONF_RACE = "CONFIRMED RACE CONDITION"
_PRIORITY = [CONF_SETTLE, CONF_OUTCOME, CONF_REPLAY, CONF_RACE, POTENTIAL, SECURE]


def _worst(verdicts: list[str]) -> str:
    for v in _PRIORITY:
        if v in verdicts:
            return v
    return SECURE


@dataclass
class GameIntegrityReport:
    game: GameRecord
    architecture: str = ""
    result_authority: str = "UNKNOWN"
    settlement_authority: str = "UNKNOWN"
    websocket: bool = False
    wallet: str = ""
    replay_protection: str = "UNKNOWN"
    round_binding: str = "UNKNOWN"
    authorization: str = "UNKNOWN"
    randomness: str = "UNKNOWN"
    risk: str = "INFO"
    verdict: str = SECURE
    confirmed: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["game"] = self.game.to_dict()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class WinIntegrityEngine:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    def run(self, out_dir: str | Path) -> dict:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        endpoints = self.db.endpoints()
        inventory = GameInventory(self.config).discover(endpoints)

        reports: list[GameIntegrityReport] = []
        for game in inventory:
            if game.transport == "http":
                reports.append(self._assess_http(game))
            elif game.transport == "ws":
                reports.append(self._assess_ws(game, out / "andar-bahar"))

        overall = _worst([r.verdict for r in reports]) if reports else SECURE
        can_influence = overall != SECURE and overall != POTENTIAL

        result = {
            "target": self.config.target.name or "(unnamed)",
            "environment": self.config.environment,
            "overall_verdict": overall,
            "can_client_influence_outcome_or_settlement": "YES" if can_influence else (
                "POTENTIAL" if overall == POTENTIAL else "NO"),
            "games_assessed": len(reports),
            "game_reports": [r.to_dict() for r in reports],
        }
        self._write_reports(out, inventory, reports, result)
        return result

    # ---- HTTP game -------------------------------------------------------
    def _http_ctx(self):
        from ..analyzers.common import authenticate
        from ..http.client import SafeHTTPClient
        from ..safety.controller import SafetyController
        controller = SafetyController(self.config)
        secrets = [a.password for a in self.config.testing.accounts if a.password]
        client = SafeHTTPClient(controller, rps=self.config.testing.max_requests_per_second,
                                secret_values=secrets)
        base = self.config.base_urls[0] if self.config.base_urls else ""
        sessions = []
        for acct in self.config.testing.accounts:
            s = authenticate(client, base, acct)
            if s:
                sessions.append(s)
        return client, base, sessions

    def _assess_http(self, game: GameRecord) -> GameIntegrityReport:
        from ..analyzers.authorization import AuthorizationAnalyzer
        from .race_analyzer import GameRaceAnalyzer
        from .replay_analyzer import GameReplayAnalyzer

        from urllib.parse import urlparse

        def _path(u: str, default: str) -> str:
            return (urlparse(u).path or default) if u else default

        rep = GameIntegrityReport(game=game, architecture="HTTP REST", websocket=False,
                                  wallet=game.wallet_endpoint or "(none)",
                                  round_binding="N/A")
        client, base, sessions = self._http_ctx()
        user = next((s for s in sessions if (s.role or "") != "admin"), None)
        victim = next((s for s in sessions if s is not user), None)
        if not user:
            rep.result_authority = rep.settlement_authority = "UNKNOWN"
            return rep

        bet_path = _path(game.bet_endpoint, "/api/game/teenpatti/bet")
        settle_path = _path(game.settlement_endpoint, "/api/game/settlement")
        wallet_path = _path(game.wallet_endpoint, "/api/wallet/me")

        settlement = SettlementAnalyzer(client, base, bet_path, settle_path, wallet_path).run(user)
        rep.result_authority = settlement.result_authority
        rep.settlement_authority = settlement.settlement_authority
        rep.findings += settlement.findings

        replay = GameReplayAnalyzer(client, base, settle_path, wallet_path).run(user)
        rep.replay_protection = "PASS" if replay.protected else "FAIL"
        rep.findings += replay.findings

        race = GameRaceAnalyzer(client, base).run(user)
        rep.findings += race.findings
        race_fail = not race.consistent

        if victim:
            authz = AuthorizationAnalyzer(client, base).run(user, victim)
            rep.authorization = "FAIL" if authz else "PASS"
            rep.findings += authz
        else:
            rep.authorization = "N/A"

        rep.randomness = "CLIENT" if settlement.result_authority == CLIENT_INPUT else "UNKNOWN"
        self._finalize(rep, client_outcome=settlement.result_authority == CLIENT_INPUT,
                       settlement_fail=settlement.settlement_authority == CLIENT_INPUT
                       or settlement.duplicate_settlement,
                       replay_fail=not replay.protected, race_fail=race_fail)
        return rep

    # ---- WebSocket game --------------------------------------------------
    def _assess_ws(self, game: GameRecord, out_dir) -> GameIntegrityReport:
        rep = GameIntegrityReport(game=game, architecture="WebSocket realtime", websocket=True,
                                  wallet=game.wallet_endpoint or "(WS)")
        ws = WebSocketGameAnalyzer(self.config).run(out_dir)
        if not ws.connected:
            rep.result_authority = rep.settlement_authority = "UNKNOWN"
            rep.verdict = SECURE
            return rep
        rep.result_authority = ws.result_authority
        rep.settlement_authority = ws.settlement_authority
        rep.replay_protection = ws.replay_protection
        rep.round_binding = ws.round_binding
        rep.randomness = ws.randomness
        rep.authorization = "N/A"
        rep.findings += self._ws_findings(ws)
        self._finalize(rep, client_outcome=ws.client_controlled_result,
                       settlement_fail=ws.settlement_authority == "CLIENT_INPUT",
                       replay_fail=ws.replay_protection == "FAIL",
                       race_fail=False, round_binding_fail=ws.round_binding == "FAIL")
        return rep

    def _ws_findings(self, ws) -> list[Finding]:
        from ..core.models import Category, Confidence
        out = []
        if ws.client_controlled_result:
            out.append(Finding(
                title="WebSocket settlement is client-controlled (Andar Bahar)",
                category=Category.GAME, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description="The server dealt the round but accepted a client-supplied "
                "winner/payout at settlement.", endpoint="WS SETTLE", parameter="winner/payout",
                impact="A client can dictate settlement on a realtime game (TEST_COINS).",
                reproduction="See data/reports/win-integrity/andar-bahar/report.md.",
                remediation="Server must settle from its own authoritative result; ignore "
                "client winner/payout.", cwe="CWE-602",
                owasp="OWASP WSTG game integrity", module="win_integrity"))
        if ws.replay_protection == "FAIL":
            out.append(Finding(
                title="WebSocket settlement replayable (Andar Bahar)", category=Category.GAME,
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="A settlement frame could be replayed with no nonce/idempotency.",
                endpoint="WS SETTLE", impact="Captured settlement can be replayed to inflate "
                "balance.", reproduction="See andar-bahar report.",
                remediation="Add per-message nonce/idempotency and server-side dedupe.",
                cwe="CWE-294", owasp="OWASP WSTG replay", module="win_integrity"))
        if ws.round_binding == "FAIL":
            out.append(Finding(
                title="WebSocket round/session binding failure (Andar Bahar)",
                category=Category.GAME, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="A user could settle for another user's id.", endpoint="WS SETTLE",
                parameter="user_id", impact="Actions not bound to the authenticated session.",
                reproduction="See andar-bahar report.",
                remediation="Bind every message to the authenticated connection.",
                cwe="CWE-639", owasp="OWASP WSTG authorization", module="win_integrity"))
        return out

    def _finalize(self, rep: GameIntegrityReport, *, client_outcome: bool,
                  settlement_fail: bool, replay_fail: bool, race_fail: bool,
                  round_binding_fail: bool = False) -> None:
        confirmed = []
        if settlement_fail:
            confirmed.append(CONF_SETTLE)
        if client_outcome:
            confirmed.append(CONF_OUTCOME)
        if replay_fail:
            confirmed.append(CONF_REPLAY)
        if race_fail:
            confirmed.append(CONF_RACE)
        rep.confirmed = confirmed
        if confirmed:
            rep.verdict = _worst(confirmed)
            rep.risk = "CRITICAL" if (settlement_fail or client_outcome) else "HIGH"
        elif "CLIENT_INPUT" in (rep.result_authority, rep.settlement_authority):
            rep.verdict = POTENTIAL
            rep.risk = "MEDIUM"
        else:
            rep.verdict = SECURE
            rep.risk = "LOW"

    # ---- reports ---------------------------------------------------------
    def _write_reports(self, out: Path, inventory, reports, result) -> None:
        (out / "game-inventory.json").write_text(
            json.dumps([g.to_dict() for g in inventory], indent=2), encoding="utf-8")
        (out / "win-integrity.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        (out / "report.md").write_text(self._markdown(reports, result), encoding="utf-8")
        (out / "report.html").write_text(self._html(reports, result), encoding="utf-8")

    def _markdown(self, reports, result) -> str:
        L = ["# Win-Integrity Assessment\n",
             f"**Target:** {result['target']} | **Environment:** {result['environment']}\n",
             "## Final Answer\n", "```",
             "Can a client influence the game outcome or settlement without the server "
             "independently validating it?", "",
             f"ANSWER: {result['can_client_influence_outcome_or_settlement']}",
             f"OVERALL VERDICT: {result['overall_verdict']}", "```\n",
             "## Per-Game Win-Integrity\n"]
        for r in reports:
            L += [f"### {r.game.name} ({r.game.transport})",
                  f"- Architecture: {r.architecture}",
                  f"- Result Authority: {r.result_authority}",
                  f"- Settlement Authority: {r.settlement_authority}",
                  f"- WebSocket: {r.websocket}",
                  f"- Wallet: {r.wallet}",
                  f"- Replay Protection: {r.replay_protection}",
                  f"- Round Binding: {r.round_binding}",
                  f"- Authorization: {r.authorization}",
                  f"- Randomness: {r.randomness}",
                  f"- Risk: {r.risk}",
                  f"- Verdict: **{r.verdict}**\n"]

        all_findings = [f for r in reports for f in r.findings]
        confirmed = [f for f in all_findings if f.confidence.value == "CONFIRMED"]
        potential = [f for f in all_findings if f.confidence.value != "CONFIRMED"]
        L.append("## Confirmed Vulnerabilities\n")
        if not confirmed:
            L.append("_None._\n")
        for f in sorted(confirmed, key=lambda x: severity_rank(x.severity)):
            L += [f"### [{f.severity.value}] {f.title}", f"- Endpoint: `{f.endpoint}`",
                  f"- Impact: {f.impact}", f"- Remediation: {f.remediation}",
                  f"- CWE: {f.cwe} | OWASP: {f.owasp}\n"]
        L.append("## Potential Vulnerabilities\n")
        L.append("\n".join(f"- {f.title}" for f in potential) or "_None._")
        L.append("\n## Secure Controls (tested & passed)\n")
        secure = []
        for r in reports:
            if r.replay_protection == "PASS":
                secure.append(f"{r.game.name}: replay protection")
            if r.round_binding == "PASS":
                secure.append(f"{r.game.name}: round binding")
            if r.authorization == "PASS":
                secure.append(f"{r.game.name}: authorization")
            if "SERVER_AUTHORITATIVE" == r.settlement_authority:
                secure.append(f"{r.game.name}: server-authoritative settlement")
        L.append("\n".join(f"- {s}" for s in secure) or "_None._")
        L.append("")
        return "\n".join(L)

    def _html(self, reports, result) -> str:
        def esc(s):
            return html.escape(str(s))
        vcolor = {SECURE: "#2a7", POTENTIAL: "#e0a800"}
        rows = "".join(
            f"<tr><td>{esc(r.game.name)}</td><td>{esc(r.game.transport)}</td>"
            f"<td>{esc(r.result_authority)}</td><td>{esc(r.settlement_authority)}</td>"
            f"<td>{esc(r.replay_protection)}</td><td>{esc(r.round_binding)}</td>"
            f"<td>{esc(r.authorization)}</td>"
            f"<td style='color:{vcolor.get(r.verdict, '#b00020')};font-weight:700'>"
            f"{esc(r.verdict)}</td></tr>" for r in reports)
        ans = result["can_client_influence_outcome_or_settlement"]
        acolor = "#2a7" if ans == "NO" else ("#e0a800" if ans == "POTENTIAL" else "#b00020")
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Win-Integrity Assessment</title><style>
 body{{font-family:system-ui,Arial,sans-serif;margin:24px;background:#0f1220;color:#e8e8f0}}
 table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #2a3050;
 padding:8px;text-align:left;font-size:13px}} th{{color:#9aa}}
 .box{{background:#1a1f36;border:1px solid #2a3050;border-radius:10px;padding:16px;margin:14px 0}}
</style></head><body>
<h1>Win-Integrity Assessment</h1>
<div class="box"><b>Can a client influence outcome/settlement without server validation?</b><br>
<span style="font-size:22px;color:{acolor};font-weight:800">{esc(ans)}</span><br>
Overall verdict: {esc(result['overall_verdict'])} &middot; games assessed: {result['games_assessed']}</div>
<table><thead><tr><th>Game</th><th>Transport</th><th>Result Auth</th><th>Settlement Auth</th>
<th>Replay</th><th>Round Binding</th><th>Authorization</th><th>Verdict</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="color:#9aa">TEST_COINS only; evidence redacted; authorized assessment.</p>
</body></html>"""
