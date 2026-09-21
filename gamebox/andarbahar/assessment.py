"""Andar Bahar WebSocket security assessment orchestrator.

Runs discovery, capture, protocol mapping and every security test against a
configured target (default: the local vulnerable demo), then writes the report
set and returns a summary including the required final answer block.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import Confidence, Severity, severity_rank
from ..safety.controller import SafetyController
from .analysis import (ClientTrustAnalyzer, RandomnessAnalysis, SafeMutator,
                       ServerAuthorityTest, classify_field_trust)
from .capture import MessageCapture
from .discovery import WebSocketDiscovery
from .environment import EnvironmentPolicy
from .integrity import ReplayTester, RoundBindingTest, WalletIntegrity
from .protocol import ProtocolMapper
from .protocol_tests import AuthorizationTest, StateMachineTest, TransportSecurity
from .results import CONFIRMED, FAIL, PASS, SecurityResult
from .ws_client import SafeWebSocketClient

log = get_logger("ab.assessment")


class AndarBaharAssessment:
    def __init__(self, config: Config):
        self.config = config
        self.controller = SafetyController(config)
        self.policy = EnvironmentPolicy.from_name(config.environment)
        self.url = config.websocket.url
        self.origin = config.websocket.origin
        self.user_id = config.websocket.user_id
        self.victim_id = config.websocket.victim_user_id

    def run(self, out_dir: str | Path) -> dict:
        results: list[SecurityResult] = []
        target = WebSocketDiscovery.from_url(self.url, self.origin)
        protocol_map: dict = {"messages": {}, "graph": []}
        wallet_analysis: dict = {}
        handshake: dict = {}
        connected = False

        client = SafeWebSocketClient(self.url, self.controller, self.policy, origin=self.origin)
        try:
            client.connect()
            connected = True
            handshake = client.handshake
        except Exception as exc:
            log.warning("WS connect failed: %s", exc)

        if connected:
            cap = MessageCapture(client)
            rounds = cap.capture_rounds(self.user_id, count=3)
            protocol_map = ProtocolMapper().build(client.frames)

            # Always-safe analyses (static + read-only gameplay).
            results.append(RandomnessAnalysis().run(client, self.user_id, rounds=30))

            # Mutation/attack tests only run where SAFE_MUTATION is permitted
            # (DEMO/STAGING). In PRODUCTION these are skipped: the tool refuses
            # to modify game outcomes.
            if self.policy.allow_mutation:
                results.append(ServerAuthorityTest().run(client, self.user_id))
                results += SafeMutator().run(client, self.user_id)
                results.append(ReplayTester().run(client, self.user_id))
                results.append(RoundBindingTest().run(client, self.user_id, self.victim_id))
                wallet_result, wallet_analysis = WalletIntegrity().run(client, self.user_id)
                results.append(wallet_result)
                results += StateMachineTest().run(client, self.user_id)
                # Rebuild the protocol map now that SETTLE frames were captured,
                # then run the static client-trust classification over it.
                protocol_map = ProtocolMapper().build(client.frames)
                results += ClientTrustAnalyzer().run(protocol_map)
            else:
                log.info("environment '%s' is read-only: skipping mutation tests",
                         self.policy.environment)
            client.close()

            # Transport tests are read-only (connect only) and always run.
            results += TransportSecurity(self.url, self.controller, self.policy).run(handshake)
            # Authorization test sends a mutation, so gate it on the policy.
            if self.policy.allow_mutation:
                results.append(AuthorizationTest(self.url, self.controller, self.policy,
                                                 self.origin).run(self.user_id))

        summary = self._summarize(connected, protocol_map, results)
        self._write_reports(out_dir, target, handshake, protocol_map, wallet_analysis,
                            results, summary)
        return summary

    def _summarize(self, connected: bool, protocol_map: dict,
                   results: list[SecurityResult]) -> dict:
        def has_confirmed(name: str) -> bool:
            return any(name.lower() in r.test.lower()
                       and r.classification == CONFIRMED for r in results)

        client_controlled = any(
            r.classification == CONFIRMED and (
                "client-controlled game outcome" in r.test.lower()
                or "wallet/settlement integrity" in r.test.lower())
            for r in results)
        server_generates = "ROUND_RESULT" in protocol_map.get("messages", {})
        replay_fail = any(r.test == "Replay protection" and r.classification == FAIL
                          for r in results)
        binding_fail = any(r.test == "Round/session binding" and r.classification == CONFIRMED
                           for r in results)
        settlement_fail = any(r.classification in (FAIL, CONFIRMED)
                              and ("settlement" in r.test.lower() or "wallet" in r.test.lower()
                                   or "duplicate" in r.test.lower())
                              for r in results)

        if not connected:
            authority = "UNKNOWN"
        elif client_controlled:
            authority = "MIXED" if server_generates else "CLIENT-AUTHORITATIVE"
        else:
            authority = "SERVER-AUTHORITATIVE"

        crit = sum(1 for r in results if r.is_vuln and r.severity == Severity.CRITICAL)
        high = sum(1 for r in results if r.is_vuln and r.severity == Severity.HIGH)
        passed = sum(1 for r in results if r.classification == PASS)

        return {
            "connected": connected,
            "protocol_mapped": bool(protocol_map.get("messages")),
            "authority": authority,
            "game_result_server_authoritative": "NO" if client_controlled else (
                "YES" if connected else "UNKNOWN"),
            "client_controlled_result": "YES" if client_controlled else "NO",
            "replay_protection": "FAIL" if replay_fail else "PASS",
            "round_binding": "FAIL" if binding_fail else "PASS",
            "settlement_integrity": "FAIL" if settlement_fail else "PASS",
            "critical_findings": crit,
            "high_findings": high,
            "tests_passed": passed,
            "field_trust": classify_field_trust(protocol_map),
        }

    def final_block(self, s: dict) -> str:
        return (
            f"WEBSOCKET DISCOVERED:\n{'YES' if s['connected'] else 'NO'}\n\n"
            f"ANDAR BAHAR PROTOCOL MAPPED:\n{'YES' if s['protocol_mapped'] else 'NO'}\n\n"
            f"GAME RESULT SERVER-AUTHORITATIVE:\n{s['game_result_server_authoritative']}\n\n"
            f"CLIENT-CONTROLLED RESULT:\n{s['client_controlled_result']}\n\n"
            f"REPLAY PROTECTION:\n{s['replay_protection']}\n\n"
            f"ROUND BINDING:\n{s['round_binding']}\n\n"
            f"SETTLEMENT INTEGRITY:\n{s['settlement_integrity']}\n\n"
            f"CRITICAL FINDINGS:\n{s['critical_findings']}\n\n"
            f"HIGH FINDINGS:\n{s['high_findings']}\n\n"
            f"TESTS PASSED:\n{s['tests_passed']}"
        )

    # ---- report writing --------------------------------------------------
    def _write_reports(self, out_dir, target, handshake, protocol_map, wallet_analysis,
                       results, summary) -> None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)

        (out / "websocket-map.json").write_text(json.dumps({
            "target": target.to_dict(), "handshake": handshake,
            "environment_policy": self.policy.describe(),
        }, indent=2), encoding="utf-8")
        (out / "protocol-map.json").write_text(json.dumps(protocol_map, indent=2),
                                               encoding="utf-8")
        (out / "game-state-machine.json").write_text(json.dumps({
            "states": StateMachineTest.STATES,
            "invalid_transition_tests": [r.to_dict() for r in results
                                         if "transition" in r.test.lower()],
        }, indent=2), encoding="utf-8")
        (out / "wallet-analysis.json").write_text(json.dumps(wallet_analysis, indent=2),
                                                  encoding="utf-8")

        findings = []
        for i, r in enumerate(sorted(results, key=lambda x: severity_rank(x.severity)), 1):
            fid = "ANDAR-BAHAR-WS-001" if r.test == "Client-controlled game outcome" \
                else f"ANDAR-BAHAR-WS-{i:03d}"
            f = r.to_finding(fid)
            findings.append({"result": r.to_dict(), "finding": f.to_dict() if f else None})
        (out / "security-findings.json").write_text(json.dumps({
            "summary": summary, "results": [r.to_dict() for r in results],
            "findings": findings,
        }, indent=2), encoding="utf-8")

        (out / "report.md").write_text(self._markdown(target, handshake, protocol_map,
                                                      wallet_analysis, results, summary),
                                       encoding="utf-8")
        (out / "report.html").write_text(self._html(summary, results), encoding="utf-8")

    def _markdown(self, target, handshake, protocol_map, wallet_analysis, results, summary):
        L = ["# Andar Bahar WebSocket Security Assessment\n",
             f"**Target:** {target.url} | **Environment:** {self.policy.environment} | "
             f"**Overall:** {summary['authority']}\n",
             "## Final Determination\n", "```", self.final_block(summary), "```\n",
             "## WebSocket & Handshake\n",
             f"- URL: `{target.url}` (secure={target.secure})",
             f"- Origin sent: {handshake.get('origin_sent', '(none)')}",
             f"- Environment policy: {json.dumps(self.policy.describe())}\n",
             "## Protocol Map\n",
             "| Message | Direction | Server-gen | Sensitive fields |",
             "|---|---|---|---|"]
        for t, spec in protocol_map.get("messages", {}).items():
            L.append(f"| {t} | {spec['direction']} | {spec['server_generated']} | "
                     f"{', '.join(spec['sensitive_fields']) or '-'} |")
        L.append("\nGraph: " + " -> ".join(protocol_map.get("graph", [])) + "\n")

        L.append("## Field Trust Classification\n")
        for k, v in summary["field_trust"].items():
            L.append(f"- `{k}` = **{v}**")
        L.append("")

        L.append("## Security Results\n")
        L.append("| Test | Field | Classification | Severity | Observed |")
        L.append("|---|---|---|---|---|")
        for r in sorted(results, key=lambda x: severity_rank(x.severity)):
            L.append(f"| {r.test} | {r.field} | {r.classification} | {r.severity.value} | "
                     f"{r.observed} |")
        L.append("")

        L.append("## Wallet Analysis\n```")
        L.append(json.dumps(wallet_analysis, indent=2))
        L.append("```\n")

        crit = [r for r in results if r.classification == CONFIRMED and
                r.severity == Severity.CRITICAL]
        if crit:
            L.append("## Critical Finding\n```")
            r = crit[0]
            L += ["ANDAR-BAHAR-WS-001", "", "Title:", r.test, "", "Severity:", "CRITICAL", "",
                  "Component:", "Andar Bahar WebSocket", "", "Issue:", r.observed, "",
                  "Impact:", r.impact, "", "Recommended Fix:",
                  "The server must exclusively determine the game result and settlement. "
                  "Client messages must never be authoritative for winning side, cards, "
                  "payout or multiplier.", "```", ""]
        return "\n".join(L)

    def _html(self, summary, results):
        def esc(s):
            return html.escape(str(s))
        colors = {"CONFIRMED_VULNERABILITY": "#b00020", "FAIL": "#d9534f",
                  "POTENTIAL_VULNERABILITY": "#e0a800", "PASS": "#2a7"}
        rows = "".join(
            f"<tr><td>{esc(r.test)}</td><td>{esc(r.field)}</td>"
            f"<td style='color:{colors.get(r.classification, '#777')}'>{esc(r.classification)}</td>"
            f"<td>{esc(r.severity.value)}</td><td>{esc(r.observed)}</td></tr>"
            for r in sorted(results, key=lambda x: severity_rank(x.severity)))
        block = esc(self.final_block(summary)).replace("\n", "<br>")
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Andar Bahar WS Assessment</title><style>
 body{{font-family:system-ui,Arial,sans-serif;margin:24px;background:#0f1220;color:#e8e8f0}}
 table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #2a3050;
 padding:8px;text-align:left;font-size:13px}} th{{color:#9aa}}
 .box{{background:#1a1f36;border:1px solid #2a3050;border-radius:10px;padding:14px;margin:14px 0}}
</style></head><body>
<h1>Andar Bahar WebSocket Security Assessment</h1>
<div class="box"><b>Overall: {esc(summary['authority'])}</b><br><br>{block}</div>
<table><thead><tr><th>Test</th><th>Field</th><th>Classification</th><th>Severity</th>
<th>Observed</th></tr></thead><tbody>{rows}</tbody></table>
<p style="color:#9aa">Evidence redacted; assessment performed under authorization on TEST_COINS.</p>
</body></html>"""
