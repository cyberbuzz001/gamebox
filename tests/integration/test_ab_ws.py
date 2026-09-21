"""End-to-end Andar Bahar WebSocket assessment against the local vulnerable demo."""
import tempfile
from pathlib import Path

from gamebox.andarbahar.assessment import AndarBaharAssessment
from gamebox.core.config import Config


def _config(ws_url, environment="demo"):
    return Config.from_dict({
        "target": {"name": "ab-demo", "environment": "sandbox"},
        "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
        "environment": environment,
        "websocket": {"url": ws_url, "origin": "http://127.0.0.1:5099",
                      "user_id": 1, "victim_user_id": 2},
        "testing": {"max_requests_per_second": 0},
        "safety": {"allow_state_changes": True},
    })


def test_detects_all_five_issues(demo_ws_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(demo_ws_server["url"])
        summary = AndarBaharAssessment(cfg).run(Path(tmp))
        import json
        d = json.loads((Path(tmp) / "security-findings.json").read_text())
        vuln = [r for r in d["results"]
                if r["classification"] in ("FAIL", "CONFIRMED_VULNERABILITY")]
        titles = " || ".join(r["test"].lower() for r in vuln)

        assert "client-controlled game outcome" in titles      # 1
        assert "replay protection" in titles                   # 2
        assert "round/session binding" in titles               # 3
        assert "duplicate settlement" in titles                # 4
        assert "message-level authorization" in titles         # 5

        assert summary["connected"] is True
        assert summary["protocol_mapped"] is True
        assert summary["client_controlled_result"] == "YES"
        assert summary["game_result_server_authoritative"] == "NO"
        assert summary["replay_protection"] == "FAIL"
        assert summary["round_binding"] == "FAIL"
        assert summary["settlement_integrity"] == "FAIL"
        assert summary["critical_findings"] >= 1
        assert summary["authority"] == "MIXED"


def test_report_files_written(demo_ws_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(demo_ws_server["url"])
        AndarBaharAssessment(cfg).run(Path(tmp))
        for name in ("websocket-map.json", "protocol-map.json", "game-state-machine.json",
                     "wallet-analysis.json", "security-findings.json", "report.md",
                     "report.html"):
            assert (Path(tmp) / name).exists(), f"missing {name}"
        # No raw credential in any output file.
        blob = "".join((Path(tmp) / n).read_text(encoding="utf-8")
                       for n in ("security-findings.json", "report.md", "report.html"))
        assert "test-token" not in blob


def test_production_environment_refuses_mutation(demo_ws_server):
    # In production, mutation frames are refused, so no client-controlled outcome
    # can be confirmed and no game data is modified by mutation probes.
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(demo_ws_server["url"], environment="production")
        summary = AndarBaharAssessment(cfg).run(Path(tmp))
        assert summary["client_controlled_result"] == "NO"
        assert summary["critical_findings"] == 0
