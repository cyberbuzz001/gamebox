"""Full end-to-end scan of the demo via the Orchestrator, covering every module,
attack-chain correlation, report generation and redaction."""
import tempfile
from pathlib import Path

from gamebox.core.config import Config
from gamebox.core.database import Database
from gamebox.core.scheduler import ALL_MODULES, Orchestrator
from gamebox.reporting import report as R


def _config(base):
    return Config.from_dict({
        "target": {"name": "demo-full", "environment": "sandbox"},
        "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
        "base_urls": [base + "/"],
        "testing": {"max_requests_per_second": 0, "accounts": [
            {"label": "A", "username": "alice", "password": "alice-test-pw"},
            {"label": "B", "username": "bob", "password": "bob-test-pw"},
        ]},
        "safety": {"allow_state_changes": True, "allow_financial_operations": True},
    })


def _run(base, tmp):
    cfg = _config(base)
    db = Database(Path(tmp) / "db.sqlite3")
    # Discover first so game_discovery has endpoints.
    from gamebox.discovery.crawler import Crawler
    from gamebox.http.client import SafeHTTPClient
    from gamebox.safety.controller import SafetyController
    from gamebox.safety.scope import ScopeManager
    client = SafeHTTPClient(SafetyController(cfg), rps=0)
    for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
        db.upsert_endpoint(ep)
    result = Orchestrator(cfg, db).run(ALL_MODULES)
    return cfg, db, result




def test_full_scan_covers_all_modules(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, result = _run(demo_server, tmp)
        findings = db.findings()
        titles = " || ".join(f.title.lower() for f in findings)
        modules = {f.module for f in findings}

        # Modules that must have produced findings against the demo.
        for m in ["wallet", "games", "authorization", "api", "authentication",
                  "admin", "payments", "randomness"]:
            assert m in modules, f"expected findings from module {m}; got {modules}"

        # Representative confirmed weaknesses across the OWASP API Top 10.
        for needle in ["idor", "reflected cross-site", "sql injection",
                       "path traversal", "permissive cors", "excessive data",
                       "mass assignment", "graphql introspection", "unrestricted file",
                       "secret exposed", "broken function-level", "webhook",
                       "username enumeration", "password reset", "rate limiting",
                       "client-controlled", "duplicate settlement", "replayable bonus",
                       "not server-authoritative"]:
            assert needle in titles, f"missing expected finding: {needle}"

        db.close()


def test_attack_chains_and_reports(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, result = _run(demo_server, tmp)

        chains = R.chains(db)
        assert chains, "expected at least one correlated attack chain"
        names = {c["name"] for c in chains}
        assert "Unauthorized balance inflation" in names

        paths = R.write_all(cfg, db, Path(tmp) / "reports")
        for kind in ("json", "csv", "markdown", "html", "dashboard"):
            assert Path(paths[kind]).exists()

        # Redaction: no raw fake secret and no bearer tokens leak into reports.
        blob = Path(paths["json"]).read_text(encoding="utf-8") + \
            Path(paths["dashboard"]).read_text(encoding="utf-8")
        assert "demo0123456789abcdef0000" not in blob
        assert "REDACTED" in blob
        db.close()


def test_severity_counts_present(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, result = _run(demo_server, tmp)
        summary = R.build_summary(cfg, db)
        sev = summary["findings_by_severity"]
        assert sev["CRITICAL"] >= 2 and sev["HIGH"] >= 3
        db.close()
