"""End-to-end admin-access simulation against the demo, using TEST_USER and
TEST_ADMIN accounts."""
import tempfile
from pathlib import Path

from gamebox.core.config import Config
from gamebox.core.database import Database
from gamebox.core.scheduler import Orchestrator
from gamebox.discovery.crawler import Crawler
from gamebox.http.client import SafeHTTPClient
from gamebox.safety.controller import SafetyController
from gamebox.safety.scope import ScopeManager


def _config(base):
    return Config.from_dict({
        "target": {"name": "admin-demo", "environment": "sandbox"},
        "scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
        "base_urls": [base + "/"],
        "testing": {"max_requests_per_second": 0, "accounts": [
            {"label": "A", "username": "alice", "password": "alice-test-pw"},
            {"label": "B", "username": "bob", "password": "bob-test-pw"},
            {"label": "ADMIN", "username": "admin", "password": "admin-test-pw"},
        ]},
        # state changes on (mass-assignment vector); destructive OFF so the
        # safety self-check can prove DELETE is blocked.
        "safety": {"allow_state_changes": True, "allow_financial_operations": False,
                   "allow_destructive_tests": False},
    })


def _run(base, tmp):
    cfg = _config(base)
    db = Database(Path(tmp) / "db.sqlite3")
    client = SafeHTTPClient(SafetyController(cfg), rps=0)
    for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
        db.upsert_endpoint(ep)
    Orchestrator(cfg, db).run(["admin_access"])
    return cfg, db, db.get_artifact("admin_assessment")


def test_admin_surface_and_confirmed_escalation(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, a = _run(demo_server, tmp)
        assert a is not None
        assert a["surface_count"] >= 5
        assert a["confirmed_boundary_failures"] >= 1
        assert a["accessible_without_admin"] >= 1

        titles = " || ".join(f.title.lower() for f in db.findings())
        assert "unauthenticated access to admin function" in titles
        assert "mass assignment reaches admin function" in titles
        assert "client-controlled role header" in titles
        assert "role claim is client-forgeable" in titles
        db.close()


def test_no_admin_data_modified_and_safety_blocks(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, a = _run(demo_server, tmp)
        assert a["admin_data_modified"] == "NONE"
        assert a["production_financial_operations"] == "NONE"
        assert a["persistence_created"] == "NONE"
        # Both safety layers must have blocked the destructive attempts.
        checks = {c["operation"]: c for c in a["safety_checks"]}
        assert checks["DELETE /api/admin/users/2"]["blocked"] is True
        assert checks["DELETE /api/admin/users/2"]["layer"] == "safety_controller"
        assert checks["POST /api/admin/wallet/adjust"]["blocked"] is True
        assert checks["POST /api/admin/wallet/adjust"]["layer"] == "guard"
        db.close()


def test_matrix_shows_working_boundary_and_admin_access(demo_server):
    with tempfile.TemporaryDirectory() as tmp:
        cfg, db, a = _run(demo_server, tmp)
        rows = {r["endpoint"]: r for r in a["matrix"]}
        settings = rows.get("GET " + demo_server + "/api/admin/settings")
        assert settings is not None
        # Properly protected endpoint: normal user denied, admin allowed.
        assert settings["user"] in ("AUTHORIZATION_REQUIRED", "ACCESS_DENIED")
        assert settings["admin"] == "ACCESS_ALLOWED"
        db.close()
