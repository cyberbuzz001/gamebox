"""Unit tests for the Worker Fleet and expanded Database Schema."""
from __future__ import annotations

import tempfile
from pathlib import Path

from gamebox.core.database import Database
from gamebox.workers import (
    SecurityModule,
    WorkerContext,
    ReconWorker,
    CrawlerWorker,
    ApiSecurityWorker,
    AuthWorker,
    AuthorizationWorker,
    GameIntegrityWorker,
    WalletIntegrityWorker,
    WebSocketWorker,
    RngWorker,
    ReportWorker,
    VerificationWorker,
)


def test_database_expanded_schema():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "test_expanded.sqlite3")
        cursor = db.conn.cursor()
        
        tables = [
            "users", "projects", "targets", "target_scopes", "test_accounts",
            "scan_profiles", "scan_jobs", "scan_results", "security_tests",
            "remediation", "verification_tests", "reports", "audit_logs"
        ]
        for tbl in tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}';")
            row = cursor.fetchone()
            assert row is not None, f"Expected table {tbl} was not found in schema"
        db.close()


def test_worker_fleet_interface():
    workers = [
        ReconWorker(),
        CrawlerWorker(),
        ApiSecurityWorker(),
        AuthWorker(),
        AuthorizationWorker(),
        GameIntegrityWorker(),
        WalletIntegrityWorker(),
        WebSocketWorker(),
        RngWorker(),
        ReportWorker(),
        VerificationWorker(),
    ]

    for w in workers:
        assert isinstance(w, SecurityModule)
        assert w.name
        assert w.version
        disc = w.discover("http://127.0.0.1:5099")
        assert isinstance(disc, list)
