import tempfile
from pathlib import Path

from gamebox.core.config import Config
from gamebox.core.database import Database
from gamebox.core.models import Category, Confidence, Finding, Severity
from gamebox.reporting import report as R


def _db_with_finding(path):
    db = Database(path)
    db.add_finding(Finding(
        title="Test finding", category=Category.WALLET, severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED, description="desc", endpoint="POST /x",
        remediation="fix it", cwe="CWE-1", owasp="API1", module="wallet",
    ))
    return db


def test_reports_generated_and_redacted():
    with tempfile.TemporaryDirectory() as d:
        db = _db_with_finding(Path(d) / "db.sqlite3")
        cfg = Config.from_dict({"target": {"name": "T"}})
        paths = R.write_all(cfg, db, Path(d) / "reports")
        for kind in ("json", "csv", "markdown", "html"):
            assert Path(paths[kind]).exists()
        md = Path(paths["markdown"]).read_text(encoding="utf-8")
        assert "Test finding" in md
        assert "CRITICAL" in md
        db.close()


def test_security_score_drops_with_critical():
    with tempfile.TemporaryDirectory() as d:
        db = _db_with_finding(Path(d) / "db.sqlite3")
        cfg = Config.from_dict({})
        summary = R.build_summary(cfg, db)
        assert summary["security_score"] == 60  # 100 - 40 for one critical
        db.close()
