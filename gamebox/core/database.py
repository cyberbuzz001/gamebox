"""SQLite-backed storage for endpoints, findings and evidence."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import (
    Category, Confidence, Endpoint, Evidence, Finding, Severity, severity_rank,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    key TEXT PRIMARY KEY,
    method TEXT, url TEXT, parameters TEXT,
    authentication_required INTEGER, content_type TEXT, response_type TEXT,
    state_changing INTEGER, category TEXT,
    first_seen REAL, last_seen REAL, notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT, category TEXT, severity TEXT, confidence TEXT,
    description TEXT, endpoint TEXT, parameter TEXT, impact TEXT,
    reproduction TEXT, remediation TEXT, cwe TEXT, owasp TEXT,
    module TEXT, timestamp REAL, evidence TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, finding_id TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
    key TEXT PRIMARY KEY, data TEXT
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ---- endpoints -------------------------------------------------------
    def upsert_endpoint(self, ep: Endpoint) -> None:
        existing = self.conn.execute(
            "SELECT first_seen, parameters FROM endpoints WHERE key=?", (ep.key(),)
        ).fetchone()
        first_seen = ep.first_seen
        params = set(ep.parameters)
        if existing:
            first_seen = existing["first_seen"]
            params |= set(json.loads(existing["parameters"] or "[]"))
        self.conn.execute(
            """INSERT OR REPLACE INTO endpoints
               (key, method, url, parameters, authentication_required, content_type,
                response_type, state_changing, category, first_seen, last_seen, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ep.key(), ep.method.upper(), ep.url, json.dumps(sorted(params)),
                None if ep.authentication_required is None else int(ep.authentication_required),
                ep.content_type, ep.response_type, int(ep.state_changing),
                ep.category.value, first_seen, ep.last_seen, ep.notes,
            ),
        )
        self.conn.commit()

    def endpoints(self) -> list[Endpoint]:
        rows = self.conn.execute("SELECT * FROM endpoints ORDER BY category, url").fetchall()
        return [self._row_to_endpoint(r) for r in rows]

    @staticmethod
    def _row_to_endpoint(r: sqlite3.Row) -> Endpoint:
        auth = r["authentication_required"]
        return Endpoint(
            method=r["method"], url=r["url"],
            parameters=json.loads(r["parameters"] or "[]"),
            authentication_required=None if auth is None else bool(auth),
            content_type=r["content_type"], response_type=r["response_type"],
            state_changing=bool(r["state_changing"]),
            category=Category(r["category"]),
            first_seen=r["first_seen"], last_seen=r["last_seen"], notes=r["notes"] or "",
        )

    # ---- findings --------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, title, category, severity, confidence, description, endpoint,
                parameter, impact, reproduction, remediation, cwe, owasp, module,
                timestamp, evidence)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f.id, f.title, f.category.value, f.severity.value, f.confidence.value,
                f.description, f.endpoint, f.parameter, f.impact, f.reproduction,
                f.remediation, f.cwe, f.owasp, f.module, f.timestamp,
                json.dumps([e.to_dict() for e in f.evidence]),
            ),
        )
        for e in f.evidence:
            self.conn.execute(
                "INSERT OR REPLACE INTO evidence (id, finding_id, data) VALUES (?,?,?)",
                (e.id, f.id, json.dumps(e.to_dict())),
            )
        self.conn.commit()

    def findings(self) -> list[Finding]:
        rows = self.conn.execute("SELECT * FROM findings").fetchall()
        result = [self._row_to_finding(r) for r in rows]
        result.sort(key=lambda f: (severity_rank(f.severity), f.title))
        return result

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        ev = []
        for d in json.loads(r["evidence"] or "[]"):
            ev.append(Evidence(**d))
        return Finding(
            id=r["id"], title=r["title"], category=Category(r["category"]),
            severity=Severity(r["severity"]), confidence=Confidence(r["confidence"]),
            description=r["description"], endpoint=r["endpoint"], parameter=r["parameter"],
            impact=r["impact"], reproduction=r["reproduction"], remediation=r["remediation"],
            cwe=r["cwe"], owasp=r["owasp"], module=r["module"], timestamp=r["timestamp"],
            evidence=ev,
        )

    # ---- stats -----------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        eps = self.endpoints()
        finds = self.findings()
        by_cat: dict[str, int] = {}
        for ep in eps:
            by_cat[ep.category.value] = by_cat.get(ep.category.value, 0) + 1
        by_sev: dict[str, int] = {s.value: 0 for s in Severity}
        for f in finds:
            by_sev[f.severity.value] += 1
        return {
            "endpoints": len(eps),
            "endpoints_by_category": by_cat,
            "findings": len(finds),
            "findings_by_severity": by_sev,
        }

    # ---- artifacts (arbitrary JSON side-data, e.g. admin assessment) -----
    def set_artifact(self, key: str, data: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO artifacts (key, data) VALUES (?,?)",
            (key, json.dumps(data)))
        self.conn.commit()

    def get_artifact(self, key: str) -> Any:
        row = self.conn.execute("SELECT data FROM artifacts WHERE key=?", (key,)).fetchone()
        return json.loads(row["data"]) if row else None

    def close(self) -> None:
        self.conn.close()
