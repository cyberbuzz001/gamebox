"""GAMEBOX command-line interface.

Commands:
    gamebox init                 scaffold config templates in ./config and .env
    gamebox config               show the resolved (redacted) configuration
    gamebox discover             read-only crawl -> populate endpoint database
    gamebox map                  print the application map
    gamebox scan [--module M]    run analyzers (safe by default)
    gamebox report               generate JSON/CSV/MD/HTML reports
    gamebox status               show current stats
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__
from .core.config import Config
from .core.database import Database
from .core.logger import configure, get_logger
from .core.scheduler import ALL_MODULES, DEFAULT_MODULES, Orchestrator
from .discovery.crawler import Crawler
from .http.client import SafeHTTPClient
from .reporting import report as report_mod
from .safety.controller import SafetyController
from .safety.scope import ScopeManager

log = get_logger("cli")

_CONFIG_TEMPLATE = "config/targets.example.yaml"
_ENV_TEMPLATE = ".env.example"


def _load(config_path: str) -> Config:
    cfg = Config.load(config_path)
    configure(cfg.log_level, Path(cfg.data_dir) / "logs" / "gamebox.log")
    return cfg


def _db(cfg: Config) -> Database:
    return Database(Path(cfg.data_dir) / "findings" / "gamebox.sqlite3")


def cmd_init(args: argparse.Namespace) -> int:
    dst = Path(args.output or "config/targets.yaml")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if Path(_CONFIG_TEMPLATE).exists() and not dst.exists():
        shutil.copy(_CONFIG_TEMPLATE, dst)
        print(f"Created {dst}")
    else:
        print(f"{dst} already exists or template missing; not overwriting.")
    if Path(_ENV_TEMPLATE).exists() and not Path(".env").exists():
        shutil.copy(_ENV_TEMPLATE, ".env")
        print("Created .env from .env.example (fill in credentials, never commit it).")
    print("Edit the config, set scope/accounts, then run: gamebox discover")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    print(f"Target:      {cfg.target.name} ({cfg.target.environment})")
    print(f"Base URLs:   {cfg.base_urls}")
    print(f"Domains:     {cfg.scope.domains}")
    print(f"API hosts:   {cfg.scope.api_hosts}")
    print(f"Excluded:    {cfg.scope.excluded_hosts}")
    print(f"Currency:    {cfg.testing.test_currency}")
    print(f"Accounts:    {[a.label for a in cfg.testing.accounts]}  (secrets hidden)")
    print("Safety policy:")
    print(f"  state_changes={cfg.safety.allow_state_changes} "
          f"financial={cfg.safety.allow_financial_operations} "
          f"destructive={cfg.safety.allow_destructive_tests}")
    print(f"  allowed classes: {sorted(c.value for c in cfg.safety.allowed_classes())}")
    # External tool configuration.
    ext = cfg.external
    tools = {
        "seclists": ext.seclists_path, "payloads": ext.payloads_path,
        "jwt_tool": ext.jwt_tool_path, "graphql-cop": ext.graphql_cop_path,
        "schemathesis": ext.schemathesis_path, "nuclei": ext.nuclei_path,
    }
    active = {k: v for k, v in tools.items() if v}
    if active:
        print("External tools:")
        for name, path in active.items():
            print(f"  {name}: {path}")
    else:
        print("External tools: (none configured — built-in checks only)")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    controller = SafetyController(cfg)
    client = SafeHTTPClient(controller, rps=cfg.testing.max_requests_per_second)
    crawler = Crawler(client, ScopeManager(cfg.scope))
    if not cfg.base_urls:
        print("No base_urls configured. Set target.base_urls in the config.", file=sys.stderr)
        return 2
    endpoints = crawler.crawl(cfg.base_urls)
    for ep in endpoints:
        db.upsert_endpoint(ep)
    print(f"Discovered {len(endpoints)} endpoints (safety: {controller.counters}).")
    db.close()
    return 0


def cmd_map(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    by_cat: dict[str, list] = {}
    for ep in db.endpoints():
        by_cat.setdefault(ep.category.value, []).append(ep)
    if not by_cat:
        print("No endpoints yet. Run: gamebox discover")
    for cat in sorted(by_cat):
        print(f"\n=== {cat} ({len(by_cat[cat])}) ===")
        for ep in by_cat[cat]:
            print(f"  {ep.method:5} {ep.url}")
    db.close()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    if not cfg.base_urls:
        print("No base_urls configured.", file=sys.stderr)
        return 2
    modules = args.module or DEFAULT_MODULES
    result = Orchestrator(cfg, db).run(modules)
    if not result["sessions"]:
        print("No test accounts authenticated. For the sandbox, enable "
              "safety.allow_state_changes and check credentials.", file=sys.stderr)
    print(f"Scan complete. {result['findings']} findings recorded.")
    print(f"  modules: {', '.join(result['modules'])}")
    print(f"  authenticated: {result['sessions'] or '(none)'}")
    print(f"  safety gate: {result['safety']}")
    db.close()
    return 0


def cmd_admin_sim(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    if not cfg.base_urls:
        print("No base_urls configured.", file=sys.stderr)
        return 2
    # Ensure there is an endpoint inventory for the surface discovery.
    if not db.endpoints():
        controller = SafetyController(cfg)
        client = SafeHTTPClient(controller, rps=cfg.testing.max_requests_per_second)
        for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
            db.upsert_endpoint(ep)

    result = Orchestrator(cfg, db).run(["admin_access"])
    assessment = db.get_artifact("admin_assessment") or {}

    print("=" * 60)
    print(assessment_text(assessment))
    print("=" * 60)
    print("\nSafety controls verification:")
    for c in assessment.get("safety_checks", []):
        status = "BLOCKED" if c.get("blocked") else "NOT BLOCKED"
        print(f"  [{status}] {c['operation']} ({c['layer']})")
    print(f"\nAuthorization matrix rows: {len(assessment.get('matrix', []))} "
          f"(see 'gamebox report' for the full table)")
    print(f"Findings recorded this run: {result['findings']}")
    db.close()
    return 0


def assessment_text(a: dict) -> str:
    if not a:
        return "ADMIN ACCESS SIMULATION\n(no assessment produced)"
    return (
        "ADMIN ACCESS SIMULATION\n\n"
        f"Initial Account:\n{a.get('initial_account', '?')}\n\n"
        f"Administrative Surface:\n{a.get('surface_count', 0)} endpoints discovered\n\n"
        f"Accessible Without Admin:\n{a.get('accessible_without_admin', 0)}\n\n"
        f"Potential Authorization Weaknesses:\n{a.get('potential_weaknesses', 0)}\n\n"
        f"Confirmed Privilege Boundary Failure:\n{a.get('confirmed_boundary_failures', 0)}\n\n"
        f"Administrative Data Modified:\n{a.get('admin_data_modified', 'NONE')}\n\n"
        f"Production Financial Operations:\n{a.get('production_financial_operations', 'NONE')}\n\n"
        f"Persistence Created:\n{a.get('persistence_created', 'NONE')}"
    )


def cmd_ab_ws(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    if not cfg.websocket.url:
        print("No websocket.url configured. Set websocket.url in the config.",
              file=sys.stderr)
        return 2
    from .andarbahar.assessment import AndarBaharAssessment
    out = args.output or str(Path(cfg.data_dir) / "reports" / "andar-bahar")
    assessment = AndarBaharAssessment(cfg)
    summary = assessment.run(out)
    print("=" * 60)
    print(assessment.final_block(summary))
    print("=" * 60)
    print(f"\nOverall determination: {summary['authority']}")
    print(f"Reports written to: {out}")
    for name in ("websocket-map.json", "protocol-map.json", "game-state-machine.json",
                 "wallet-analysis.json", "security-findings.json", "report.md", "report.html"):
        print(f"  {out}/{name}")
    return 0


def cmd_win_integrity(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    if not cfg.base_urls:
        print("No base_urls configured.", file=sys.stderr)
        return 2
    if not db.endpoints():
        controller = SafetyController(cfg)
        client = SafeHTTPClient(controller, rps=cfg.testing.max_requests_per_second)
        for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
            db.upsert_endpoint(ep)
    from .games.win_integrity import WinIntegrityEngine
    out = args.output or str(Path(cfg.data_dir) / "reports" / "win-integrity")
    result = WinIntegrityEngine(cfg, db).run(out)
    print("=" * 60)
    print("WIN-INTEGRITY ASSESSMENT")
    print("Can a client influence the game outcome or settlement without the")
    print("server independently validating it?")
    print(f"\n  ANSWER: {result['can_client_influence_outcome_or_settlement']}")
    print(f"  OVERALL VERDICT: {result['overall_verdict']}")
    print(f"  GAMES ASSESSED: {result['games_assessed']}")
    print("=" * 60)
    for r in result["game_reports"]:
        print(f"  {r['game']['name']:14} [{r['game']['transport']}]  "
              f"result={r['result_authority']:20} settlement={r['settlement_authority']:16} "
              f"-> {r['verdict']}")
    print(f"\nReports written to: {out}")
    for name in ("game-inventory.json", "win-integrity.json", "report.md", "report.html"):
        print(f"  {out}/{name}")
    db.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    out = args.output or str(Path(cfg.data_dir) / "reports")
    paths = report_mod.write_all(cfg, db, out)
    print("Reports written:")
    for kind, p in paths.items():
        print(f"  {kind:9} {p}")
    db.close()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    db = _db(cfg)
    stats = db.stats()
    print(f"Endpoints: {stats['endpoints']}")
    print(f"By category: {stats['endpoints_by_category']}")
    print(f"Findings: {stats['findings']}  by severity: {stats['findings_by_severity']}")
    db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gamebox", description="GAMEBOX Security Auditor")
    p.add_argument("--version", action="version", version=f"gamebox {__version__}")
    p.add_argument("-c", "--config", default="config/targets.yaml",
                   help="path to target config (default: config/targets.yaml)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="scaffold config templates")
    sp.add_argument("-o", "--output", help="config output path")
    sp.set_defaults(func=cmd_init)

    sub.add_parser("config", help="show resolved config").set_defaults(func=cmd_config)
    sub.add_parser("discover", help="read-only discovery").set_defaults(func=cmd_discover)
    sub.add_parser("map", help="print application map").set_defaults(func=cmd_map)

    sp = sub.add_parser("scan", help="run analyzers (safe by default)")
    sp.add_argument("--module", action="append", choices=ALL_MODULES, metavar="MODULE",
                    help="limit to module(s); repeatable. Choices: " + ", ".join(ALL_MODULES))
    sp.add_argument("--safe", action="store_true",
                    help="documentation flag: scanning is safe/opt-in by design")
    sp.set_defaults(func=cmd_scan)

    sub.add_parser("admin-sim",
                   help="run the Admin Access Simulation (read-only)").set_defaults(
                       func=cmd_admin_sim)

    sp = sub.add_parser("ab-ws", help="run the Andar Bahar WebSocket security assessment")
    sp.add_argument("-o", "--output", help="report output directory")
    sp.set_defaults(func=cmd_ab_ws)

    sp = sub.add_parser("win-integrity",
                        help="run the Win-Integrity engine across all games (HTTP + WS)")
    sp.add_argument("-o", "--output", help="report output directory")
    sp.set_defaults(func=cmd_win_integrity)

    sp = sub.add_parser("report", help="generate reports")
    sp.add_argument("-o", "--output", help="report output directory")
    sp.set_defaults(func=cmd_report)

    sub.add_parser("status", help="show stats").set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"Config not found: {exc}. Run 'gamebox init' first.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
