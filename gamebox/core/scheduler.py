"""Scan orchestrator.

Wires the safety controller, HTTP client, authenticated sessions and every
analyzer together, runs the requested modules in a safe order, stores findings,
and correlates attack chains. The CLI is a thin wrapper over this.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
import threading
from importlib.metadata import entry_points

from ..admin.admin_checks import AdminAnalyzer
from ..admin.simulation import AdminAccessSimulator
from ..analyzers.authorization import AuthorizationAnalyzer
from ..analyzers.client_trust import ClientTrustAnalyzer
from ..analyzers.common import AccountSession, authenticate
from ..analyzers.games import GameIntegrityAnalyzer
from ..analyzers.race import RaceTester
from ..analyzers.replay import ReplayTester
from ..analyzers.wallet import WalletAnalyzer
from ..api.graphql import GraphQLAnalyzer
from ..api.injection import InjectionAnalyzer
from ..api.misconfig import MisconfigAnalyzer
from ..api.rate_limit import RateLimitAnalyzer
from ..api.secrets import SecretsAnalyzer
from ..api.upload import UploadAnalyzer
from ..api.websocket import WebSocketAnalyzer
from ..authentication.auth_checks import AuthAnalyzer
from ..games.discovery import GameDiscovery
from ..games.randomness import RandomnessAnalyzer
from ..payments.payment_checks import PaymentAnalyzer
from .config import Config
from .database import Database
from .logger import get_logger
from .models import Finding

log = get_logger("scheduler")

DEFAULT_MODULES = [
    "wallet", "games", "randomness", "authorization", "api",
    "authentication", "admin_access", "payments", "game_discovery", "client_trust",
]
OPTIN_MODULES = ["admin", "replay", "race", "jwt_deep", "schema_fuzz", "wallet_advanced", "state_race", "recon"]
ALL_MODULES = DEFAULT_MODULES + OPTIN_MODULES


class ScanCancelled(Exception):
    """Raised when a cooperative scan cancellation is requested."""


AnalyzerFactory = Callable[["ScanContext"], Callable[[], list[Finding]]]
_PLUGIN_ANALYZERS: dict[str, AnalyzerFactory] = {}
_PLUGINS_LOADED = False


def register_analyzer(name: str, factory: AnalyzerFactory, *, default: bool = False) -> None:
    """Register a named analyzer factory for applications and plugins.

    Factories receive a :class:`ScanContext` and return a zero-argument runner.
    Registration is explicit and stays inside the same scope/safety-controlled
    orchestrator; plugins do not receive a raw shell or network client.
    """
    if name not in ALL_MODULES and name not in _PLUGIN_ANALYZERS:
        ALL_MODULES.append(name)
    _PLUGIN_ANALYZERS[name] = factory
    if default and name not in DEFAULT_MODULES:
        DEFAULT_MODULES.append(name)


def load_plugins() -> None:
    """Load installed ``gamebox.analyzers`` entry points once."""
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    for ep in entry_points().select(group="gamebox.analyzers"):
        try:
            plugin = ep.load()
            plugin(register_analyzer)
        except Exception as exc:
            log.warning("analyzer plugin %s failed to load: %s", ep.name, exc)


def available_modules() -> list[str]:
    load_plugins()
    return list(ALL_MODULES)


@dataclass
class ScanContext:
    config: Config
    db: Database
    client: object
    base_url: str
    sessions: list[AccountSession] = field(default_factory=list)

    @property
    def primary(self) -> Optional[AccountSession]:
        return self.sessions[0] if self.sessions else None

    @property
    def secondary(self) -> Optional[AccountSession]:
        return self.sessions[1] if len(self.sessions) > 1 else None

    @property
    def admin_session(self) -> Optional[AccountSession]:
        for s in self.sessions:
            if s.role == "admin" or s.label.upper() in ("ADMIN", "TEST_ADMIN"):
                return s
        return None

    @property
    def user_session(self) -> Optional[AccountSession]:
        for s in self.sessions:
            if s.role != "admin" and s.label.upper() not in ("ADMIN", "TEST_ADMIN"):
                return s
        return self.primary


class Orchestrator:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    def _build_client(self):
        from ..http.client import SafeHTTPClient
        from ..safety.controller import SafetyController
        controller = SafetyController(self.config)
        secrets = [a.password for a in self.config.testing.accounts if a.password]
        secrets += [a.token for a in self.config.testing.accounts if a.token]
        client = SafeHTTPClient(controller, rps=self.config.testing.max_requests_per_second,
                                secret_values=secrets)
        return client, controller

    def run(self, modules: Optional[list[str]] = None, *,
            progress_callback: Callable[[str, int, int], None] | None = None,
            cancel_event: threading.Event | None = None) -> dict:
        load_plugins()
        modules = modules or DEFAULT_MODULES
        base = self.config.base_urls[0] if self.config.base_urls else ""
        client, controller = self._build_client()

        sessions: list[AccountSession] = []
        for acct in self.config.testing.accounts:
            s = authenticate(client, base, acct, self.config.login_path)
            if s:
                sessions.append(s)
        ctx = ScanContext(self.config, self.db, client, base, sessions)

        registry = self._registry(ctx)
        total = 0
        total_modules = len(modules)
        for index, name in enumerate(modules, 1):
            if cancel_event and cancel_event.is_set():
                raise ScanCancelled()
            if progress_callback:
                progress_callback(name, index - 1, total_modules)
            fn = registry.get(name)
            if not fn:
                log.warning("unknown module: %s", name)
                continue
            try:
                findings = fn() or []
            except Exception as exc:  # a module error must not abort the scan
                log.warning("module %s errored: %s", name, exc)
                findings = []
            for f in findings:
                self.db.add_finding(f)
                total += 1
            log.info("module %s -> %d findings", name, len(findings))
            if progress_callback:
                progress_callback(name, index, total_modules)

        return {"findings": total, "safety": controller.counters,
                "sessions": [s.label for s in sessions],
                "modules": modules}

    def _registry(self, ctx: ScanContext) -> dict[str, Callable[[], list[Finding]]]:
        base = ctx.base_url
        client = ctx.client
        acct0 = self.config.testing.accounts[0] if self.config.testing.accounts else None

        def wallet():
            return WalletAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def games():
            return GameIntegrityAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def randomness():
            return RandomnessAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def authorization():
            if ctx.primary and ctx.secondary:
                return AuthorizationAnalyzer(client, base).run(ctx.primary, ctx.secondary)
            return []

        def api():
            out: list[Finding] = []
            ext = self.config.external
            out += MisconfigAnalyzer(client, base).run(ctx.primary)
            out += InjectionAnalyzer(client, base,
                                     payloads_path=ext.payloads_path).run(ctx.primary)
            victim_id = ctx.secondary.user_id if ctx.secondary else None
            out += GraphQLAnalyzer(client, base,
                                   graphql_cop_path=ext.graphql_cop_path).run(
                ctx.primary, victim_id)
            out += WebSocketAnalyzer(client, base).run()
            out += SecretsAnalyzer(client, base).run()
            if ctx.primary:
                out += UploadAnalyzer(client, base).run(ctx.primary)
            if acct0 and acct0.username:
                out += RateLimitAnalyzer(client, base).run(acct0.username)
            return out

        def authentication():
            if acct0 and acct0.username:
                return AuthAnalyzer(client, base).run(acct0.username)
            return []

        def admin():
            return AdminAnalyzer(client, base).run(ctx.primary)

        def admin_access():
            from ..safety.scope import ScopeManager
            ext = self.config.external
            sim = AdminAccessSimulator(client, base, ScopeManager(self.config.scope),
                                       seclists_path=ext.seclists_path,
                                       jwt_tool_path=ext.jwt_tool_path)
            findings, assessment = sim.run(ctx.user_session, ctx.admin_session,
                                           self.db.endpoints())
            self.db.set_artifact("admin_assessment", assessment.to_dict())
            return findings

        def payments():
            return PaymentAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def game_discovery():
            gd = GameDiscovery()
            return gd.as_findings(gd.analyze(self.db.endpoints()))

        def client_trust():
            return ClientTrustAnalyzer(client, base).run()

        def replay():
            if not ctx.primary:
                return []
            wa = WalletAnalyzer(client, base)
            tester = ReplayTester(client, lambda: wa._balance(ctx.primary))
            res = tester.test("bonus claim", "POST", base.rstrip("/") + "/api/bonus/claim",
                              headers=ctx.primary.headers(), json_body={})
            return tester.as_finding(res, "POST /api/bonus/claim", ctx.primary) if res else []

        def race():
            if not ctx.primary:
                return []
            wa = WalletAnalyzer(client, base)
            tester = RaceTester(client, lambda: wa._balance(ctx.primary))
            res = tester.test("bonus claim", "POST", base.rstrip("/") + "/api/bonus/claim",
                              headers=ctx.primary.headers(), json_body={},
                              expected_single_delta=100)
            return tester.as_finding(res, "POST /api/bonus/claim") if res else []

        def jwt_deep():
            """Run comprehensive JWT attack vectors (alg:none, confusion, cracking)."""
            if not ctx.user_session:
                return []
            from ..admin.session import SessionSecurity
            ext = self.config.external
            ss = SessionSecurity(client, base, jwt_tool_path=ext.jwt_tool_path)
            return ss.run(ctx.user_session)

        def schema_fuzz():
            """Run schemathesis-based API fuzzing against OpenAPI specs."""
            from ..api.schema_fuzzer import SchemaFuzzer
            ext = self.config.external
            return SchemaFuzzer(client, base,
                               schemathesis_path=ext.schemathesis_path).run()

        def wallet_advanced():
            from ..analyzers.wallet_advanced import AdvancedWalletAnalyzer
            return AdvancedWalletAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def state_race():
            from ..games.state_race import BetCancellationRaceAnalyzer
            return BetCancellationRaceAnalyzer(client, base).run(ctx.primary) if ctx.primary else []

        def recon():
            from ..discovery.recon import ReconEngine
            return ReconEngine(client).analyze_headers(base)


        builtins = {
            "wallet": wallet, "games": games, "randomness": randomness,
            "authorization": authorization, "api": api,
            "authentication": authentication, "admin": admin,
            "admin_access": admin_access, "payments": payments,
            "game_discovery": game_discovery, "client_trust": client_trust,
            "replay": replay, "race": race,
            "jwt_deep": jwt_deep, "schema_fuzz": schema_fuzz,
            "wallet_advanced": wallet_advanced, "state_race": state_race,
            "recon": recon,
        }
        builtins.update({name: factory(ctx) for name, factory in _PLUGIN_ANALYZERS.items()})
        return builtins

