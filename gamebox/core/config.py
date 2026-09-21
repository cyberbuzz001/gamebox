"""Configuration system.

Config is loaded from a YAML file and layered with environment variables.
Credentials are NEVER read from YAML committed to a repo -- they come from the
environment (see .env.example). YAML may reference ${ENV_VAR} placeholders.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import RequestClass

_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


@dataclass
class TargetConfig:
    name: str = ""
    environment: str = "staging"


@dataclass
class ScopeConfig:
    domains: list[str] = field(default_factory=list)
    api_hosts: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)


@dataclass
class Account:
    """A single authorized test account. Secrets come from the environment."""

    label: str = ""
    username: str = ""
    password: str = ""
    token: str = ""


@dataclass
class TestingConfig:
    test_currency: str = "TEST_COINS"
    accounts: list[Account] = field(default_factory=list)
    max_requests_per_second: float = 3.0


@dataclass
class SafetyConfig:
    allow_state_changes: bool = False
    allow_financial_operations: bool = False
    allow_destructive_tests: bool = False

    def allowed_classes(self) -> set[RequestClass]:
        allowed = {RequestClass.READ_ONLY, RequestClass.SAFE_TEST}
        if self.allow_state_changes:
            allowed.add(RequestClass.STATE_CHANGING)
        if self.allow_financial_operations:
            allowed.add(RequestClass.FINANCIAL)
        if self.allow_destructive_tests:
            allowed.add(RequestClass.DESTRUCTIVE)
        return allowed


@dataclass
class WebSocketConfig:
    url: str = ""
    origin: str = ""
    user_id: int = 1
    victim_user_id: int = 2


@dataclass
class ExternalToolsConfig:
    """Paths / flags for optional external security tools.

    Every field defaults to empty (tool not available). When empty, modules
    fall back to their built-in checks with no loss of core functionality.
    """

    seclists_path: str = ""            # local clone of danielmiessler/SecLists
    payloads_path: str = ""            # local clone of swisskyrepo/PayloadsAllTheThings
    jwt_tool_path: str = ""            # path to ticarpi/jwt_tool.py
    graphql_cop_path: str = ""         # path to graphql-cop entry point
    schemathesis_path: str = ""        # 'schemathesis' if pip-installed, else path
    nuclei_path: str = ""              # 'nuclei' if on PATH, else absolute path
    subprocess_timeout: int = 30       # seconds; applies to all subprocess calls


@dataclass
class Config:
    target: TargetConfig = field(default_factory=TargetConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    testing: TestingConfig = field(default_factory=TestingConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    websocket: WebSocketConfig = field(default_factory=WebSocketConfig)
    external: ExternalToolsConfig = field(default_factory=ExternalToolsConfig)
    base_urls: list[str] = field(default_factory=list)
    environment: str = "demo"
    data_dir: str = "data"
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw = _expand_env(raw)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        t = raw.get("target", {}) or {}
        s = raw.get("scope", {}) or {}
        te = raw.get("testing", {}) or {}
        sa = raw.get("safety", {}) or {}

        accounts = []
        for a in te.get("accounts", []) or []:
            accounts.append(Account(
                label=a.get("label", ""),
                username=a.get("username", ""),
                password=a.get("password", ""),
                token=a.get("token", ""),
            ))

        ws = raw.get("websocket", {}) or {}
        ex = raw.get("external", {}) or {}
        return cls(
            target=TargetConfig(name=t.get("name", ""), environment=t.get("environment", "staging")),
            websocket=WebSocketConfig(
                url=ws.get("url", ""), origin=ws.get("origin", ""),
                user_id=int(ws.get("user_id", 1)),
                victim_user_id=int(ws.get("victim_user_id", 2)),
            ),
            external=ExternalToolsConfig(
                seclists_path=ex.get("seclists_path", ""),
                payloads_path=ex.get("payloads_path", ""),
                jwt_tool_path=ex.get("jwt_tool_path", ""),
                graphql_cop_path=ex.get("graphql_cop_path", ""),
                schemathesis_path=ex.get("schemathesis_path", ""),
                nuclei_path=ex.get("nuclei_path", ""),
                subprocess_timeout=int(ex.get("subprocess_timeout", 30)),
            ),
            environment=raw.get("environment", "demo"),
            scope=ScopeConfig(
                domains=list(s.get("domains", []) or []),
                api_hosts=list(s.get("api_hosts", []) or []),
                excluded_hosts=list(s.get("excluded_hosts", []) or []),
            ),
            testing=TestingConfig(
                test_currency=te.get("test_currency", "TEST_COINS"),
                accounts=accounts,
                max_requests_per_second=float(te.get("max_requests_per_second", 3.0)),
            ),
            safety=SafetyConfig(
                allow_state_changes=bool(sa.get("allow_state_changes", False)),
                allow_financial_operations=bool(sa.get("allow_financial_operations", False)),
                allow_destructive_tests=bool(sa.get("allow_destructive_tests", False)),
            ),
            base_urls=list(raw.get("base_urls", []) or []),
            data_dir=raw.get("data_dir", "data"),
            log_level=raw.get("log_level", "INFO"),
        )

    def account(self, label: str) -> Account | None:
        for a in self.testing.accounts:
            if a.label == label:
                return a
        return None
