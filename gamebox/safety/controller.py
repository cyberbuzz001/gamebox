"""Central safety controller -- the single gate every request passes through.

No scanner talks to the network directly; they all go through the SafeHTTPClient,
which asks this controller for authorization first. This centralization is the
core safety guarantee of the framework.

Default policy:
    READ_ONLY      = ALLOWED
    SAFE_TEST      = ALLOWED
    STATE_CHANGING = BLOCKED  (enable via safety.allow_state_changes)
    FINANCIAL      = BLOCKED  (enable via safety.allow_financial_operations)
    DESTRUCTIVE    = BLOCKED  (enable via safety.allow_destructive_tests)

Regardless of configuration, a hard deny-list blocks operations that must never
run against a live system.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.config import Config
from ..core.logger import get_logger
from ..core.models import RequestClass
from .classifier import classify
from .scope import ScopeManager

log = get_logger("safety")

# Substrings that indicate an operation we refuse to perform under ANY config,
# because it cannot be made safe by a scanner (real money / persistence / DoS).
_HARD_DENY = (
    "real-withdraw", "real_withdraw", "bank-transfer", "wire-transfer",
    "delete-account", "drop-database", "shutdown", "install-backdoor",
)


@dataclass
class Decision:
    allowed: bool
    request_class: RequestClass
    reason: str


class SafetyController:
    def __init__(self, config: Config):
        self.config = config
        self.scope = ScopeManager(config.scope)
        self.allowed_classes = config.safety.allowed_classes()
        self._blocked_count = 0
        self._allowed_count = 0

    def authorize(
        self,
        method: str,
        url: str,
        body: str | None = None,
        params: dict | None = None,
        *,
        declared: RequestClass | None = None,
    ) -> Decision:
        rc = classify(method, url, body, params, declared=declared)

        # 1. Scope: fail closed.
        if not self.scope.in_scope(url):
            return self._deny(rc, f"out of scope: {url}")

        # 2. Hard deny-list: never overridable.
        low = f"{method} {url} {body or ''}".lower()
        if any(tok in low for tok in _HARD_DENY):
            return self._deny(rc, "hard deny-list (never permitted)")

        # 3. Policy check.
        if rc not in self.allowed_classes:
            return self._deny(rc, f"{rc.value} blocked by policy (enable explicitly in config)")

        self._allowed_count += 1
        return Decision(True, rc, "permitted")

    def _deny(self, rc: RequestClass, reason: str) -> Decision:
        self._blocked_count += 1
        log.warning("BLOCKED [%s] %s", rc.value, reason)
        return Decision(False, rc, reason)

    @property
    def counters(self) -> dict[str, int]:
        return {"allowed": self._allowed_count, "blocked": self._blocked_count}
