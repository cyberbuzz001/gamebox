"""Scope enforcement: only authorized hosts may be contacted."""
from __future__ import annotations

from urllib.parse import urlparse

from ..core.config import ScopeConfig


class ScopeError(RuntimeError):
    """Raised when a request targets a host outside the authorized scope."""


class ScopeManager:
    def __init__(self, scope: ScopeConfig):
        self.allowed = {h.lower().strip() for h in (scope.domains + scope.api_hosts) if h.strip()}
        self.excluded = {h.lower().strip() for h in scope.excluded_hosts if h.strip()}

    @staticmethod
    def _host(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def _matches(self, host: str, patterns: set[str]) -> bool:
        for p in patterns:
            if p.startswith("*."):
                if host == p[2:] or host.endswith(p[1:]):
                    return True
            elif host == p:
                return True
        return False

    def in_scope(self, url: str) -> bool:
        host = self._host(url)
        if not host:
            return False
        if self._matches(host, self.excluded):
            return False
        if not self.allowed:  # empty allow-list => nothing in scope (fail closed)
            return False
        return self._matches(host, self.allowed)

    def enforce(self, url: str) -> None:
        if not self.in_scope(url):
            raise ScopeError(f"Out-of-scope host for URL: {url}")
