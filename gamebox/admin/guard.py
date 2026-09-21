"""Destructive-test guard for the admin module.

A defense-in-depth layer above the SafetyController. The admin assessment is
built to be read-only for discovery/matrix work; this guard makes that explicit
and refuses to construct admin write/delete/financial operations regardless of
the controller's policy.
"""
from __future__ import annotations

from ..core.models import RequestClass
from ..safety.classifier import classify

_READ_SAFE = {RequestClass.READ_ONLY, RequestClass.SAFE_TEST}


class GuardBlocked(RuntimeError):
    def __init__(self, method: str, url: str, rc: RequestClass):
        super().__init__(f"guard refused {rc.value} admin op: {method} {url}")
        self.request_class = rc


class DestructiveTestGuard:
    @staticmethod
    def classify(method: str, url: str, body: str | None = None) -> RequestClass:
        return classify(method, url, body)

    def is_read_safe(self, method: str, url: str, body: str | None = None) -> bool:
        return self.classify(method, url, body) in _READ_SAFE

    def is_destructive(self, method: str, url: str, body: str | None = None) -> bool:
        return self.classify(method, url, body) in {
            RequestClass.DESTRUCTIVE, RequestClass.FINANCIAL}

    def ensure_read_only(self, method: str, url: str, body: str | None = None) -> None:
        rc = self.classify(method, url, body)
        if rc not in _READ_SAFE:
            raise GuardBlocked(method, url, rc)
