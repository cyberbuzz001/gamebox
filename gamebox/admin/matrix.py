"""Authorization matrix.

For each discovered admin endpoint (GET only -- writes are never sent), records
the access result for three principals: anonymous, normal user (TEST_USER) and
admin (TEST_ADMIN). Only observed results are recorded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..http.client import SafeHTTPClient
from .discovery import AdminEndpoint
from .guard import DestructiveTestGuard

log = get_logger("admin.matrix")

ACCESS_ALLOWED = "ACCESS_ALLOWED"
ACCESS_DENIED = "ACCESS_DENIED"
AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
NOT_TESTED = "NOT_TESTED"


@dataclass
class MatrixRow:
    function: str
    endpoint: str
    anon: str = NOT_TESTED
    user: str = NOT_TESTED
    admin: str = NOT_TESTED

    def to_dict(self) -> dict:
        return self.__dict__


def _classify(status: int, text: str) -> str:
    if status == 200 and '"error"' not in (text or ""):
        return ACCESS_ALLOWED
    if status == 401:
        return AUTHENTICATION_REQUIRED
    if status == 403:
        return AUTHORIZATION_REQUIRED
    return ACCESS_DENIED


class AuthorizationMatrix:
    def __init__(self, client: SafeHTTPClient, base_url: str):
        self.client = client
        self.base = base_url.rstrip("/")
        self.guard = DestructiveTestGuard()

    def _probe(self, url: str, headers: Optional[dict]) -> str:
        try:
            resp, _ = self.client.get(url, headers=headers, capture=False)
        except Exception:
            return NOT_TESTED
        return _classify(resp.status_code, resp.text)

    def build(self, admin_endpoints: list[AdminEndpoint],
              user: Optional[AccountSession],
              admin: Optional[AccountSession]) -> list[MatrixRow]:
        rows: list[MatrixRow] = []
        for ep in admin_endpoints:
            # Only GET endpoints are exercised; writes are recorded as NOT_TESTED.
            if ep.method.upper() != "GET" or self.guard.is_destructive(ep.method, ep.url):
                rows.append(MatrixRow(ep.function, f"{ep.method} {ep.url}",
                                      NOT_TESTED, NOT_TESTED, NOT_TESTED))
                continue
            rows.append(MatrixRow(
                function=ep.function, endpoint=f"GET {ep.url}",
                anon=self._probe(ep.url, None),
                user=self._probe(ep.url, user.headers()) if user else NOT_TESTED,
                admin=self._probe(ep.url, admin.headers()) if admin else NOT_TESTED,
            ))
        return rows

    @staticmethod
    def accessible_without_admin(rows: list[MatrixRow]) -> list[MatrixRow]:
        return [r for r in rows if ACCESS_ALLOWED in (r.anon, r.user)]
