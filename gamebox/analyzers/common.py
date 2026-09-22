"""Shared helpers for analyzers: authenticating configured test accounts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.config import Account
from ..core.logger import get_logger
from ..core.models import RequestClass
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("analyzers")


@dataclass
class AccountSession:
    label: str
    token: str = ""
    user_id: Optional[int] = None
    wallet_id: Optional[int] = None
    role: str = ""
    access_token: str = ""

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}


def authenticate(client: SafeHTTPClient, base_url: str, account: Account,
                 login_path: str | None = None) -> Optional[AccountSession]:
    """Log an account in against the demo/target and return a session.

    Login is a STATE_CHANGING operation, so this only succeeds when the
    operator has explicitly enabled state changes for the (sandbox) target.
    """
    if account.token:
        return AccountSession(label=account.label, token=account.token)
    url = base_url.rstrip("/") + (login_path or "/api/auth/login")
    try:
        resp, _ = client.post(
            url, json_body={"username": account.username, "password": account.password}
        )
    except BlockedRequest as b:
        log.warning("login blocked for %s: %s", account.label, b.decision.reason)
        return None
    except Exception as exc:
        log.warning("login failed for %s: %s", account.label, exc)
        return None
    if resp.status_code != 200:
        log.warning("login rejected for %s (%s)", account.label, resp.status_code)
        return None
    body = resp.json() or {}
    return AccountSession(
        label=account.label,
        token=body.get("token", ""),
        user_id=body.get("user_id"),
        wallet_id=body.get("wallet_id"),
        role=body.get("role", ""),
        access_token=body.get("access_token", ""),
    )
