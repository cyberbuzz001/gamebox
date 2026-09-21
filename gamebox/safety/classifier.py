"""Request risk classifier.

Maps an outbound HTTP request to a RequestClass so the SafetyController can
decide whether it is permitted. Conservative by design: when in doubt, escalate
to the more dangerous class rather than the safer one.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core.models import RequestClass

_TOKEN_RE = re.compile(r"[a-z0-9]+")

_READ_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_DESTRUCTIVE_METHODS = {"DELETE"}

# Keyword -> class. Order of checks in classify() matters (most dangerous first).
_DESTRUCTIVE_KW = ("delete", "destroy", "remove", "wipe", "drop", "purge", "reset")
# Real money-movement keywords. Note: "payout"/"win_amount" are game-result
# fields (handled as STATE_CHANGING game logic), NOT money movement, so they are
# intentionally absent here; the broad token "pay" is avoided (it matches
# "player", "payout", ...). "payment" remains for payment/checkout flows.
_FINANCIAL_KW = (
    "withdraw", "withdrawal", "cashout", "cash-out", "deposit",
    "transfer", "payment", "topup", "top-up", "recharge", "redeem",
    "bank", "upi", "wallet/send",
)
_STATE_KW = (
    "bet", "stake", "wager", "bonus", "claim", "settle", "settlement", "spin",
    "play", "buy", "create", "update", "edit", "set", "add", "apply", "refund",
    "cancel", "confirm", "register", "logout",
)


def _haystack(url: str, body: str | None, params: dict | None) -> tuple[str, set[str]]:
    """Return (raw lowercased text, set of alphanumeric tokens).

    Keyword matching is token-based to avoid substring false positives
    (e.g. the state keyword 'set' must not match the path segment 'settings').
    """
    parsed = urlparse(url)
    parts = [parsed.path.lower(), (parsed.query or "").lower()]
    if body:
        parts.append(str(body).lower())
    if params:
        parts.append(" ".join(f"{k}={v}" for k, v in params.items()).lower())
    raw = " ".join(parts)
    return raw, set(_TOKEN_RE.findall(raw))


def _match(keywords, raw: str, tokens: set[str]) -> bool:
    """A keyword matches as a whole token when alphanumeric; keywords that
    contain separators (e.g. 'cash-out', 'wallet/send') fall back to substring."""
    for k in keywords:
        if k.isalnum():
            if k in tokens:
                return True
        elif k in raw:
            return True
    return False


def classify(
    method: str,
    url: str,
    body: str | None = None,
    params: dict | None = None,
    *,
    declared: RequestClass | None = None,
) -> RequestClass:
    """Classify a request.

    ``declared`` lets a scanner assert that a crafted probe is a controlled
    SAFE_TEST (e.g. a bounded TEST_COINS action against a sandbox). A declared
    SAFE_TEST is only honoured when the request would not otherwise be
    FINANCIAL or DESTRUCTIVE -- those always win.
    """
    method = method.upper()
    raw, tokens = _haystack(url, body, params)

    if method in _DESTRUCTIVE_METHODS or _match(_DESTRUCTIVE_KW, raw, tokens):
        return RequestClass.DESTRUCTIVE
    if _match(_FINANCIAL_KW, raw, tokens):
        return RequestClass.FINANCIAL

    if declared == RequestClass.SAFE_TEST:
        return RequestClass.SAFE_TEST

    state = _match(_STATE_KW, raw, tokens)
    if method in _READ_METHODS and not state:
        return RequestClass.READ_ONLY
    if state or method not in _READ_METHODS:
        return RequestClass.STATE_CHANGING
    return RequestClass.READ_ONLY
