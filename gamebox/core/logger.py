"""Structured logging with automatic secret redaction.

Every log record passes through RedactingFilter so that tokens, passwords,
cookies and similar secrets never reach the console or log files.
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Iterable

# Patterns whose *values* must be masked wherever they appear in text.
_REDACT_KEYS = [
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "authorization", "auth", "cookie", "set-cookie", "session", "sessionid",
    "api_key", "apikey", "x-api-key", "secret", "client_secret", "private_key",
    "card", "cardnumber", "cvv", "pan", "ssn", "otp",
]

# key: value   /   "key": "value"   /   key=value  (best-effort, non-greedy).
# The trailing \w* lets compound keys match too (password_hash, jwt_secret,
# api_key_id, ...), so their values are redacted as well.
_KV_PATTERN = re.compile(
    r'(?i)(["\']?(?:' + "|".join(re.escape(k) for k in _REDACT_KEYS) + r')\w*["\']?\s*[:=]\s*)'
    r'(["\']?)([^"\'\s,;&}]+)(\2)'
)
# Bearer tokens and well-known secret value shapes.
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]+)")
_SECRET_VALUE_PATTERNS = [
    re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{4,}"),   # Stripe secret keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),          # GitHub tokens
]

_MASK = "***REDACTED***"


def redact(text: str, extra_values: Iterable[str] | None = None) -> str:
    """Return *text* with known secret shapes masked.

    ``extra_values`` lets callers mask specific live values (e.g. the current
    session token) even when they don't match a generic pattern.
    """
    if not text:
        return text
    # Bearer first: otherwise the key=value rule masks only the word "Bearer"
    # and leaves the token itself in place.
    out = _BEARER_PATTERN.sub(lambda m: f"{m.group(1)}{_MASK}", text)
    out = _KV_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{_MASK}{m.group(4)}", out)
    for pat in _SECRET_VALUE_PATTERNS:
        out = pat.sub(_MASK, out)
    if extra_values:
        for val in extra_values:
            if val and len(val) >= 6:
                out = out.replace(val, _MASK)
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of *headers* with sensitive header values masked."""
    safe: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k.lower() in _REDACT_KEYS:
            safe[k] = _MASK
        else:
            safe[k] = redact(str(v))
    return safe


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = redact(str(record.getMessage()))
            record.args = ()
        except Exception:  # never let logging redaction crash the app
            pass
        return True


_CONFIGURED = False


def configure(level: str = "INFO", log_file: str | Path | None = None) -> None:
    global _CONFIGURED
    root = logging.getLogger("gamebox")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler(stream=sys.stderr)
    console.setFormatter(fmt)
    console.addFilter(RedactingFilter())
    root.addHandler(console)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(RedactingFilter())
        root.addHandler(fh)

    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure()
    return logging.getLogger(f"gamebox.{name}")
