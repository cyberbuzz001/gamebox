"""Administrative attack-surface discovery.

Combines the discovered endpoint inventory with a curated set of
conventional admin paths, probed READ-ONLY (GET) within scope. Records every
admin-looking endpoint and maps it to an administrative function.

Enhanced with configurable wordlist loading:
- Loads admin paths from SecLists when external.seclists_path is configured
- Falls back to the built-in candidate list when SecLists is absent

Reference: danielmiessler/SecLists Discovery/Web-Content.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger
from ..core.models import Category, Endpoint
from ..http.client import BlockedRequest, SafeHTTPClient
from ..safety.scope import ScopeManager
from .guard import DestructiveTestGuard

log = get_logger("admin.discovery")

# Built-in conventional admin path candidates (never assumed to exist — probed
# read-only). This is the fallback when SecLists is not available.
_BUILTIN_CANDIDATES = [
    "/admin", "/administrator", "/management", "/staff", "/operator",
    "/backoffice", "/dashboard", "/control", "/console",
    "/api/admin", "/api/management", "/api/admin/users", "/api/admin/config",
    "/api/admin/settings", "/api/admin/games", "/api/admin/reports",
    "/api/admin/analytics", "/api/admin/wallet/adjustments",
]

# SecLists filenames to try (relative to the SecLists root).
_SECLISTS_ADMIN_FILES = [
    "Discovery/Web-Content/combined-admin-paths.txt",
    "Discovery/Web-Content/raft-small-directories.txt",
]

# Maximum paths to probe from an external wordlist (prevent excessive probing).
_MAX_EXTERNAL_PATHS = 200

_ADMIN_HINTS = ("admin", "administrator", "management", "manage", "staff",
                "operator", "backoffice", "control", "console")

# URL keyword -> administrative function label (for the authorization matrix).
_FUNCTION_MAP = [
    (("wallet/adjust", "adjust"), "Wallet adjustment"),
    (("users", "user-management"), "User management"),
    (("roles", "permission", "privilege"), "Role management"),
    (("config", "settings"), "Admin settings"),
    (("games", "game-config", "rtp"), "Game configuration"),
    (("reports", "analytics", "stats"), "Reports"),
    (("transactions", "withdraw", "deposit"), "Financial operations"),
]


@dataclass
class AdminEndpoint:
    method: str
    url: str
    function: str
    discovered_via: str
    status_anon: int | None = None

    def to_dict(self) -> dict:
        return self.__dict__


def _function_of(url: str) -> str:
    low = url.lower()
    for kws, label in _FUNCTION_MAP:
        if any(k in low for k in kws):
            return label
    return "Admin (other)"


class AdminSurfaceDiscovery:
    def __init__(self, client: SafeHTTPClient, base_url: str, scope: ScopeManager,
                 seclists_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.scope = scope
        self.guard = DestructiveTestGuard()
        self.seclists_path = seclists_path

    def _load_wordlist(self) -> list[str]:
        """Load admin path candidates from SecLists or fall back to built-in.

        Reference: danielmiessler/SecLists Discovery/Web-Content/*admin*.
        """
        if not self.seclists_path:
            return list(_BUILTIN_CANDIDATES)

        seclists_root = Path(self.seclists_path)
        if not seclists_root.is_dir():
            log.info("SecLists path '%s' not found; using built-in candidates",
                     self.seclists_path)
            return list(_BUILTIN_CANDIDATES)

        for rel_path in _SECLISTS_ADMIN_FILES:
            wl_file = seclists_root / rel_path
            if wl_file.is_file():
                try:
                    lines = wl_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    # Filter: only keep lines that look like admin paths.
                    paths = []
                    seen: set[str] = set()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Normalize: ensure leading slash.
                        if not line.startswith("/"):
                            line = "/" + line
                        # Only keep admin-relevant paths (keyword filter).
                        low = line.lower()
                        if any(h in low for h in _ADMIN_HINTS):
                            if line not in seen:
                                seen.add(line)
                                paths.append(line)
                    # Merge with built-in candidates (built-in first).
                    merged_seen: set[str] = set()
                    merged: list[str] = []
                    for p in _BUILTIN_CANDIDATES:
                        merged.append(p)
                        merged_seen.add(p)
                    for p in paths:
                        if p not in merged_seen:
                            merged.append(p)
                            merged_seen.add(p)
                    final = merged[:_MAX_EXTERNAL_PATHS]
                    log.info("loaded %d admin paths from SecLists (%s) + %d built-in",
                             len(final) - len(_BUILTIN_CANDIDATES), wl_file.name,
                             len(_BUILTIN_CANDIDATES))
                    return final
                except Exception as exc:
                    log.warning("failed to read SecLists file %s: %s", wl_file, exc)

        log.info("no suitable SecLists admin wordlist found; using built-in candidates")
        return list(_BUILTIN_CANDIDATES)

    def discover(self, endpoints: list[Endpoint]) -> list[AdminEndpoint]:
        found: dict[str, AdminEndpoint] = {}

        # 1. From the discovered inventory (crawler + JS mining).
        for ep in endpoints:
            low = ep.url.lower()
            if ep.category == Category.ADMIN or any(h in low for h in _ADMIN_HINTS):
                found[ep.url] = AdminEndpoint(
                    method=ep.method, url=ep.url, function=_function_of(ep.url),
                    discovered_via="inventory")

        # 2. Wordlist candidates, probed READ-ONLY within scope.
        candidates = self._load_wordlist()
        for path in candidates:
            url = self.base + path
            if url in found or not self.scope.in_scope(url):
                continue
            self.guard.ensure_read_only("GET", url)  # never send a write here
            try:
                resp, _ = self.client.get(url, capture=False)
            except BlockedRequest:
                continue
            except Exception:
                continue
            if resp.status_code != 404:
                found[url] = AdminEndpoint(
                    method="GET", url=url, function=_function_of(url),
                    discovered_via="probe", status_anon=resp.status_code)

        result = list(found.values())
        log.info("admin surface: %d endpoints", len(result))
        return result
