# Architecture

GAMEBOX is a modular, safety-first assessment framework. The guiding rule:
**no scanner talks to the network directly** — every request flows through the
`SafeHTTPClient`, which asks the `SafetyController` for permission first.

```
              +---------------------------+
              |          CLI              |  init/config/discover/map/scan/report
              +-------------+-------------+
                            |
        +-------------------+--------------------+
        |                   |                    |
   Discovery           Analyzers            Reporting
   (crawler)      (wallet/games/authz)   (json/csv/md/html)
        |                   |                    ^
        +---------+---------+                    |
                  v                              |
            SafeHTTPClient  ---- Evidence ------>+
                  |
                  v
            SafetyController  --- classify + scope + policy + hard-deny
                  |
                  v
              network (in-scope hosts only)

   Core: Config | Logger(+redaction) | Models | Database(SQLite)
```

## Components

- **Config** — `core/config.py`: YAML + `${ENV}` expansion, dataclasses,
  credentials from the environment only.
- **Scope Manager** — `safety/scope.py`: fail-closed host allow/deny, wildcards.
- **Authentication** — `analyzers/common.py`: logs in configured test accounts,
  yields `AccountSession` (token/user_id/wallet_id).
- **HTTP Client** — `http/client.py`: rate-limited, redacted, gated.
- **Discovery** — `discovery/crawler.py` + `classify.py`: read-only crawl,
  JS mining, endpoint categorization.
- **Endpoint / Finding / Evidence store** — `core/database.py` (SQLite).
- **Analyzers** — `analyzers/` (wallet, games, authorization, client_trust,
  replay, race), plus the security packages `api/`, `authentication/`, `admin/`,
  `payments/`, and `games/` (discovery + randomness).
- **Orchestrator** — `core/scheduler.py`: authenticates sessions, runs the
  requested modules in a safe order, stores findings. The CLI is a thin wrapper.
- **Report Generator** — `reporting/report.py` (JSON/CSV/MD/HTML + interactive
  `dashboard.html`) and `reporting/attack_chains.py` (multi-step correlation).
- **Safety Controller** — `safety/controller.py` (the central gate).
- **CLI** — `cli.py`. `dashboard.html` is the interactive dashboard.

### Module map

`core/scheduler.py` exposes `DEFAULT_MODULES` and `OPTIN_MODULES`. Each module is
a callable returning `list[Finding]`; the `api` module fans out to the seven
`gamebox/api/*` analyzers. Add a module by writing an analyzer and registering it
in `Orchestrator._registry`.

## Request lifecycle

1. An analyzer calls `client.post(url, json_body=..., declared=SAFE_TEST?)`.
2. `SafeHTTPClient` builds a body preview and calls `controller.authorize(...)`.
3. `SafetyController`:
   - `classify()` produces a `RequestClass` (most-dangerous-wins).
   - scope check (fail closed).
   - hard deny-list (never overridable).
   - policy check against `Config.safety.allowed_classes()`.
4. If allowed: rate-limit, send, wrap response, build **redacted** `Evidence`.
   If blocked: raise `BlockedRequest` — nothing leaves the tool.

## Extending

Add an analyzer under `gamebox/analyzers/`:

```python
class MyAnalyzer:
    def __init__(self, client, base_url):
        self.client, self.base = client, base_url.rstrip("/")

    def run(self, session):
        resp, ev = self.client.get(self.base + "/api/thing", headers=session.headers())
        # detect, attach evidence, return a list of Finding(...) objects
        return []
```

Register it in `cli.py:cmd_scan` and add a `--module` choice. Always go through
`self.client` so the safety gate and redaction apply.
