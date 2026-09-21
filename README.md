# GAMEBOX Security Auditor

A **safety-first, authorized** black-box security assessment framework for gaming
platforms — sports betting, casino, Teen Patti / poker / rummy, crash & slot
games, virtual-coin wallets, bonus/reward systems and payment integrations.

It ships with a **local, intentionally-vulnerable demo target** (synthetic
`TEST_COINS`, `127.0.0.1` only) so you can exercise the whole pipeline safely,
in the tradition of OWASP Juice Shop / DVWA.

> ⚠️ **Authorized use only.** Run the scanner exclusively against systems you
> have explicit, written permission to test. Real deposits, withdrawals,
> payments, data deletion and persistence are blocked by design and must never
> be enabled against a live system.

---

## 1. What it does

```
DEMO / AUTHORIZED TARGET
        │
        ▼
   DISCOVERY  ──►  APPLICATION MAP  ──►  ANALYZERS  ──►  FINDINGS  ──►  REPORT
 (read-only crawl)   (categorized)     (wallet/games/    (evidence)   (JSON/CSV/
                                        authorization)                 MD/HTML)
```

Every outbound request passes through a **central safety controller** that
classifies it (`READ_ONLY` / `SAFE_TEST` / `STATE_CHANGING` / `FINANCIAL` /
`DESTRUCTIVE`), enforces **scope**, and blocks anything above your configured
policy. Financial and destructive operations are blocked *even when* state
changes are enabled, and a hard deny-list can never be overridden.

## 2. Architecture

See [docs/architecture.md](docs/architecture.md). In short:

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Core | `gamebox/core` | config, logging+redaction, models, SQLite store, scan orchestrator |
| Safety | `gamebox/safety` | request classifier, scope manager, controller (the gate) |
| Transport | `gamebox/http` | `SafeHTTPClient` — the only path to the network |
| Discovery | `gamebox/discovery` | read-only crawler + endpoint categorization |
| Analyzers | `gamebox/analyzers` | wallet, game-integrity, authorization (BOLA/IDOR), client-trust, replay, race |
| API | `gamebox/api` | misconfig/CORS/headers, injection family, GraphQL, WebSocket, rate-limit, upload, secrets |
| Auth | `gamebox/authentication` | enumeration, insecure password reset |
| Admin | `gamebox/admin` | admin discovery + broken function-level authorization |
| Payments | `gamebox/payments` | webhook signature bypass + replay (financial, opt-in) |
| Games | `gamebox/games` | game discovery + randomness/RNG authority |
| Reporting | `gamebox/reporting` | JSON / CSV / Markdown / HTML + interactive dashboard + attack chains |
| CLI | `gamebox/cli.py` | `init / config / discover / map / scan / report / status` |

### Scan modules

Default (`gamebox scan`): `wallet`, `games`, `randomness`, `authorization`, `api`,
`authentication`, `admin_access`, `payments`, `game_discovery`, `client_trust`.
Opt-in (via `--module`): `admin` (basic FLA), `replay`, `race`. The `payments`
module only runs when `allow_financial_operations` is enabled for an authorized
sandbox.

### Administrative-access module (`admin_access`)

Determines whether a normal user can reach administrative functionality. It runs
read-only admin-surface discovery, builds a **normal-user vs staff vs admin
authorization matrix**, and runs safe privilege-escalation vectors (broken
function-level auth, mass-assignment role elevation, client-controlled role
header, and an unsigned-token role-claim forge) using the configured TEST_USER /
TEST_ADMIN accounts. It never modifies admin data and verifies that destructive
admin operations are blocked at two layers (the module guard and the safety
controller). Run the simulation on its own:

```bash
gamebox admin-sim
```

which prints an **ADMIN ACCESS SIMULATION** summary; the full authorization
matrix and findings land in `gamebox report`.

## 3. Installation

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows;  source .venv/bin/activate on Unix
pip install -r requirements.txt
pip install -e .
```

## 4. Configuration

```bash
gamebox init                  # creates config/targets.yaml and .env
```

Edit `config/targets.yaml`: set `scope`, `base_urls`, test `accounts`, and the
`safety` policy. **Credentials come from environment variables** via `${VAR}`
placeholders — never commit real secrets. See `.env.example`.

Safety defaults (opt in explicitly, only against an authorized sandbox):

```yaml
safety:
  allow_state_changes: false        # bonus/bet/settlement (test currency)
  allow_financial_operations: false # keep false — real money stays blocked
  allow_destructive_tests: false
```

## 5. Run the demo (safe, offline)

```bash
# Terminal 1 — start the intentionally-vulnerable target (TEST_COINS, localhost)
python -m tests.fixtures.demo_game.app --port 5099

# Terminal 2 — point gamebox at it and run the full loop
cp config/targets.demo-full.yaml config/targets.yaml   # sandbox: financial checks on
gamebox discover
gamebox scan --module wallet --module games --module randomness \
             --module authorization --module api --module authentication \
             --module admin --module payments --module game_discovery \
             --module client_trust --module replay --module race
gamebox report
```

Expected: ~18 endpoints and **~28 findings** (7 CRITICAL, 14 HIGH, 5 MEDIUM,
1 LOW, 1 INFO) plus 4 correlated attack chains. Open
`data/reports/dashboard.html` for the interactive view.

For the safe minimal demo (no financial checks), use `config/targets.demo.yaml`
and a plain `gamebox scan`.

## 6. Running discovery

`gamebox discover` performs a **read-only** crawl within scope: it fetches pages,
parses links/forms, and mines JavaScript for API paths, then stores an endpoint
inventory. It never submits forms or changes state.

## 7. Running safe scans

`gamebox scan` authenticates your configured test accounts and runs the
analyzers. By default only `READ_ONLY` and `SAFE_TEST` requests are permitted;
`STATE_CHANGING` sandbox checks (bonus/bet/settlement on `TEST_COINS`) require
`allow_state_changes: true`. Limit modules with `--module wallet` (repeatable).

## 8. Reading reports

`gamebox report` writes `data/reports/report.{json,md,html}` and `findings.csv`.
Each finding carries severity, confidence (`CONFIRMED` / `LIKELY` / `SUSPECTED`),
CWE, OWASP API Top-10 mapping, reproduction steps, remediation, and **redacted**
evidence.

## 9. Adding scanner modules

An analyzer is a small class taking a `SafeHTTPClient` + base URL and returning
`list[Finding]`. Route all traffic through the client (so the safety gate
applies), attach redacted `Evidence`, and register it in `gamebox/cli.py`'s
`cmd_scan`. See [docs/architecture.md](docs/architecture.md#extending).

## 10. Security limitations & guarantees

- **Fail-closed scope:** an empty allow-list means *nothing* is in scope.
- **Never real money:** `FINANCIAL` requests are blocked unless explicitly
  enabled, and a hard deny-list (`real-withdraw`, `bank-transfer`,
  `delete-account`, `shutdown`, …) is *never* permitted.
- **No persistence / no DoS:** the framework does not create accounts, install
  persistence, or perform destructive load testing.
- **Redaction everywhere:** tokens, passwords, cookies, API keys and PII are
  masked in logs and reports.
- This is an **assessment aid**, not an autonomous exploit tool. Confirm findings
  and obtain authorization before testing any real target.

## Phase coverage

All 22 build phases are implemented and exercised end-to-end against the demo:

| # | Phase | Where |
|---|-------|-------|
| 1 | Project build | full package + packaging (`pyproject.toml`) |
| 2 | Modular architecture | `docs/architecture.md`, `core/scheduler.py` orchestrator |
| 3 | Target configuration | `core/config.py`, `config/*.yaml`, `.env.example` |
| 4 | Safety architecture | `safety/{classifier,scope,controller}.py` |
| 5 | Reconnaissance engine | `discovery/crawler.py` |
| 6 | Application map | `discovery/classify.py`, `gamebox map` |
| 7 | Game discovery | `games/discovery.py` |
| 8 | Wallet analysis | `analyzers/wallet.py` (ledger + replay + settlement) |
| 9 | Authorization analyzer | `analyzers/authorization.py` (BOLA), two accounts |
| 10 | API security engine | `api/{misconfig,injection,graphql,websocket,rate_limit,upload,secrets}.py` |
| 11 | Replay / idempotency | `analyzers/replay.py` |
| 12 | Race-condition engine | `analyzers/race.py` |
| 13 | Client-trust analysis | `analyzers/client_trust.py`, `games/randomness.py` |
| 14 | Admin + payment modules | `admin/admin_checks.py`, `payments/payment_checks.py` |
| 15 | Finding engine | `core/models.py`, `core/database.py` |
| 16 | Evidence engine | `core/models.Evidence` + redaction in `http/client.py` |
| 17 | Reporting | `reporting/report.py` (JSON/CSV/MD/HTML) |
| 18 | CLI | `cli.py` |
| 19 | Dashboard | `reporting/report.py::to_dashboard` (interactive, filterable) |
| 20 | Demo target | `tests/fixtures/demo_game/app.py` (20 deliberate flaws) |
| 21 | Automated testing | `tests/` (unit + integration, all green) |
| 22 | Documentation | `README.md`, `docs/*` |
| +  | Attack-chain correlation | `reporting/attack_chains.py` |
| +  | Administrative-access module | `gamebox/admin/` (discovery, matrix, escalation, session, guard, simulation) + `gamebox admin-sim` |
| +  | Andar Bahar WebSocket tester | `gamebox/andarbahar/` (discovery, capture, protocol map, client-trust, mutation, replay, round-binding, authz, state-machine, wallet, randomness, transport) + `gamebox ab-ws` |

### Andar Bahar WebSocket tester (`ab-ws`)

Determines whether a real-time Andar Bahar implementation improperly trusts
client-controlled WebSocket messages. It discovers the WS endpoint, captures the
message lifecycle, infers a protocol map, classifies every sensitive field
(`SERVER_AUTHORITATIVE` / `CLIENT_INPUT` / `DERIVED` / `UNKNOWN`), and runs
server-authority, safe-mutation, replay, round-binding, message-authorization,
state-machine, wallet-integrity, randomness and transport tests. It honours an
explicit environment model — **DEMO (default)** / STAGING enable SAFE_MUTATION on
TEST_COINS; **PRODUCTION is read-only** and the tester refuses to mutate game
outcomes. Run it against the bundled vulnerable demo:

```bash
# Terminal 1 — the intentionally-vulnerable Andar Bahar WS demo (TEST_COINS)
python -m tests.fixtures.demo_game.andar_bahar_ws --port 8765
# Terminal 2
cp config/targets.demo-full.yaml config/targets.yaml
gamebox ab-ws
```

Reports land in `data/reports/andar-bahar/` (`websocket-map.json`,
`protocol-map.json`, `game-state-machine.json`, `wallet-analysis.json`,
`security-findings.json`, `report.md`, `report.html`).

## Tests

```bash
pytest -q      # 69 tests: safety, scope, config, redaction, ledger, reporting,
               # attack chains, game discovery, admin guard/matrix/session,
               # Andar Bahar WS (env policy, protocol map, redaction, prod guard),
               # e2e demo + full-coverage scan + admin-sim + AB WS assessment
```

## License

MIT — see [LICENSE](LICENSE). Authorized testing only.
