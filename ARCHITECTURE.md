# System Architecture: GameBox & Security Assessment Engine

## 1. Overview
The GameBox repository contains an authorized, safety-first black-box security assessment framework for online gaming, betting, casino, and virtual-wallet platforms. It includes both the scanning/assessment engine and an intentionally-vulnerable local demo target for testing.

```
┌─────────────────────────────────────────────────────────────┐
│                      OPERATOR INTERFACE                     │
│               CLI (gamebox) & Web GUI (Flask)               │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   SCAN SCHEDULER & ORCHESTRATOR             │
│   Account Auth │ Module Registry │ Concurrency & Progress   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    CENTRAL SAFETY CONTROLLER                │
│    Scope Validation │ 5-Tier Request Gate │ Hard Deny-List  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   SAFE TRANSPORT (HTTP & WS)                │
│    Rate Limiting │ PII/Secret Redaction │ Evidence Capture  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       TARGET APPLICATION                    │
│      REST APIs │ WebSockets │ Web Pages │ Admin Surface      │
└─────────────────────────────────────────────────────────────┘
```

## 2. Discovered Technology Stack

| Component | Technology | Description |
|-----------|------------|-------------|
| **Language** | Python 3.11+ / 3.13 | Core runtime |
| **CLI / Entrypoint** | Setuptools console script | `gamebox` CLI with `init`, `discover`, `map`, `scan`, `report`, `gui` |
| **Web Service / GUI** | Flask / WSGI | Interactive control dashboard with job queueing, CSRF tokens, and live status |
| **Database** | SQLite 3 (`gamebox.sqlite3`) | Persistent storage for endpoints, findings, evidence, artifacts |
| **HTTP Transport** | `requests` / `httpx` / `urllib3` | Transport routed exclusively through `SafeHTTPClient` |
| **WebSocket** | Python native socket / `websockets` | Live game feed analysis and protocol fuzzing (e.g. Andar Bahar) |
| **Containerization** | Docker & Docker Compose | Containerized local testbed (`demo:5099` + `scanner`) |
| **Test Framework** | `pytest` | 96 unit and integration test suites |

## 3. Subsystem Breakdown

### 3.1 Core Subsystem (`gamebox/core/`)
- `config.py`: Environment-variable expansion (`${VAR}`), YAML target profile loader.
- `database.py`: SQLite schema defining `endpoints`, `findings`, `evidence`, `artifacts`.
- `models.py`: Strongly-typed dataclasses for `Endpoint`, `Finding`, `Evidence`, `RequestClass`, `Category`, `Severity`.
- `logger.py`: Streaming logger with regex-based redaction for secrets, passwords, cookies, and tokens.
- `scheduler.py`: Scan orchestrator coordinating authentications, module execution, cooperative cancellation, and plugin hooks.

### 3.2 Safety Controller (`gamebox/safety/`)
- `scope.py`: Strict allow-list matching domains, subdomains, and ports; default fail-closed.
- `classifier.py`: Request risk classifier assigning `READ_ONLY`, `SAFE_TEST`, `STATE_CHANGING`, `FINANCIAL`, or `DESTRUCTIVE`.
- `controller.py`: Gatekeeper enforcing target environment rules (production is forced read-only) and enforcing an immutable hard deny-list against dangerous operations.

### 3.3 Security Analyzers (`gamebox/analyzers/`, `gamebox/games/`, `gamebox/api/`, `gamebox/admin/`)
- **Wallet Security**: Virtual ledger balance verification, replayable credits, duplicate settlement, negative amounts, precision float truncation.
- **Game Integrity**: Client-controlled payouts, bet cancellation TOCTOU race conditions, round state verification.
- **Fairness & RNG**: Seed commitment verification (HMAC-SHA256/512), client-chosen result detection, randomness distribution.
- **Authorization**: Cross-account object-level authorization (BOLA/IDOR), administrative surface discovery, mass-assignment privilege escalation, unsigned JWT forging.
- **API Security**: GraphQL introspection, CORS misconfigurations, missing security headers, SQLi/Command Injection heuristics, file upload validation, WebSocket message authorization.

### 3.4 Reporting & Evidence (`gamebox/reporting/`)
- Correlation engine for attack chains (e.g. BOLA + Missing Rate Limit -> Account Takeover).
- Exporters for JSON, CSV, Markdown, HTML, and interactive executive dashboards.
