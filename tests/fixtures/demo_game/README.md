# GAMEBOX Demo Target (intentionally vulnerable)

**For authorized local testing only.** Synthetic `TEST_COINS`, bound to
`127.0.0.1`. No real money, no payment integration, no persistence. Do not
expose on a network.

```bash
python -m tests.fixtures.demo_game.app --port 5099
```

Test accounts (synthetic, public): `alice / alice-test-pw`, `bob / bob-test-pw`,
and TEST_ADMIN `admin / admin-test-pw` (used to build the authorization matrix).

Deliberate weaknesses (each affects only synthetic data / TEST_COINS):

| # | Endpoint | Weakness |
|---|----------|----------|
| 1 | `GET /api/wallet/<id>` | IDOR - no ownership check |
| 2 | `POST /api/bonus/claim` | Replayable / race - no idempotency |
| 3 | `POST /api/game/settlement` | Duplicate settlement (same round_id) |
| 4 | `POST /api/game/teenpatti/bet` | Client-trusted payout + client-set result |
| 5 | `GET /api/wallet/me` | Excessive data exposure (password_hash, is_admin) |
| 6 | `POST /api/profile/update` | Mass assignment (role/is_admin/balance) |
| 7 | `GET /api/search?q=` | Reflected XSS |
| 8 | `GET /api/user?id='` | SQL-injection error indicator |
| 9 | `GET /api/file?name=../` | Path traversal |
| 10 | `POST /api/avatar/fetch` | SSRF (no target validation) |
| 11 | `GET /api/admin/users` | Broken function-level authz (no auth) |
| 12 | `GET /api/admin/config` | Secret exposure (no auth) |
| 13 | `POST /api/auth/login` | Username enumeration + no rate limiting |
| 14 | `POST /api/auth/forgot` | Predictable reset token in response |
| 15 | any | Permissive CORS (reflects Origin + credentials) |
| 16 | any | Missing security headers |
| 17 | `POST /api/upload` | Unrestricted file upload |
| 18 | `POST /graphql` | Introspection enabled + BOLA on user(id) |
| 19 | `ws://.../ws/game` | Unauthenticated WebSocket reference |
| 20 | `POST /api/payment/webhook` | Unsigned + replayable callback (financial) |
| 21 | `GET /api/admin/analytics` | Trusts role claim in an unsigned access token |
| 22 | `GET /api/admin/reports` | Trusts a client-supplied `X-User-Role` header |

Properly-protected admin endpoints (used as controls in the authorization
matrix): `GET /api/admin/settings`, `/api/admin/games`,
`/api/admin/wallet/adjustments` (server-side `is_admin` check). A normal user can
still reach `/api/admin/settings` after the mass-assignment escalation (#6).

## Andar Bahar WebSocket demo (`andar_bahar_ws.py`)

A separate intentionally-vulnerable **WebSocket** server (TEST_COINS, 127.0.0.1):

```bash
python -m tests.fixtures.demo_game.andar_bahar_ws --port 8765
```

It deals a genuine, server-side Andar Bahar round (the `ROUND_RESULT` winner is
server-generated) but SETTLEMENT trusts client input. Seeded weaknesses:

| # | Message | Weakness |
|---|---------|----------|
| 1 | `SETTLE` | Client-controlled result/payout |
| 2 | `SETTLE` | Replayable (no nonce/idempotency) |
| 3 | `SETTLE` | Missing round/session binding (`user_id` from message) |
| 4 | `SETTLE` | Duplicate settlement double-credits |
| 5 | `SETTLE` | Weak authorization (works with no AUTH) |

Assess it with `gamebox ab-ws`.
