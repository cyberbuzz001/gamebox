# Testing Guide

## Run the unit + integration suite

```bash
pip install -r requirements.txt && pip install -e .
pytest -q
```

Covers (44 tests): request classifier, scope enforcement (fail-closed +
wildcards), config + env expansion, secret redaction (incl. compound keys and
Stripe/AWS shapes), wallet ledger, report generation, attack-chain correlation,
game discovery, a targeted end-to-end demo scan, and a full-coverage scan that
runs every module and asserts a blocked financial request.

## Exercise the demo end-to-end (full coverage)

```bash
python -m tests.fixtures.demo_game.app --port 5099        # terminal 1
cp config/targets.demo-full.yaml config/targets.yaml      # terminal 2 (sandbox)
gamebox discover
gamebox scan --module wallet --module games --module randomness \
             --module authorization --module api --module authentication \
             --module admin --module payments --module game_discovery \
             --module client_trust --module replay --module race
gamebox report
```

### Expected result

- ~18 endpoints discovered (including `/api/admin/*`, `/graphql`,
  `/api/payment/webhook` and `/api/wallet/{id}` mined from JavaScript).
- ~28 findings: 7 CRITICAL, 14 HIGH, 5 MEDIUM, 1 LOW, 1 INFO — spanning wallet,
  games, authorization, API (XSS/SQLi/traversal/SSRF/CORS/upload/GraphQL/secrets),
  authentication, admin and payments.
- 4 correlated attack chains (balance inflation, account takeover, mass data
  exposure, secret-to-escalation).
- `data/reports/dashboard.html` is the interactive dashboard; evidence is redacted.

For the minimal safe demo (no financial checks), use `config/targets.demo.yaml`
and a plain `gamebox scan`.

## Verifying safety behavior

- Set `allow_state_changes: false` and re-run `gamebox scan`: state-changing
  probes are blocked and no wallet/game findings are produced.
- A `POST /api/wallet/withdraw` is always blocked (FINANCIAL) - see
  `tests/integration/test_demo_scan.py::test_financial_operation_is_blocked`.
- Point `base_urls` at an out-of-scope host: every request is blocked by scope.

## Against a real (authorized) target

1. Confirm written authorization and scope.
2. `gamebox init`, set scope + `base_urls`, put credentials in `.env`.
3. Keep `allow_financial_operations: false`. Only enable `allow_state_changes`
   against a sandbox that uses test currency.
4. `gamebox discover` -> review `gamebox map` -> `gamebox scan` -> `gamebox report`.
