# Methodology

GAMEBOX follows an evidence-based, least-impact methodology. Findings are
labelled `CONFIRMED` / `LIKELY` / `SUSPECTED`; nothing is called CONFIRMED
without observed proof.

## Request classification (the safety spine)

| Class | Examples | Default |
|-------|----------|---------|
| READ_ONLY | GET profile, list, history | ALLOWED |
| SAFE_TEST | bounded, reversible sandbox probe on TEST_COINS | ALLOWED |
| STATE_CHANGING | bet, bonus claim, settlement (test currency) | BLOCKED (opt-in) |
| FINANCIAL | deposit, withdraw, transfer, payment | BLOCKED |
| DESTRUCTIVE | delete, drop, reset, DELETE verb | BLOCKED |

Financial and destructive requests stay blocked even with state changes enabled.
A hard deny-list (real-withdraw, bank/wire-transfer, delete-account, shutdown,
install-backdoor) is never permitted under any configuration.

## Phases

1. **Reconnaissance / discovery** — read-only crawl; map the attack surface.
2. **Application mapping** — categorize endpoints (AUTH/WALLET/GAME/PAYMENT/ADMIN).
3. **Risk ranking** — prioritize components by observable characteristics:
   client-controlled monetary fields, separate settlement APIs, replayable
   requests, weak or enumerable identifiers.
4. **Client-trust analysis** — identify values that should be server-authoritative
   (balance, payout, multiplier, result) but appear client-influenced.
5. **Wallet integrity** — build the ledger model and compare with observed state;
   look for duplicate credits, missing debits, duplicate settlement, replay,
   idempotency and race indicators.
6. **Authorization (BOLA/IDOR)** — using two authorized test accounts only, test
   whether account A can reach account B's objects.
7. **Reporting** — findings with evidence, CWE/OWASP mapping, remediation,
   regression tests.

## Wallet ledger model

```
expected_balance = opening_balance
                 + legitimate credits (one bonus, one settlement, ...)
                 - legitimate debits (wagers, legitimate withdrawals)
```

A gap between `expected_balance` and the observed balance after a controlled,
repeated operation is the signal for replay / duplicate-processing findings.

## Safe demonstration

Impact is demonstrated with synthetic `TEST_COINS` against an authorized sandbox
account. A proof-of-concept never escalates into a real withdrawal, a real
payment, modification of unrelated users, data deletion, or persistence.
