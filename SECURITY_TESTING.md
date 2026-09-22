# Security Testing Methodology & Assessment Guide

## 1. Assessment Profiles

The platform supports six standardized scan profiles, balancing coverage against server performance:

| Profile | Focus | Typical Runtime | Target Policy |
|---------|-------|-----------------|---------------|
| **Passive Recon** | Headers, DNS, robots.txt, tech stack, TLS | < 1 minute | READ_ONLY |
| **Standard Assessment** | Discovery, misconfig, auth, API checks | 2-5 minutes | READ_ONLY / SAFE_TEST |
| **API Security** | GraphQL, rate limits, schema fuzzing, CORS, injection | 5-10 minutes | SAFE_TEST |
| **Game Security Lab** | Bet validation, payout authority, RNG, round states | 3-7 minutes | STATE_CHANGING (sandbox only) |
| **Wallet Integrity** | Replay, duplicate settlement, negative amounts, precision | 2-5 minutes | STATE_CHANGING (sandbox only) |
| **Full Security Assessment** | All modules executed end-to-end + attack chain correlation | 10-20 minutes | Configured policy |

## 2. Game Security Lab Testing Vectors

### 2.1 Server-Authoritative Game Integrity
- **Objective**: Verify that the server calculates outcomes and payouts independently, without trusting client parameters.
- **Test Vector**:
  1. Client sends bet: `{"bet_amount": 10, "result": "win", "payout": 500}`.
  2. Finding Trigger: If the server credits the wallet by 500 or records the client-supplied `"win"` outcome without generating its own random round result, a **CRITICAL** finding is issued.

### 2.2 Bet Cancellation TOCTOU Race Condition
- **Objective**: Prevent players from canceling a placed bet while simultaneously claiming a win/payout on the same round.
- **Test Vector**:
  1. Submit bet for `round_id: 12345`.
  2. Dispatch concurrent requests using Last-Byte HTTP/2 synchronization:
     - Thread 1: `POST /api/game/bet/cancel`
     - Thread 2: `POST /api/game/settlement`
  3. Finding Trigger: If both cancellation refund and settlement payout succeed, resulting in double credit for one round.

### 2.3 Wallet Arithmetic & Precision Tests
- **Objective**: Ensure negative amounts and extreme float values cannot manipulate balances.
- **Test Vectors**:
  - `POST /api/wallet/bet` with `amount: -100.0` (verifies debit does not invert into credit).
  - `POST /api/wallet/bet` with `amount: 0.000000000000001` (tests float precision loss).
  - `POST /api/wallet/bet` with `amount: 9007199254740991` (tests integer overflow limits).

### 2.4 Provably Fair & RNG Entropy
- **Objective**: Validate cryptographic commitments and ensure outcome randomness.
- **Test Vector**:
  1. Extract server seed hash before round execution.
  2. After round completion, extract unhashed server seed and client seed.
  3. Calculate `HMAC_SHA256(server_seed, client_seed)` and verify mathematical match with outcome.
  4. Finding Trigger: Mismatched hashes, constant server seeds, or predictable PRNG distributions.

## 3. Exploit Validation Protocol

When a vulnerability is suspected, **Controlled Exploit Validation** is used to confirm exploitability without causing operational damage:

1. **Safety Envelope**: Operates exclusively on explicitly authorized test accounts (e.g. `security-test-user`) using virtual currency (`TEST_COINS`).
2. **Minimal Proof of Concept**: The test terminates immediately upon observing evidence of the flaw (e.g. a balance incrementing by 100 instead of decrementing).
3. **Evidence Archival**: Request/response headers and bodies are captured, scrubbed of credentials, and stored in the database for developer remediation.
4. **No Destructive Exploitation**: The validator never wipes databases, modifies third-party user data, or attempts lateral movement.

## 4. Fix Verification & Continuous Assurance

To close an identified finding, the developer or tester triggers **Fix Verification**:
1. The platform replays the exact test vector that triggered the finding.
2. If the application returns a secure response (e.g. `400 Bad Request` or `403 Forbidden` with no state modification), the finding status transitions from `Retest Required` to `Closed`.
3. If the vulnerability remains exploitable, the finding transitions to `Reopened`.
