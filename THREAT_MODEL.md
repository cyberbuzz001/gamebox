# Threat Model: Gaming & Betting Platforms

## 1. System Context & Critical Assets

Online gaming, casino, and betting systems manage high-velocity transactions and real-time state synchronization. Critical assets include:

1. **User Wallets & Balances**: Ledger integrity, deposits, and withdrawal authority.
2. **Game Authority & State Machine**: Outcome generation, win calculations, and settlement credits.
3. **Random Number Generation (RNG)**: Unpredictability and cryptographic seed commitment.
4. **Administrative Controls**: User management, odds configuration, and manual balance adjustments.
5. **Real-time Comms**: WebSocket feeds broadcasting card deals, bets, and multipliers.

---

## 2. Threat Actor Profiles

- **Opportunistic Player**: Uses web proxies or dev tools to tamper with client-side JSON parameters (e.g. changing `win: false` to `win: true`).
- **Automated Sybil Rings**: Uses botnets to claim one-time sign-up bonuses repeatedly or perform table collusion.
- **Race Condition Exploiters**: Sends sub-millisecond concurrent HTTP/2 requests to exploit non-atomic database operations (e.g. bet cancellation during settlement).
- **Cryptanalytic Attackers**: Analyzes sequential RNG outputs to recover seeds or predict future card sequences.

---

## 3. STRIDE Threat Analysis

| Threat (STRIDE) | Attack Vector in Gaming Systems | Impact | Platform Defense / Scanner Module |
|-----------------|---------------------------------|--------|-----------------------------------|
| **Spoofing** | Forging JWT claims or role headers | Access administrative capabilities | `admin_access`, `jwt_deep` |
| **Tampering** | Sending negative bet amounts or custom multipliers | Unauthorized wallet inflation | `wallet_advanced`, `games` |
| **Repudiation** | Replaying bonus claims or duplicate settlement | Double crediting of rewards | `wallet`, `replay` |
| **Information Disclosure** | IDOR on user balance or predictable reset tokens | Account takeover, balance snooping | `authorization`, `authentication` |
| **Denial of Service** | Unrestricted GraphQL queries or unauthenticated endpoints | Service degradation | `api:graphql`, `api:rate_limit` |
| **Elevation of Privilege** | Mass assignment updating `role: admin` on profile update | Complete platform compromise | `admin_access`, `api:misconfig` |

---

## 4. Top Attack Scenarios & Mitigations

### 4.1 Client-Controlled Outcome / Payout
- **Mechanism**: The mobile or web client calculates whether a game won and tells the server how many coins to add.
- **Mitigation**: Server-side RNG generation. The server accepts only user inputs (bet amount, selection), computes the random event internally, calculates the payout using verified odds tables, and updates the database in a single ACID transaction.

### 4.2 Bet Cancellation TOCTOU Race
- **Mechanism**: The attacker sends a cancel request at the exact instant the game round settles, receiving a refund while simultaneously collecting the winning payout.
- **Mitigation**: Strict state machine: `INIT` -> `PLACED` -> `IN_PROGRESS` -> `SETTLED` / `CANCELLED`. Cancellation is forbidden once round calculation begins. Database row locks (`SELECT FOR UPDATE`) prevent concurrent execution.

### 4.3 Virtual Coin Arbitrage & Negative Amount Injection
- **Mechanism**: Attacker bets `-100.0`. If backend performs `balance = balance - bet_amount`, the subtraction of a negative value produces `balance - (-100) = balance + 100`.
- **Mitigation**: Strict schema validation rejecting any numerical value less than or equal to zero before application processing.
