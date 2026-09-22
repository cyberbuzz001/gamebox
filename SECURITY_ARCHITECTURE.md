# Security Architecture: Security Lab Assessment Platform

## 1. System Topology & Separation of Concerns
The **SECURITY LAB** is an authorized, internal security-testing and vulnerability-management platform. It is engineered to decouple the security testing apparatus from the target gaming applications, preventing cross-contamination and eliminating risk to live production environments.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      SECURITY PLATFORM WEB CONSOLE                      │
│                                                                         │
│ Dashboard │ Projects │ Targets │ Scan Center │ Testing Lab │ Findings    │
│ Exploit Validation │ Evidence │ Fix Center │ Verification │ Reports     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                REST / SSE
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                         CONTROL PLANE / API                             │
│                                                                         │
│ Authentication │ RBAC │ Scope Controller │ Scan Manager │ Audit Log     │
└──────────────┬──────────────────────────────────────────┬───────────────┘
               │                                          │
               ▼                                          ▼
       ┌──────────────┐                          ┌────────────────┐
       │ Storage Layer│                          │ Task Dispatcher│
       │              │                          │                │
       │ Projects     │                          │ Scan Jobs      │
       │ Targets      │                          │ Worker Pool    │
       │ Findings     │                          │ Rate Limiters  │
       │ Evidence     │                          └───────┬────────┘
       └──────────────┘                                  │
                                                         ▼
                                            ┌─────────────────────────┐
                                            │      WORKER FLEET       │
                                            │                         │
                                            │ Recon Worker            │
                                            │ Crawler / Discovery     │
                                            │ API Security Worker     │
                                            │ Auth & RBAC Worker      │
                                            │ Game Integrity Worker   │
                                            │ Wallet Integrity Worker │
                                            │ Concurrency / Race      │
                                            │ Exploit Validator       │
                                            │ Fix Verification Worker │
                                            └────────────┬────────────┘
                                                         │
                                                         ▼
                                            ┌─────────────────────────┐
                                            │  CENTRAL SAFETY GATE    │
                                            │                         │
                                            │ Target Scope Filter     │
                                            │ Rate Limiting Engine    │
                                            │ Request Risk Classifier │
                                            │ Hard Deny-List Guard    │
                                            └────────────┬────────────┘
                                                         │
                                                         ▼
                                               Authorized Target API
```

## 2. Core Security Guarantees & Safety Controls

1. **Fail-Closed Scope Policy**:
   - Outbound requests MUST match explicit host/domain and path allow-lists configured on the target.
   - If no scope is defined, 100% of requests are dropped immediately.
   - Live/production targets are locked permanently into `READ_ONLY` mode.

2. **Immutable Hard Deny-List**:
   - Operations involving real money withdrawals, banking transfers, permanent database drops, administrative user deletions, or backdoor persistence are blocked at the lowest network layer regardless of operator permissions.

3. **Virtual Currency & Sandboxing**:
   - State-changing betting, settlement, and wallet checks operate strictly against designated `TEST_COINS` / synthetic currency test accounts.
   - Real money transactions are strictly prohibited.

4. **Zero Plaintext Credentials in Reports & UI**:
   - Sensitive values (passwords, JWT tokens, session cookies, personal identification numbers) are redacted both in memory before disk storage and when rendering HTTP response evidence.

5. **Safe Exploit Validation**:
   - When proving vulnerability existence (e.g. BOLA/IDOR, Replay, Negative Bets), execution stops at the minimum viable proof of concept. The platform never weaponizes exploits or performs destructive modifications.

## 3. Data Model Architecture

The platform organizes security intelligence into structured, relational entities:

- **Projects**: Top-level organizational grouping (e.g. `GameBox Core`, `Partner Integration`).
- **Targets**: Host endpoints, base URLs, and environment flags (`Development`, `Staging`, `Authorized Production`).
- **Target Scopes**: Specific allowed domains, allowed subdomains, allowed paths, and excluded paths.
- **Test Accounts**: Test credentials reference, username, assigned role (`user`, `staff`, `admin`), and session token cache.
- **Scan Jobs**: Specific assessment executions, scan profiles (`Passive`, `Standard`, `Deep`, `Game Security`, `API Security`, `Full Assessment`), state (`queued`, `running`, `paused`, `completed`, `cancelled`), and live progress telemetry.
- **Findings**: Normalized vulnerability records with severity, confidence, OWASP API Top-10 / CWE mapping, impact, root cause, and remediation guidance.
- **Evidence**: Captured request/response payloads with timestamps, status codes, and automatic secret redaction.
- **Remediations**: Code patches, architectural guidance, affected file references, and developer review tracking.
- **Verification Tests**: Automated regression replays that re-execute the original finding probe after developer remediation (`PASS` -> Closed, `FAIL` -> Reopened).
- **Audit Logs**: Immutable record of operator actions (`SCAN_STARTED`, `EXPLOIT_VALIDATED`, `FIX_VERIFIED`, `TARGET_MODIFIED`).

## 4. Remediation & Verification Lifecycle

```
[Finding Identified]
        │
        ▼
[Exploit Validation] ──(Proof Confirmed)──► [Root Cause Analysis]
                                                    │
                                                    ▼
                                            [Generate Patch & Test]
                                                    │
                                                    ▼
                                            [Developer Human Review]
                                                    │
                                                    ▼
                                            [Deploy Fix to Staging]
                                                    │
                                                    ▼
                                            [Run Fix Verification]
                                                    │
                                   ┌────────────────┴────────────────┐
                                   ▼                                 ▼
                                [PASS]                            [FAIL]
                            Finding Closed                    Finding Reopened
                                                              Notify Developer
```
