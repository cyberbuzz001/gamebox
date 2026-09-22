# Platform API Documentation: Security Lab

The Security Lab platform exposes a clean REST API for managing projects, targets, scan jobs, manual security tests, findings, exploit validations, and verification replays.

## Base URL
`/api/v1`

---

## 1. Projects & Targets

### `GET /api/v1/projects`
List all configured testing projects.
- **Response**: `200 OK`
```json
[
  {
    "id": "proj-01",
    "name": "GameBox Core Platform",
    "description": "Primary gaming & betting system",
    "target_count": 2,
    "created_at": "2026-09-22T10:00:00Z"
  }
]
```

### `POST /api/v1/targets`
Create or update an authorized target.
- **Request Body**:
```json
{
  "project_id": "proj-01",
  "name": "GameBox Staging",
  "base_url": "https://staging.gamebox.test",
  "environment": "staging",
  "scope_domains": ["staging.gamebox.test", "api.staging.gamebox.test"],
  "excluded_domains": ["payments.gamebox.test"],
  "max_rps": 5.0,
  "test_account": {
    "username": "security-test-user",
    "role": "user"
  }
}
```

---

## 2. Scan Center & Job Execution

### `POST /api/v1/scans`
Initialize and dispatch a security assessment job.
- **Request Body**:
```json
{
  "target_id": "tgt-01",
  "profile": "Game Security Lab",
  "modules": ["wallet", "games", "randomness", "wallet_advanced", "state_race"],
  "rate_limit": 5.0
}
```
- **Response**: `202 Accepted`
```json
{
  "job_id": "scan- job-883",
  "status": "queued",
  "progress_url": "/api/v1/scans/scan-job-883/status"
}
```

### `GET /api/v1/scans/{job_id}/status`
Query real-time scan progress.
- **Response**: `200 OK`
```json
{
  "job_id": "scan-job-883",
  "status": "running",
  "progress_percent": 65,
  "current_module": "state_race",
  "completed_modules": ["wallet", "games", "randomness", "wallet_advanced"],
  "endpoints_discovered": 143,
  "findings_count": 7
}
```

### `POST /api/v1/scans/{job_id}/cancel`
Cooperatively stop an active scan job.

---

## 3. Testing Lab (Manual Security Tests)

### `POST /api/v1/tests/execute`
Execute an isolated test probe against a specific endpoint.
- **Request Body**:
```json
{
  "target_id": "tgt-01",
  "category": "Authentication",
  "test_name": "Session invalidation after logout",
  "account_label": "security-test-user",
  "method": "POST",
  "path": "/api/auth/logout"
}
```

---

## 4. Findings & Remediation

### `GET /api/v1/findings`
Retrieve filtered findings.
- **Query Parameters**: `severity`, `category`, `status`, `target_id`.

### `POST /api/v1/findings/{finding_id}/validate`
Trigger controlled exploit validation on an identified finding.
- **Response**:
```json
{
  "finding_id": "find-102",
  "validated": true,
  "summary": "Vulnerability successfully reproduced on synthetic test account with zero real-money exposure.",
  "evidence_id": "evi-9481"
}
```

### `POST /api/v1/findings/{finding_id}/verify`
Rerun regression test to verify developer fix.
- **Response**:
```json
{
  "finding_id": "find-102",
  "status": "Closed",
  "retest_result": "PASS",
  "details": "Server now properly rejects duplicate settlement with HTTP 409 Conflict."
}
```
