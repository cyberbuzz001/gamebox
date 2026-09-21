"""Schemathesis-based API fuzzing (optional, spec-driven).

Detects OpenAPI/Swagger spec endpoints and runs schemathesis for
property-based API fuzzing when the tool is available.

Registered as the ``schema_fuzz`` opt-in scan module.

Reference: schemathesis/schemathesis.
"""
from __future__ import annotations

from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import SafeHTTPClient

log = get_logger("api.schema_fuzzer")

# Common OpenAPI spec endpoint paths.
_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api/docs",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/swagger/v1/swagger.json", "/api/swagger.json",
    "/graphql",  # GraphQL introspection also counts.
]


def detect_openapi_spec(client: SafeHTTPClient, base_url: str) -> str | None:
    """Probe common endpoints for an OpenAPI/Swagger spec.

    Returns the spec URL if found, else None.
    """
    base = base_url.rstrip("/")
    for path in _SPEC_PATHS:
        try:
            resp, _ = client.get(base + path, capture=False)
        except Exception:
            continue
        if resp.status_code < 400:
            body = resp.json() or {}
            if isinstance(body, dict) and ("openapi" in body or "swagger" in body or
                                            "info" in body):
                log.info("OpenAPI spec detected at %s", base + path)
                return base + path
    return None


def run_schemathesis(spec_url: str, base_url: str,
                     schemathesis_path: str = "schemathesis",
                     timeout: int = 60) -> list[Finding]:
    """Run schemathesis against the spec via subprocess.

    Returns findings parsed from schemathesis output. Requires schemathesis
    on PATH or as pip-installed tool. Returns empty list if unavailable.
    """
    from ..core.external import tool_available, run_tool
    if not tool_available(schemathesis_path):
        log.info("schemathesis not available; skipping spec-based fuzzing")
        return []

    # Use the 'st run' command with JSON output.
    cmd = [
        schemathesis_path, "run", spec_url,
        "--base-url", base_url,
        "--workers", "2",
        "--max-response-time", "5000",
        "--hypothesis-max-examples", "20",
        "--dry-run",  # safe mode: validate requests but minimize state changes
    ]
    result = run_tool(cmd, timeout=timeout)

    findings: list[Finding] = []
    if result.ok or result.stdout:
        # Parse schemathesis text output for failures.
        output = result.stdout + result.stderr
        if "FAILED" in output or "ERROR" in output:
            # Count failure lines.
            failures = [l for l in output.splitlines()
                        if "FAILED" in l or "500" in l or "ERROR" in l]
            findings.append(Finding(
                title=f"[schemathesis] API spec fuzzing found {len(failures)} issue(s)",
                category=Category.OTHER, severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                description=f"Schemathesis property-based fuzzing against {spec_url} "
                f"produced {len(failures)} failure(s). "
                f"First issue: {failures[0].strip()[:150] if failures else 'N/A'}",
                endpoint=spec_url,
                impact="API endpoints may not properly validate input or may crash "
                "on unexpected payloads.",
                reproduction=f"schemathesis run {spec_url} --base-url {base_url}",
                remediation="Fix the failing endpoints to properly validate input and "
                "return appropriate error responses.",
                cwe="CWE-20 (Improper Input Validation)",
                owasp="API8:2023 Security Misconfiguration", module="schema_fuzz"))

    return findings


class SchemaFuzzer:
    """Orchestrates schemathesis-based API fuzzing as a scan module."""

    def __init__(self, client: SafeHTTPClient, base_url: str,
                 schemathesis_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.schemathesis_path = schemathesis_path or "schemathesis"

    def run(self) -> list[Finding]:
        spec_url = detect_openapi_spec(self.client, self.base)
        if not spec_url:
            log.info("no OpenAPI spec detected; schema_fuzz skipped")
            return []
        return run_schemathesis(spec_url, self.base,
                                schemathesis_path=self.schemathesis_path)
