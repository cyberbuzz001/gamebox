"""GraphQL security checks: introspection exposure, BOLA on a by-id query,
batching abuse, query depth limits, field suggestion leaks, alias-based DoS,
schema recovery when introspection is disabled, and optional graphql-cop
subprocess integration.

Enhanced with techniques from:
- dolevf/graphql-cop (Python misconfig scanner)
- nikitastupin/clairvoyance (schema recovery)
- doyensec/inql (deep GraphQL testing)

References: Escape-Technologies/awesome-graphql-security.
"""
from __future__ import annotations

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, RequestClass, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("api.graphql")

_INTROSPECTION = "{ __schema { queryType { name } types { name } } }"

# Common type/field names for clairvoyance-style schema probing.
_COMMON_TYPES = [
    "User", "Account", "Player", "Game", "Bet", "Wallet", "Transaction",
    "Admin", "Settings", "Config", "Payment", "Bonus", "Deposit", "Withdrawal",
    "Session", "Token", "Role", "Permission", "Profile", "Balance",
]


class GraphQLAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str, path: str = "/graphql",
                 graphql_cop_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.path = path
        self.graphql_cop_path = graphql_cop_path

    def run(self, attacker: AccountSession | None = None,
            victim_user_id: int | None = None) -> list[Finding]:
        out: list[Finding] = []
        introspection_found = self._introspection()
        out += introspection_found
        if victim_user_id is not None:
            out += self._bola(attacker, victim_user_id)
        # --- Enhanced checks ---
        out += self._batching()
        out += self._depth_limit()
        out += self._field_suggestions()
        out += self._alias_overloading()
        if not introspection_found:
            out += self._schema_recovery()
        out += self._run_graphql_cop()
        return out

    def _introspection(self) -> list[Finding]:
        url = self.base + self.path
        try:
            # Read-only in intent -> declare SAFE_TEST so it runs without state opt-in.
            resp, ev = self.client.post(url, json_body={"query": _INTROSPECTION},
                                        declared=RequestClass.SAFE_TEST)
        except BlockedRequest as b:
            log.info("graphql introspection skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        body = resp.json() or {}
        if resp.status_code < 400 and isinstance(body, dict) and \
                body.get("data", {}).get("__schema"):
            return [Finding(
                title="GraphQL introspection is enabled",
                category=Category.OTHER, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                description="The GraphQL endpoint answers __schema introspection queries.",
                endpoint=f"POST {self.path}",
                impact="Attackers can enumerate the full schema, easing discovery of sensitive "
                "queries/mutations.",
                reproduction=f"POST {self.path} with an introspection query returns __schema.",
                remediation="Disable introspection in production; require auth; apply query "
                "depth/complexity limits.",
                cwe="CWE-200 (Information Exposure)", owasp="API8:2023 / API9:2023",
                module="api", evidence=[ev] if ev else [])]
        return []

    def _bola(self, attacker: AccountSession | None, victim_user_id: int) -> list[Finding]:
        url = self.base + self.path
        query = "{ user(id: %d) { id email balance } }" % victim_user_id
        headers = attacker.headers() if attacker else None
        try:
            resp, ev = self.client.post(url, headers=headers,
                                        json_body={"query": query},
                                        declared=RequestClass.SAFE_TEST)
        except Exception:
            return []
        body = resp.json() or {}
        user = (body.get("data") or {}).get("user") if isinstance(body, dict) else None
        if user and user.get("id") == victim_user_id and "email" in user:
            if ev and attacker:
                ev.test_account = attacker.label
            return [Finding(
                title="GraphQL BOLA: user(id) returns arbitrary users' data",
                category=Category.USER, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="The user(id) query returns another account's data without an "
                "ownership/authorization check.",
                endpoint=f"POST {self.path}", parameter="id",
                impact="Any client can read arbitrary users' email and balance by id.",
                reproduction=f"POST {self.path} with query user(id: {victim_user_id}).",
                remediation="Enforce authorization in resolvers; scope queries to the "
                "authenticated principal.",
                cwe="CWE-639 (Authorization Bypass Through User-Controlled Key)",
                owasp="API1:2023 Broken Object Level Authorization", module="api",
                evidence=[ev] if ev else [])]
        return []

    # -- Batching abuse (graphql-cop inspired) --------------------------------

    def _batching(self) -> list[Finding]:
        """Send an array of queries to detect unbounded batching (DoS vector)."""
        url = self.base + self.path
        batch = [{"query": "{ __typename }"} for _ in range(25)]
        try:
            resp, ev = self.client.post(url, json_body=batch,
                                        declared=RequestClass.SAFE_TEST)
        except Exception:
            return []
        body = resp.json()
        if isinstance(body, list) and len(body) >= 25:
            return [Finding(
                title="GraphQL batching: unlimited batch queries accepted",
                category=Category.OTHER, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description=f"The endpoint accepted a batch of 25 queries in a single "
                "request and returned all results. Unbounded batching can be abused "
                "for DoS or to bypass rate limiting.",
                endpoint=f"POST {self.path}",
                impact="An attacker can amplify requests, bypass per-request rate limits, "
                "or brute-force fields by batching many queries.",
                reproduction=f"POST {self.path} with a JSON array of 25 queries.",
                remediation="Limit the number of queries per batch request (e.g. max 5). "
                "Apply cost/complexity analysis per batch.",
                cwe="CWE-770 (Allocation of Resources Without Limits)",
                owasp="API4:2023 Unrestricted Resource Consumption", module="api",
                evidence=[ev] if ev else [])]
        return []

    # -- Query depth limit check ---------------------------------------------

    def _depth_limit(self) -> list[Finding]:
        """Send a deeply nested query to check for depth limits."""
        url = self.base + self.path
        # Build a query nested 15 levels deep.
        nested = "{ __typename " + "".join(
            f"... on Query {{ __typename " for _ in range(15)
        ) + "}" * 16
        try:
            resp, ev = self.client.post(url, json_body={"query": nested},
                                        declared=RequestClass.SAFE_TEST)
        except Exception:
            return []
        body = resp.json() or {}
        # If the server returns data without an error about depth, it has no limit.
        if resp.status_code < 400 and isinstance(body, dict) and \
                "errors" not in body and body.get("data"):
            return [Finding(
                title="GraphQL: no query depth limit detected",
                category=Category.OTHER, severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description="A deeply nested GraphQL query (15 levels) was executed "
                "without being rejected, suggesting no depth limit is enforced.",
                endpoint=f"POST {self.path}",
                impact="Attackers can craft deeply nested queries to exhaust server "
                "resources (denial of service via recursive resolution).",
                reproduction=f"POST {self.path} with a 15-level nested query.",
                remediation="Implement query depth limiting (e.g. max depth 10) and "
                "query complexity analysis.",
                cwe="CWE-770 (Allocation of Resources Without Limits)",
                owasp="API4:2023 Unrestricted Resource Consumption", module="api",
                evidence=[ev] if ev else [])]
        return []

    # -- Field suggestion leak -----------------------------------------------

    def _field_suggestions(self) -> list[Finding]:
        """Send a typo'd field to check for 'Did you mean...' suggestion leaks."""
        url = self.base + self.path
        query = "{ usre { id } }"  # deliberate typo of 'user'
        try:
            resp, ev = self.client.post(url, json_body={"query": query},
                                        declared=RequestClass.SAFE_TEST)
        except Exception:
            return []
        body = resp.json() or {}
        errors = body.get("errors", []) if isinstance(body, dict) else []
        suggestions = [e for e in errors
                       if isinstance(e, dict) and "did you mean" in str(e).lower()]
        if suggestions:
            return [Finding(
                title="GraphQL field suggestion leak (schema enumeration aid)",
                category=Category.OTHER, severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description="The endpoint returns 'Did you mean...' suggestions for "
                "misspelled field names, enabling attackers to enumerate the schema "
                "even when introspection is disabled.",
                endpoint=f"POST {self.path}",
                impact="Schema fields can be discovered through systematic typos, "
                "bypassing introspection restrictions.",
                reproduction=f"POST {self.path} with query '{{ usre {{ id }} }}'; "
                f"response contains suggestions: {suggestions[0]}",
                remediation="Disable field suggestions in production GraphQL configuration.",
                cwe="CWE-200 (Information Exposure)",
                owasp="API8:2023 Security Misconfiguration", module="api",
                evidence=[ev] if ev else [])]
        return []

    # -- Alias-based DoS check -----------------------------------------------

    def _alias_overloading(self) -> list[Finding]:
        """Send many aliased copies of a query to check for alias limits."""
        url = self.base + self.path
        aliases = " ".join(f"a{i}: __typename" for i in range(100))
        query = "{ " + aliases + " }"
        try:
            resp, ev = self.client.post(url, json_body={"query": query},
                                        declared=RequestClass.SAFE_TEST)
        except Exception:
            return []
        body = resp.json() or {}
        if resp.status_code < 400 and isinstance(body, dict) and \
                body.get("data") and len(body["data"]) >= 100:
            return [Finding(
                title="GraphQL alias overloading: 100 aliases accepted without limit",
                category=Category.OTHER, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description="The endpoint accepted 100 aliased copies of a query in a "
                "single request, indicating no alias/complexity limit.",
                endpoint=f"POST {self.path}",
                impact="Attackers can amplify expensive resolvers by aliasing them many "
                "times in a single query, causing DoS.",
                reproduction=f"POST {self.path} with 100 aliases of __typename.",
                remediation="Implement query complexity/cost analysis that counts aliases "
                "toward the complexity budget.",
                cwe="CWE-770 (Allocation of Resources Without Limits)",
                owasp="API4:2023 Unrestricted Resource Consumption", module="api",
                evidence=[ev] if ev else [])]
        return []

    # -- Schema recovery (clairvoyance-style) --------------------------------

    def _schema_recovery(self) -> list[Finding]:
        """When introspection is disabled, probe common type/field names.

        Reference: nikitastupin/clairvoyance.
        """
        url = self.base + self.path
        discovered_types: list[str] = []
        for type_name in _COMMON_TYPES:
            query = "{ %s { __typename } }" % type_name.lower()
            try:
                resp, _ = self.client.post(url, json_body={"query": query},
                                           declared=RequestClass.SAFE_TEST)
            except Exception:
                continue
            body = resp.json() or {}
            if resp.status_code < 400 and isinstance(body, dict):
                data = body.get("data") or {}
                if data.get(type_name.lower()):
                    discovered_types.append(type_name)
                # Also check 'Did you mean' suggestions.
                errors = body.get("errors", [])
                for e in errors:
                    if isinstance(e, dict) and "did you mean" in str(e).lower():
                        discovered_types.append(f"{type_name}(suggested)")
                        break

        if discovered_types:
            return [Finding(
                title=f"GraphQL schema partially recovered ({len(discovered_types)} types)",
                category=Category.OTHER, severity=Severity.LOW,
                confidence=Confidence.SUSPECTED,
                description=f"Even with introspection disabled, {len(discovered_types)} "
                f"types/fields were discovered via wordlist probing: "
                f"{', '.join(discovered_types[:10])}.",
                endpoint=f"POST {self.path}",
                impact="Attackers can enumerate the schema through systematic probing, "
                "discovering sensitive queries and mutations.",
                reproduction="Probe common type names against the endpoint.",
                remediation="Disable field suggestions and consider query whitelisting "
                "(persisted queries).",
                cwe="CWE-200 (Information Exposure)",
                owasp="API8:2023 Security Misconfiguration", module="api")]
        return []

    # -- External: graphql-cop subprocess (optional) -------------------------

    def _run_graphql_cop(self) -> list[Finding]:
        """Run graphql-cop for comprehensive misconfig scanning if available."""
        if not self.graphql_cop_path:
            return []
        from ..core.external import tool_available, run_tool
        if not tool_available(self.graphql_cop_path):
            log.info("graphql-cop not available; skipping")
            return []

        url = self.base + self.path
        result = run_tool([
            "python", self.graphql_cop_path, "-t", url,
        ], timeout=30)

        findings: list[Finding] = []
        if result.ok and result.stdout:
            import json as _json
            for line in result.stdout.strip().splitlines():
                try:
                    entry = _json.loads(line)
                    severity = Severity.MEDIUM
                    if entry.get("severity", "").upper() == "HIGH":
                        severity = Severity.HIGH
                    findings.append(Finding(
                        title=f"[graphql-cop] {entry.get('title', 'misconfiguration')}",
                        category=Category.OTHER, severity=severity,
                        confidence=Confidence.LIKELY,
                        description=entry.get("description", "Detected by graphql-cop."),
                        endpoint=f"POST {self.path}",
                        impact=entry.get("impact", "GraphQL misconfiguration."),
                        reproduction=f"graphql-cop -t {url}",
                        remediation=entry.get("remediation", "Review GraphQL configuration."),
                        cwe="CWE-16 (Configuration)",
                        owasp="API8:2023 Security Misconfiguration", module="api"))
                except Exception:
                    continue
        return findings

