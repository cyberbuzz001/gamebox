"""Privilege-escalation vectors (safe, non-destructive).

Each vector, if it succeeds, proves that a normal user (TEST_USER) can reach
administrative functionality. Proof is limited to reading harmless admin
metadata endpoints. The mass-assignment vector only ever toggles the *test
account's own* flag and restores it afterwards; it never touches other users.
"""
from __future__ import annotations

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient
from .discovery import AdminEndpoint


def _desc(observed: str, expected: str, required_priv: str, detail: str) -> str:
    return (f"{detail}\n\n"
            f"Required privilege (observed to be sufficient): {required_priv}\n"
            f"Observed behavior: {observed}\n"
            f"Expected behavior: {expected}")


log = get_logger("admin.escalation")


class PrivilegeEscalation:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 profile_update_path: str = "/api/profile/update",
                 admin_settings_path: str = "/api/admin/settings",
                 admin_reports_path: str = "/api/admin/reports"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.profile_update_path = profile_update_path
        self.admin_settings_path = admin_settings_path
        self.admin_reports_path = admin_reports_path

    # --- Vector 1: broken function-level authorization (no auth) ----------
    def fla_no_auth(self, admin_endpoints: list[AdminEndpoint]) -> list[Finding]:
        out: list[Finding] = []
        for ep in admin_endpoints:
            if ep.method.upper() != "GET":
                continue
            try:
                resp, ev = self.client.get(ep.url)
            except Exception:
                continue
            if resp.status_code == 200 and '"error"' not in resp.text:
                out.append(Finding(
                    title=f"Unauthenticated access to admin function ({ep.function})",
                    category=Category.ADMIN, severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    description=_desc(
                        observed=f"GET {ep.url} returned 200 with data and no credentials.",
                        expected="401/403 for any non-admin (and unauthenticated) caller.",
                        required_priv="None (unauthenticated)",
                        detail="An administrative endpoint enforces no authentication or "
                        "authorization."),
                    endpoint=f"GET {ep.url}",
                    impact="Anyone can read/operate administrative functionality without "
                    "logging in.",
                    reproduction=f"GET {ep.url} with no Authorization header -> 200.",
                    remediation="Require authentication and an explicit admin-role check on "
                    "every admin route; deny by default.",
                    cwe="CWE-862 (Missing Authorization)",
                    owasp="API5:2023 Broken Function Level Authorization", module="admin_access",
                    evidence=[ev] if ev else []))
        return out

    # --- Vector 2: mass-assignment privilege escalation -------------------
    def mass_assignment(self, user: AccountSession) -> list[Finding]:
        settings_url = self.base + self.admin_settings_path
        # Baseline: a normal user must be denied.
        try:
            before, _ = self.client.get(settings_url, headers=user.headers())
        except Exception:
            return []
        if before.status_code == 200:
            return []  # already open -> covered by FLA vector, not escalation

        upd_url = self.base + self.profile_update_path
        try:
            self.client.post(upd_url, headers=user.headers(),
                             json_body={"is_admin": True, "role": "admin"})
            after, ev = self.client.get(settings_url, headers=user.headers())
        except BlockedRequest as b:
            log.info("mass-assignment escalation skipped (blocked): %s", b.decision.reason)
            return []
        except Exception:
            return []
        finding: list[Finding] = []
        if after.status_code == 200 and '"error"' not in after.text:
            if ev:
                ev.test_account = user.label
            finding = [Finding(
                title="Privilege escalation via mass assignment reaches admin function",
                category=Category.ADMIN, severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description=_desc(
                    observed=f"After POST {self.profile_update_path} with is_admin=true, the "
                    f"same user received 200 from {self.admin_settings_path} (was denied "
                    "before).",
                    expected="is_admin/role are server-controlled; a user cannot grant them.",
                    required_priv="Normal authenticated user (TEST_USER)",
                    detail="A normal user elevated their own privileges by setting is_admin "
                    "through a mass-assignment flaw, then reached an admin-only endpoint."),
                endpoint=f"POST {self.profile_update_path} -> GET {self.admin_settings_path}",
                parameter="is_admin/role",
                impact="Any normal user can become an administrator and access admin "
                "functionality (demonstrated on the test account only).",
                reproduction=f"As TEST_USER: GET {self.admin_settings_path} (403) -> "
                f"POST {self.profile_update_path} is_admin=true -> GET "
                f"{self.admin_settings_path} (200).",
                remediation="Never bind is_admin/role from the request body; manage roles "
                "through a separate admin-only, audited flow; re-check role server-side.",
                cwe="CWE-269 (Improper Privilege Management)",
                owasp="API3:2023 / API5:2023", module="admin_access",
                evidence=[ev] if ev else [])]
        # Restore the test account's flag (courtesy; demo is in-memory anyway).
        try:
            self.client.post(upd_url, headers=user.headers(),
                             json_body={"is_admin": False, "role": "user"})
        except Exception:
            pass
        return finding

    # --- Vector 3: client-controlled role header --------------------------
    def role_header(self, user: AccountSession) -> list[Finding]:
        url = self.base + self.admin_reports_path
        try:
            denied, _ = self.client.get(url, headers=user.headers())
            forged, ev = self.client.get(
                url, headers={**user.headers(), "X-User-Role": "admin"})
        except Exception:
            return []
        if forged.status_code == 200 and '"error"' not in forged.text and \
                denied.status_code != 200:
            if ev:
                ev.test_account = user.label
            return [Finding(
                title="Client-controlled role header grants admin access",
                category=Category.ADMIN, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description=_desc(
                    observed=f"GET {self.admin_reports_path} was denied normally but returned "
                    "200 when an 'X-User-Role: admin' header was added.",
                    expected="Role is derived from the authenticated session server-side; "
                    "client headers are ignored.",
                    required_priv="Normal authenticated user (TEST_USER)",
                    detail="Authorization is decided from a client-supplied role header."),
                endpoint=f"GET {self.admin_reports_path}", parameter="X-User-Role",
                impact="Any user can access admin reports by sending a header.",
                reproduction=f"GET {self.admin_reports_path} with header X-User-Role: admin -> "
                "200.",
                remediation="Determine authorization from the server-side session/role only; "
                "never trust client-supplied role headers.",
                cwe="CWE-602 (Client-Side Enforcement of Server-Side Security)",
                owasp="API5:2023 Broken Function Level Authorization", module="admin_access",
                evidence=[ev] if ev else [])]
        return []
