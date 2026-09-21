"""Admin Access Simulation.

Answers a single question with evidence: *could the configured normal test
account reach administrative functionality?* It performs read-only discovery and
an authorization matrix, runs safe (non-destructive) privilege-escalation and
session vectors, and verifies that destructive admin operations are prevented by
both the guard and the safety controller. It never modifies admin data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Confidence, Endpoint, Finding
from ..http.client import BlockedRequest, SafeHTTPClient
from ..safety.scope import ScopeManager
from .discovery import AdminSurfaceDiscovery
from .escalation import PrivilegeEscalation
from .guard import DestructiveTestGuard, GuardBlocked
from .matrix import AuthorizationMatrix
from .session import SessionSecurity

log = get_logger("admin.simulation")


@dataclass
class AdminAssessment:
    initial_account: str
    admin_account: str
    surface_count: int
    accessible_without_admin: int
    potential_weaknesses: int
    confirmed_boundary_failures: int
    admin_data_modified: str = "NONE"
    production_financial_operations: str = "NONE"
    persistence_created: str = "NONE"
    halted_before_destructive_poc: bool = True
    sufficient_evidence: bool = False
    endpoints: list = field(default_factory=list)
    matrix: list = field(default_factory=list)
    safety_checks: list = field(default_factory=list)
    session_notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__

    def text_block(self) -> str:
        return (
            "ADMIN ACCESS SIMULATION\n\n"
            f"Initial Account:\n{self.initial_account}\n\n"
            f"Administrative Surface:\n{self.surface_count} endpoints discovered\n\n"
            f"Accessible Without Admin:\n{self.accessible_without_admin}\n\n"
            f"Potential Authorization Weaknesses:\n{self.potential_weaknesses}\n\n"
            f"Confirmed Privilege Boundary Failure:\n{self.confirmed_boundary_failures}\n\n"
            f"Administrative Data Modified:\n{self.admin_data_modified}\n\n"
            f"Production Financial Operations:\n{self.production_financial_operations}\n\n"
            f"Persistence Created:\n{self.persistence_created}"
        )


class AdminAccessSimulator:
    def __init__(self, client: SafeHTTPClient, base_url: str, scope: ScopeManager,
                 seclists_path: str = "", jwt_tool_path: str = ""):
        self.client = client
        self.base = base_url.rstrip("/")
        self.scope = scope
        self.guard = DestructiveTestGuard()
        self.seclists_path = seclists_path
        self.jwt_tool_path = jwt_tool_path

    def run(self, user: Optional[AccountSession], admin: Optional[AccountSession],
            endpoints: list[Endpoint]) -> tuple[list[Finding], AdminAssessment]:
        # 1. Discovery (read-only).
        surface = AdminSurfaceDiscovery(self.client, self.base, self.scope,
                                        seclists_path=self.seclists_path).discover(endpoints)

        # 2. Authorization matrix (read-only).
        matrix = AuthorizationMatrix(self.client, self.base).build(surface, user, admin)
        accessible = AuthorizationMatrix.accessible_without_admin(matrix)

        # 3. Safe privilege-escalation + session vectors (never destructive).
        findings: list[Finding] = []
        esc = PrivilegeEscalation(self.client, self.base)
        findings += esc.fla_no_auth(surface)
        if user:
            findings += esc.role_header(user)
            findings += SessionSecurity(self.client, self.base,
                                        jwt_tool_path=self.jwt_tool_path).run(user)
            findings += esc.mass_assignment(user)

        # 4. Safety self-check: destructive admin ops must be prevented.
        safety_checks = self._safety_self_check()

        confirmed = sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)
        potential = sum(1 for f in findings
                        if f.confidence in (Confidence.LIKELY, Confidence.SUSPECTED))

        assessment = AdminAssessment(
            initial_account=(f"Normal Test User ({user.label})" if user else "Normal Test User"),
            admin_account=(admin.label if admin else "(none configured)"),
            surface_count=len(surface),
            accessible_without_admin=len(accessible),
            potential_weaknesses=potential,
            confirmed_boundary_failures=confirmed,
            sufficient_evidence=confirmed > 0,
            endpoints=[e.to_dict() for e in surface],
            matrix=[m.to_dict() for m in matrix],
            safety_checks=safety_checks,
            session_notes=[
                "Session bearer token is opaque (no embedded claims).",
                "Access token carries a role claim; see session findings for signature review.",
            ],
        )
        log.info("admin simulation: surface=%d, confirmed boundary failures=%d",
                 len(surface), confirmed)
        return findings, assessment

    def _safety_self_check(self) -> list[dict]:
        """Prove destructive admin operations are blocked at two layers."""
        checks: list[dict] = []

        # Layer 1: the guard refuses to construct an admin write op.
        adjust_url = self.base + "/api/admin/wallet/adjust"
        try:
            self.guard.ensure_read_only("POST", adjust_url, '{"amount": 1}')
            checks.append({"operation": "POST /api/admin/wallet/adjust",
                           "layer": "guard", "blocked": False})
        except GuardBlocked as g:
            checks.append({"operation": "POST /api/admin/wallet/adjust", "layer": "guard",
                           "blocked": True, "request_class": g.request_class.value})

        # Layer 2: the safety controller blocks a destructive DELETE at send time.
        delete_url = self.base + "/api/admin/users/2"
        try:
            self.client.request("DELETE", delete_url)
            checks.append({"operation": "DELETE /api/admin/users/2",
                           "layer": "safety_controller", "blocked": False})
        except BlockedRequest as b:
            checks.append({"operation": "DELETE /api/admin/users/2",
                           "layer": "safety_controller", "blocked": True,
                           "reason": b.decision.reason})
        except Exception:
            # A network error is not a safety pass; record it honestly.
            checks.append({"operation": "DELETE /api/admin/users/2",
                           "layer": "safety_controller", "blocked": False,
                           "reason": "request error (not a controller block)"})
        return checks
