"""Attack-chain correlation (Phase 18).

Combines individual findings into higher-impact chains, but only emits a chain
when all of its component findings are actually present in the results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..core.models import Finding


@dataclass
class AttackChain:
    name: str
    steps: list[str]
    initial_weakness: str
    required_privileges: str
    boundary_crossed: str
    result: str
    business_impact: str
    remediation: str
    component_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


def _has(findings: list[Finding], *needles: str) -> Finding | None:
    for f in findings:
        hay = (f.title + " " + f.category.value + " " + f.module).lower()
        if all(n.lower() in hay for n in needles):
            return f
    return None


# Each rule: (name, predicate builder). Predicate returns an AttackChain or None.
def _chain_balance_inflation(fs: list[Finding]) -> AttackChain | None:
    comp = [f for f in (
        _has(fs, "payout"), _has(fs, "settlement"),
        _has(fs, "bonus"), _has(fs, "webhook")) if f]
    if not comp:
        return None
    return AttackChain(
        name="Unauthorized balance inflation",
        steps=["Authenticate as a normal user",
               "Invoke a money-affecting flow that trusts client input or lacks "
               "idempotency (payout/settlement/bonus/webhook)",
               "Repeat / tamper to credit arbitrary amounts"],
        initial_weakness=comp[0].title,
        required_privileges="Single authenticated user",
        boundary_crossed="Wallet monetary integrity",
        result="Attacker-controlled balance increase (demonstrated on TEST_COINS)",
        business_impact="Direct financial loss and fraud exposure at scale",
        remediation="Server-authoritative outcomes + idempotent, signed, transactional "
                    "money operations",
        component_ids=[f.id for f in comp])


def _chain_account_takeover(fs: list[Finding]) -> AttackChain | None:
    enum = _has(fs, "enumeration")
    rl = _has(fs, "rate limiting")
    reset = _has(fs, "password reset")
    comp = [f for f in (enum, rl, reset) if f]
    if not (reset or (enum and rl)):
        return None
    return AttackChain(
        name="Account takeover path",
        steps=["Enumerate valid usernames from login responses" if enum else
               "Target a known account",
               "Abuse missing rate limiting to brute force" if rl else
               "Trigger the password-reset flow",
               "Recover/predict the reset token and seize the account" if reset else
               "Complete credential stuffing"],
        initial_weakness=(reset or enum or rl).title,
        required_privileges="Unauthenticated attacker",
        boundary_crossed="Authentication",
        result="Takeover of a targeted account",
        business_impact="Loss of user funds and trust; regulatory exposure",
        remediation="Generic auth errors, strict rate limiting/MFA, out-of-band single-use "
                    "reset tokens",
        component_ids=[f.id for f in comp])


def _chain_data_exposure(fs: list[Finding]) -> AttackChain | None:
    admin = _has(fs, "authorization", "admin") or _has(fs, "admin")
    idor = _has(fs, "idor") or _has(fs, "object-level")
    excessive = _has(fs, "excessive data")
    comp = [f for f in (admin, idor, excessive) if f]
    if len(comp) < 2:
        return None
    return AttackChain(
        name="Mass account/data exposure",
        steps=["Access an under-protected endpoint (admin or by-id)",
               "Enumerate object identifiers",
               "Harvest other users' data (balances, PII, internal fields)"],
        initial_weakness=comp[0].title,
        required_privileges="Unauthenticated or single low-priv user",
        boundary_crossed="Object/function authorization",
        result="Bulk read of other users' data",
        business_impact="Privacy breach, PII exposure, regulatory penalties",
        remediation="Deny-by-default authorization on every object and admin function; "
                    "return whitelist DTOs",
        component_ids=[f.id for f in comp])


def _chain_secret_escalation(fs: list[Finding]) -> AttackChain | None:
    secret = _has(fs, "secret")
    admin_cfg = _has(fs, "admin")
    comp = [f for f in (secret, admin_cfg) if f]
    if not secret:
        return None
    return AttackChain(
        name="Secret exposure to privilege escalation",
        steps=["Extract a secret from client source or an exposed config endpoint",
               "Use it (e.g. JWT secret) to forge tokens or authenticate to services",
               "Escalate privileges / access admin functions"],
        initial_weakness=secret.title,
        required_privileges="Unauthenticated attacker",
        boundary_crossed="Secret confidentiality / privilege",
        result="Forged trust material enabling escalation",
        business_impact="Full compromise potential",
        remediation="Remove secrets from clients/configs, rotate immediately, scope and "
                    "short-live tokens",
        component_ids=[f.id for f in comp])


_RULES: list[Callable[[list[Finding]], AttackChain | None]] = [
    _chain_balance_inflation, _chain_account_takeover,
    _chain_data_exposure, _chain_secret_escalation,
]


def correlate(findings: list[Finding]) -> list[AttackChain]:
    chains = []
    for rule in _RULES:
        chain = rule(findings)
        if chain:
            chains.append(chain)
    return chains
