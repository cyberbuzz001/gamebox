"""Provably-fair verification (offline).

Vendored, dependency-free implementation of the standard commit/reveal scheme
used by crypto casinos, so the tester can VERIFY a game's fairness claims rather
than only observe statistics:

    commit:  the server publishes  H = SHA256(server_seed)   before the bet
    outcome: result = f( HMAC_SHA256(server_seed, "client_seed:nonce") )
    reveal:  the server later reveals server_seed; anyone can recompute H and
             the outcome and confirm they match.

This module performs only local hashing -- it never contacts a target and never
predicts a live outcome. It turns "SUSPECTED" randomness findings into
"CONFIRMED"/"PASS" when seed material is available (e.g. captured from an
authorized sandbox).

Reference schemes: rakestake/provably-fair-verifier, provably-fair/provably-fair-app.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.models import Category, Confidence, Finding, Severity

# Randomness architecture classifications.
CLIENT = "CLIENT"
SERVER = "SERVER"
SERVER_COMMITTED = "SERVER-COMMITTED RNG"
THIRD_PARTY = "THIRD-PARTY PROVIDER"
UNKNOWN = "UNKNOWN"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def verify_commitment(server_seed: str, committed_hash: str) -> bool:
    """True iff SHA256(server_seed) matches the pre-published commitment."""
    if not server_seed or not committed_hash:
        return False
    return hmac.compare_digest(sha256_hex(server_seed), committed_hash.lower().strip())


def outcome_hmac(server_seed: str, client_seed: str, nonce: int) -> str:
    msg = f"{client_seed}:{nonce}".encode()
    return hmac.new(server_seed.encode(), msg, hashlib.sha256).hexdigest()


def outcome_hmac_sha512(server_seed: str, client_seed: str, nonce: int) -> str:
    """SHA-512 HMAC variant used by some platforms."""
    msg = f"{client_seed}:{nonce}".encode()
    return hmac.new(server_seed.encode(), msg, hashlib.sha512).hexdigest()


def float_from_hmac(hmac_hex: str) -> float:
    """Map the first 8 hex chars of the HMAC to a float in [0, 1)."""
    return int(hmac_hex[:8], 16) / 0x100000000


def verify_crash_multiplier(server_seed: str, hmac_hex: str = "") -> float:
    """Verify a bustabit/crash-style multiplier.

    Standard formula: result = max(1, floor(2^52 / (2^52 - hash_int)))
    where hash_int is derived from the first 13 hex chars of the HMAC.

    Reference: bustabit provably-fair verification.
    """
    if not hmac_hex:
        h = hashlib.sha256(server_seed.encode()).hexdigest()
    else:
        h = hmac_hex
    hash_int = int(h[:13], 16)
    e = 2 ** 52
    if hash_int >= e:
        return 1.0
    return max(1.0, e / (e - hash_int))


@dataclass
class RoundVerification:
    nonce: int
    commitment_valid: Optional[bool]
    computed_hmac: str
    computed_float: float
    computed_outcome: object = None
    claimed_outcome: object = None
    outcome_match: Optional[bool] = None

    @property
    def is_failure(self) -> bool:
        return self.commitment_valid is False or self.outcome_match is False

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ProvablyFairReport:
    architecture: str = UNKNOWN
    rounds: list = field(default_factory=list)     # list[RoundVerification]
    findings: list = field(default_factory=list)   # list[Finding]

    def to_dict(self) -> dict:
        return {"architecture": self.architecture,
                "rounds": [r.to_dict() for r in self.rounds],
                "findings": [f.to_dict() for f in self.findings]}


class ProvablyFairVerifier:
    """Verifies commit/reveal fairness for a set of observed rounds.

    ``outcome_fn`` maps a float in [0,1) to the game's outcome space (e.g. a card
    index or crash multiplier); when supplied and a claimed outcome is present,
    the verifier checks the server's claimed result against the recomputed one.
    """

    def __init__(self, outcome_fn: Optional[Callable[[float], object]] = None):
        self.outcome_fn = outcome_fn

    def verify_round(self, server_seed: str, client_seed: str, nonce: int,
                     committed_hash: str = "", claimed_outcome: object = None
                     ) -> RoundVerification:
        commitment = verify_commitment(server_seed, committed_hash) if committed_hash else None
        h = outcome_hmac(server_seed, client_seed, nonce)
        f = float_from_hmac(h)
        computed = self.outcome_fn(f) if self.outcome_fn else None
        match = None
        if claimed_outcome is not None and computed is not None:
            match = computed == claimed_outcome
        return RoundVerification(nonce=nonce, commitment_valid=commitment,
                                 computed_hmac=h, computed_float=f,
                                 computed_outcome=computed, claimed_outcome=claimed_outcome,
                                 outcome_match=match)

    def verify(self, observations: list[dict]) -> ProvablyFairReport:
        """observations: [{server_seed, client_seed, nonce, committed_hash?,
        claimed_outcome?}]."""
        report = ProvablyFairReport()
        any_commit = False
        for obs in observations:
            rv = self.verify_round(
                obs.get("server_seed", ""), obs.get("client_seed", ""),
                int(obs.get("nonce", 0)), obs.get("committed_hash", ""),
                obs.get("claimed_outcome"))
            report.rounds.append(rv)
            if rv.commitment_valid is not None:
                any_commit = True

        report.architecture = self.classify(report.rounds, any_commit)
        report.findings = self._findings(report.rounds)
        return report

    @staticmethod
    def classify(rounds: list[RoundVerification], any_commitment: bool) -> str:
        if not rounds:
            return UNKNOWN
        if any_commitment and all(r.commitment_valid is not False for r in rounds):
            return SERVER_COMMITTED
        return UNKNOWN

    def _findings(self, rounds: list[RoundVerification]) -> list[Finding]:
        out: list[Finding] = []
        bad_commit = [r for r in rounds if r.commitment_valid is False]
        bad_outcome = [r for r in rounds if r.outcome_match is False]
        if bad_commit:
            out.append(Finding(
                title="Provably-fair commitment mismatch (revealed seed does not match hash)",
                category=Category.GAME, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description=f"For {len(bad_commit)} round(s) SHA256(server_seed) did not equal "
                "the pre-published commitment hash. The fairness proof is broken -- the server "
                "may be selecting seeds after the bet.",
                endpoint="(provably-fair verification)", parameter="server_seed/committed_hash",
                impact="The house can alter outcomes despite claiming provable fairness.",
                reproduction="Recompute SHA256(server_seed) and compare to the published "
                "commitment; they differ.",
                remediation="Publish the commitment before the bet and reveal the exact seed "
                "that hashes to it; never rotate seeds post-commit.",
                cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                owasp="game integrity / provable fairness", module="provably_fair"))
        if bad_outcome:
            out.append(Finding(
                title="Game result does not match provably-fair computation",
                category=Category.GAME, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description=f"For {len(bad_outcome)} round(s) the server's claimed outcome did "
                "not match the outcome recomputed from the revealed seeds.",
                endpoint="(provably-fair verification)", parameter="result",
                impact="Outcomes are not derived from the committed seeds; results can be "
                "manipulated.",
                reproduction="Recompute f(HMAC(server_seed, client_seed:nonce)); it differs "
                "from the claimed result.",
                remediation="Derive every outcome deterministically from the committed seeds "
                "with a published algorithm.",
                cwe="CWE-330 (Use of Insufficiently Random Values)",
                owasp="game integrity / provable fairness", module="provably_fair"))
        return out


class ProvablyFairDetector:
    """Heuristically detect provably-fair fields in API responses.

    Scans JSON response bodies for field names that indicate a
    commit/reveal scheme, allowing the RandomnessAnalyzer to
    automatically extract seed data for verification.
    """

    # Field names that suggest provably-fair seed material.
    _SEED_FIELDS = {
        "server_seed", "serverSeed", "server_seed_hash", "serverSeedHash",
        "client_seed", "clientSeed", "nonce", "round_nonce",
        "committed_hash", "committedHash", "seed_hash", "seedHash",
        "server_seed_revealed", "revealed_seed", "revealedSeed",
        "hash_commitment", "commitment",
    }

    @classmethod
    def detect_from_response(cls, body: dict) -> Optional[dict]:
        """Extract provably-fair fields from a response body.

        Returns a dict with normalized keys if PF fields are found, else None.
        Keys: server_seed, client_seed, nonce, committed_hash, claimed_outcome.
        """
        if not isinstance(body, dict):
            return None

        found = {}
        flat = cls._flatten(body)
        for key, value in flat.items():
            key_lower = key.lower().replace("-", "_")
            if key_lower in ("server_seed", "serverseed", "server_seed_revealed",
                             "revealed_seed", "revealedseed"):
                found["server_seed"] = str(value)
            elif key_lower in ("client_seed", "clientseed"):
                found["client_seed"] = str(value)
            elif key_lower in ("nonce", "round_nonce"):
                found["nonce"] = value
            elif key_lower in ("server_seed_hash", "serverseedhash", "seed_hash",
                               "seedhash", "committed_hash", "committedhash",
                               "hash_commitment", "commitment"):
                found["committed_hash"] = str(value)
            elif key_lower in ("result", "outcome", "game_result"):
                found["claimed_outcome"] = value

        # Return only if we have at least server_seed or committed_hash.
        if "server_seed" in found or "committed_hash" in found:
            return found
        return None

    @staticmethod
    def _flatten(d: dict, prefix: str = "") -> dict:
        """Flatten nested dicts into dot-separated keys."""
        items: dict = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.update(ProvablyFairDetector._flatten(v, key))
            else:
                items[k] = v  # Use leaf key name only for matching.
        return items
