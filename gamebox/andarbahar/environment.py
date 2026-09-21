"""Environment policy for the WebSocket tester.

Environments: DEMO (default), STAGING, PRODUCTION.

  DEMO / STAGING  -> TEST_COINS, SAFE_MUTATION enabled, real payment/withdrawal
                     disabled.
  PRODUCTION      -> SAFE_READ_ONLY: game-result mutation, financial mutation and
                     destructive tests are all disabled. The tester refuses to
                     modify production game outcomes.
"""
from __future__ import annotations

from dataclasses import dataclass


class Environment:
    DEMO = "demo"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass(frozen=True)
class EnvironmentPolicy:
    environment: str = Environment.DEMO

    @classmethod
    def from_name(cls, name: str | None) -> "EnvironmentPolicy":
        env = (name or Environment.DEMO).strip().lower()
        if env not in (Environment.DEMO, Environment.STAGING, Environment.PRODUCTION):
            env = Environment.DEMO
        return cls(environment=env)

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def allow_mutation(self) -> bool:
        """SAFE_MUTATION / game-result mutation. Never in production."""
        return not self.is_production

    @property
    def allow_financial_mutation(self) -> bool:
        return False  # real payment/withdrawal are never enabled by this tool

    @property
    def safe_read_only(self) -> bool:
        return self.is_production

    def describe(self) -> dict:
        return {
            "environment": self.environment,
            "test_currency": "TEST_COINS",
            "safe_mutation": self.allow_mutation,
            "real_payment": False,
            "real_withdrawal": False,
            "game_result_mutation": self.allow_mutation,
            "safe_read_only": self.safe_read_only,
        }


class MutationBlocked(RuntimeError):
    """Raised when a mutation is attempted in an environment that forbids it."""
