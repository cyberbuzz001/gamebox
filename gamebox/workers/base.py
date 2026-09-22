"""Security Module & Worker Base Interfaces.

Provides standard asynchronous / synchronous job contracts for:
  * discover(target)
  * test(context)
  * validate(finding)
  * report(finding)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.models import Finding
from ..http.client import SafeHTTPClient


@dataclass
class WorkerContext:
    target_url: str
    client: SafeHTTPClient
    scope_domains: list[str] = field(default_factory=list)
    test_account: Optional[dict[str, Any]] = None
    configuration: dict[str, Any] = field(default_factory=dict)


class SecurityModule(ABC):
    """Common interface for all Game Security Lab scanning & testing workers."""

    name: str = "base_module"
    version: str = "1.0.0"

    @abstractmethod
    def discover(self, target: str) -> list[dict[str, Any]]:
        """Surface discovery without state modification."""
        ...

    @abstractmethod
    def test(self, context: WorkerContext) -> list[Finding]:
        """Execute active security assessments against authorized test targets."""
        ...

    @abstractmethod
    def validate(self, finding: Finding) -> dict[str, Any]:
        """Safely prove vulnerability existence stopping at minimal PoC."""
        ...

    @abstractmethod
    def report(self, finding: Finding) -> dict[str, Any]:
        """Format finding evidence, reproduction, and remediation guidance."""
        ...
