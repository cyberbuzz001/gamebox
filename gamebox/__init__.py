"""GAMEBOX SECURITY AUDITOR.

An authorized, safety-first black-box security assessment framework for
gaming platforms (betting, casino, card games, wallets, bonus systems).

Design principles:
  * Safety and scope are enforced centrally, before any request leaves the tool.
  * State-changing / financial / destructive operations are BLOCKED by default.
  * Every finding carries evidence; every piece of evidence is redacted.
  * Nothing in this package performs real financial operations.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
