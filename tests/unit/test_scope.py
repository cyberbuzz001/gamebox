from gamebox.core.config import ScopeConfig
from gamebox.safety.scope import ScopeManager, ScopeError
import pytest


def test_in_scope_exact():
    s = ScopeManager(ScopeConfig(api_hosts=["api.test"]))
    assert s.in_scope("https://api.test/x")
    assert not s.in_scope("https://other.test/x")


def test_wildcard():
    s = ScopeManager(ScopeConfig(domains=["*.example.test"]))
    assert s.in_scope("https://app.example.test/")
    assert s.in_scope("https://example.test/")
    assert not s.in_scope("https://example.evil/")


def test_excluded_wins():
    s = ScopeManager(ScopeConfig(domains=["*.example.test"],
                                 excluded_hosts=["pay.example.test"]))
    assert not s.in_scope("https://pay.example.test/")


def test_fail_closed_empty_allowlist():
    s = ScopeManager(ScopeConfig())
    assert not s.in_scope("https://anything.test/")


def test_enforce_raises():
    s = ScopeManager(ScopeConfig(api_hosts=["api.test"]))
    with pytest.raises(ScopeError):
        s.enforce("https://nope.test/")
