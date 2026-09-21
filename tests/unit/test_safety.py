"""Tests for the classifier and the central safety controller."""
from gamebox.core.config import Config
from gamebox.core.models import RequestClass
from gamebox.safety.classifier import classify
from gamebox.safety.controller import SafetyController


def _config(**safety):
    return Config.from_dict({
        "scope": {"api_hosts": ["api.test"], "domains": ["app.test"]},
        "safety": safety,
    })


def test_classify_read_only():
    assert classify("GET", "https://api.test/profile") == RequestClass.READ_ONLY


def test_classify_state_changing():
    assert classify("POST", "https://api.test/bonus/claim") == RequestClass.STATE_CHANGING


def test_classify_financial_wins_over_declared_safe():
    # A financial keyword must not be downgraded to SAFE_TEST.
    rc = classify("POST", "https://api.test/wallet/withdraw",
                  declared=RequestClass.SAFE_TEST)
    assert rc == RequestClass.FINANCIAL


def test_classify_destructive_method():
    assert classify("DELETE", "https://api.test/user/1") == RequestClass.DESTRUCTIVE


def test_controller_blocks_state_change_by_default():
    ctrl = SafetyController(_config())
    d = ctrl.authorize("POST", "https://api.test/bonus/claim", "{}")
    assert not d.allowed
    assert d.request_class == RequestClass.STATE_CHANGING


def test_controller_allows_state_change_when_enabled():
    ctrl = SafetyController(_config(allow_state_changes=True))
    d = ctrl.authorize("POST", "https://api.test/bonus/claim", "{}")
    assert d.allowed


def test_controller_blocks_out_of_scope():
    ctrl = SafetyController(_config(allow_state_changes=True))
    d = ctrl.authorize("GET", "https://evil.example.com/")
    assert not d.allowed
    assert "scope" in d.reason


def test_controller_hard_denylist_never_allowed():
    ctrl = SafetyController(_config(allow_financial_operations=True,
                                    allow_state_changes=True,
                                    allow_destructive_tests=True))
    d = ctrl.authorize("POST", "https://api.test/real-withdraw", "{}")
    assert not d.allowed
    assert "hard deny" in d.reason


def test_financial_blocked_even_when_state_changes_enabled():
    ctrl = SafetyController(_config(allow_state_changes=True))
    d = ctrl.authorize("POST", "https://api.test/wallet/withdraw", "{}")
    assert not d.allowed
    assert d.request_class == RequestClass.FINANCIAL
