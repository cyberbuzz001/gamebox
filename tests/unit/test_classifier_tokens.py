from gamebox.safety.classifier import classify
from gamebox.core.models import RequestClass


def test_settings_not_confused_with_set():
    # Regression: 'set' must not match the 'settings' path segment.
    assert classify("GET", "https://api.test/api/admin/settings") == RequestClass.READ_ONLY


def test_adjustments_read_is_read_only():
    assert classify("GET", "https://api.test/api/admin/wallet/adjustments") == RequestClass.READ_ONLY


def test_profile_update_is_state_changing():
    assert classify("POST", "https://api.test/api/profile/update",
                    '{"is_admin":true}') == RequestClass.STATE_CHANGING


def test_reset_password_path_still_destructive_token():
    # 'reset' as a standalone token still classifies as destructive.
    assert classify("POST", "https://api.test/api/admin/reset") == RequestClass.DESTRUCTIVE
