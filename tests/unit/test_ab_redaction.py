from gamebox.andarbahar.ws_client import sanitize


def test_sanitize_redacts_credentials():
    out = sanitize({"type": "AUTH", "token": "test-token", "password": "p", "user_id": 1})
    assert out["token"] == "***REDACTED***"
    assert out["password"] == "***REDACTED***"
    assert out["user_id"] == 1
