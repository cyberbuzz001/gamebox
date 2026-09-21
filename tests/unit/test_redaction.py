from gamebox.core.logger import redact, redact_headers


def test_redact_key_value():
    assert "s3cr3t" not in redact('{"password": "s3cr3t"}')
    assert "REDACTED" in redact('{"password": "s3cr3t"}')


def test_redact_bearer():
    out = redact("Authorization: Bearer abcdef123456token")
    assert "abcdef123456token" not in out


def test_redact_headers():
    h = redact_headers({"Authorization": "Bearer x", "Accept": "application/json"})
    assert h["Authorization"] == "***REDACTED***"
    assert h["Accept"] == "application/json"


def test_redact_extra_values():
    out = redact("balance token=none here is livetoken99", extra_values=["livetoken99"])
    assert "livetoken99" not in out
