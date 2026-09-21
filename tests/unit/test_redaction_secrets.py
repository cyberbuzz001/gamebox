from gamebox.core.logger import redact


def test_stripe_key_masked():
    # Assemble the Stripe-shaped value at runtime so the source file itself does
    # not contain a provider-key pattern (avoids VCS secret-scan false positives).
    key = "sk_test_" + "51H8qEXAMPLEabcdef123456"
    out = redact('config: {"stripe_key": "%s"}' % key)
    assert key not in out


def test_compound_key_masked():
    out = redact('{"password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"}')
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in out


def test_jwt_secret_masked():
    out = redact('{"jwt_secret": "demo-jwt-secret-do-not-use"}')
    assert "demo-jwt-secret-do-not-use" not in out
