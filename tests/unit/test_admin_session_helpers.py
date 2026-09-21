from gamebox.admin.session import _b64url_decode, _b64url_encode


def test_roundtrip_and_forge():
    claims = {"uid": 1, "role": "user", "is_admin": False}
    tok = _b64url_encode(claims)
    assert _b64url_decode(tok) == claims
    forged = dict(claims); forged["role"] = "admin"; forged["is_admin"] = True
    tok2 = _b64url_encode(forged)
    assert _b64url_decode(tok2)["role"] == "admin"
