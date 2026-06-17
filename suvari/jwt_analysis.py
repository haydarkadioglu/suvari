"""
JWT Analysis — decodes, analyzes, and tests JWT tokens.
Tests: algorithm confusion, none algorithm, brute force, expiration.
"""

import json
import base64
import subprocess
from typing import Optional


def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format (expected 3 parts)"}

        def b64_decode(data: str) -> str:
            # Add padding
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            try:
                return base64.urlsafe_b64decode(data).decode("utf-8")
            except Exception:
                return base64.b64decode(data).decode("utf-8")

        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))

        return {
            "header": header,
            "payload": payload,
            "alg": header.get("alg", "unknown"),
            "typ": header.get("typ", "JWT"),
            "exp": payload.get("exp", None),
            "iss": payload.get("iss", None),
            "sub": payload.get("sub", None),
            "kid": header.get("kid", None),
        }
    except Exception as e:
        return {"error": f"Failed to decode JWT: {e}"}


def test_none_algorithm(token: str) -> Optional[str]:
    """Test if server accepts 'none' algorithm JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    # Create modified token with alg: none
    try:
        header = json.dumps({"alg": "none", "typ": "JWT"})
        b64_header = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
        forged = f"{b64_header}.{parts[1]}."  # No signature
        return forged
    except Exception:
        return None


def test_algorithm_confusion(token: str) -> list:
    """Test algorithm confusion: change RS256 to HS256."""
    findings = []
    parts = token.split(".")
    if len(parts) != 3:
        return findings

    try:
        # Change RS256 -> HS256 (use public key as HMAC secret)
        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        b64_header = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
        payload = parts[1]

        # Try common weak secrets
        for secret in ["secret", "password", "key", "123456", "admin", "changeme"]:
            forged = f"{b64_header}.{payload}.{_hmac_sign(f'{b64_header}.{payload}', secret)}"
            findings.append({
                "type": "Algorithm Confusion Test",
                "forged_token": forged[:60] + "...",
                "secret_tried": secret,
                "procedure": f"Changed alg from RS256 to HS256 with secret='{secret}'",
            })
    except Exception:
        pass

    return findings


def _hmac_sign(data: str, secret: str) -> str:
    """Simple HMAC-SHA256 signer."""
    import hashlib
    import hmac
    sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def brute_force_weak_keys(token: str, wordlist: list = None) -> Optional[str]:
    """Try to brute force HMAC secret."""
    if wordlist is None:
        wordlist = ["secret", "password", "key", "123456", "admin", "changeme",
                     "token", "jwt", "supersecret", "pass", "test", "dev",
                     "api_key", "private", "s3cr3t", "p@ssw0rd"]

    parts = token.split(".")
    if len(parts) != 3:
        return None

    data = f"{parts[0]}.{parts[1]}"
    target_sig = parts[2]

    # Add padding for comparison
    padding = 4 - len(target_sig) % 4
    target_bytes = base64.urlsafe_b64decode(target_sig + "=" * padding if padding != 4 else target_sig)

    for secret in wordlist:
        try:
            sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
            if sig == target_bytes:
                return secret
        except Exception:
            continue
    return None


import hmac, hashlib  # noqa


def analyze_jwt(token: str) -> dict:
    """Full JWT analysis."""
    result = decode_jwt(token)
    if "error" in result:
        return result

    findings = []

    # Check expiration
    if result.get("exp"):
        import time
        if time.time() > result["exp"]:
            findings.append({"type": "Expired Token", "severity": "INFO"})
        else:
            expires_in = result["exp"] - time.time()
            if expires_in > 86400 * 365:
                findings.append({"type": "Token never expires", "severity": "MEDIUM"})

    # Check algorithm
    alg = result.get("alg", "")
    if alg == "none":
        findings.append({"type": "Insecure Algorithm: none", "severity": "CRITICAL"})
    elif alg == "HS256":
        weak_secret = brute_force_weak_keys(token)
        if weak_secret:
            findings.append({"type": f"Weak HMAC Secret Found: {weak_secret}", "severity": "HIGH"})
    elif alg in ("RS256", "RS384", "RS512"):
        # Test algorithm confusion
        confusion_results = test_algorithm_confusion(token)
        findings.extend(confusion_results)

    # Check for sensitive data in payload
    payload = result.get("payload", {})
    sensitive = ["password", "secret", "token", "key", "credential", "admin"]
    for key in payload:
        if any(s in key.lower() for s in sensitive):
            findings.append({"type": f"Sensitive data in JWT payload: {key}", "severity": "MEDIUM"})

    return {
        "decoded": result,
        "findings": findings,
        "summary": f"{len(findings)} JWT issues found",
    }
