import base64
import json
import time
from typing import Dict, Any


def base64url_decode(input_str: str) -> bytes:
    """Decode Base64URL without padding."""
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


def decode_jwt(token: str) -> Dict[str, Any]:
    """Split and decode JWT header & payload without verifying signature."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        return {"error": "Token is not a valid JWT (must contain 3 parts)"}

    try:
        header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))
    except Exception:
        return {"error": "Failed to decode JWT. Invalid Base64URL or JSON."}

    return {
        "header": header,
        "payload": payload,
        "signature": signature_b64
    }


def validate_claims(decoded: Dict[str, Any]) -> Dict[str, Any]:
    """Validate standard JWT claims: iss, aud, exp, nbf, iat."""
    if "error" in decoded:
        return {"valid": False, "error": decoded["error"]}

    payload = decoded.get("payload", {})
    now = int(time.time())

    results = {
        "iss": None,
        "aud": None,
        "exp": None,
        "nbf": None,
        "iat": None,
        "overall_valid": True,
        "messages": []
    }

    # Validate issuer
    if "iss" not in payload:
        results["messages"].append("Missing 'iss' (issuer) claim.")
        results["overall_valid"] = False
    else:
        results["iss"] = payload["iss"]

    # Validate audience
    if "aud" not in payload:
        results["messages"].append("Missing 'aud' (audience) claim.")
        results["overall_valid"] = False
    else:
        results["aud"] = payload["aud"]

    # Validate expiration
    if "exp" in payload:
        exp = payload["exp"]
        results["exp"] = exp
        if now > exp:
            results["messages"].append(f"Token expired {now - exp} seconds ago.")
            results["overall_valid"] = False
    else:
        results["messages"].append("Missing 'exp' (expiration) claim.")
        results["overall_valid"] = False

    # Validate not-before
    if "nbf" in payload:
        nbf = payload["nbf"]
        results["nbf"] = nbf
        if now < nbf:
            results["messages"].append("Token is not valid yet (nbf in the future).")
            results["overall_valid"] = False

    # Validate issued-at
    if "iat" in payload:
        iat = payload["iat"]
        results["iat"] = iat
        if now < iat:
            results["messages"].append("Token 'iat' is in the future.")
            results["overall_valid"] = False

    if results["overall_valid"]:
        results["messages"].append("All standard claims are valid.")

    return results

