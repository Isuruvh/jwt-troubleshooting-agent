from typing import Dict, Any


def basic_troubleshooting(decoded: Dict[str, Any], claims: Dict[str, Any], signature: Dict[str, Any]) -> Dict[str, Any]:
    """
    Improved troubleshooting engine.
    Supports all algorithms and avoids false warnings.
    """

    issues = []

    # ----------------------------------------------------
    # 1. Check for decoding errors
    # ----------------------------------------------------
    if "error" in decoded:
        issues.append("Token could not be decoded. It may be malformed.")
        return {"issues": issues}

    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    # ----------------------------------------------------
    # 2. Algorithm analysis (no more RS256 assumption)
    # ----------------------------------------------------
    alg = header.get("alg")

    supported_algs = [
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512"
    ]

    if alg not in supported_algs:
        issues.append(f"Unsupported or unknown algorithm '{alg}'.")
    else:
        # Helpful hint: algorithm mismatch between token and JWKS
        if signature.get("error") and "key" in signature.get("error", "").lower():
            issues.append(f"Token uses '{alg}' but matching key was not found in JWKS.")

    # ----------------------------------------------------
    # 3. Missing required claims
    # ----------------------------------------------------
    required_claims = ["iss", "aud", "exp"]
    for claim in required_claims:
        if claim not in payload:
            issues.append(f"Missing required claim: {claim}")

    # ----------------------------------------------------
    # 4. Signature validation result
    # ----------------------------------------------------
    if not signature.get("valid", False):
        issues.append(f"Signature invalid: {signature.get('error')}")

    # ----------------------------------------------------
    # 5. Claim validation result
    # ----------------------------------------------------
    if not claims.get("overall_valid", False):
        issues.append("One or more standard claims are invalid.")

    # ----------------------------------------------------
    # 6. Token type analysis (ID token vs Access token)
    # ----------------------------------------------------
    # Access tokens normally contain: scp, roles, permissions, or custom claims
    # ID tokens normally contain: name, email, sub, auth_time, etc.

    has_access_claims = any(k in payload for k in ["scp", "roles", "permissions"])
    has_id_claims = any(k in payload for k in ["email", "name", "auth_time"])

    if not has_access_claims and has_id_claims:
        issues.append("Token appears to be an ID token, not an access token.")

    # ----------------------------------------------------
    # 7. Issuer format check
    # ----------------------------------------------------
    iss = payload.get("iss", "")
    if iss and not iss.startswith("https://"):
        issues.append("Issuer (iss) is not a valid HTTPS URL.")

    # ----------------------------------------------------
    # Final output
    # ----------------------------------------------------
    return {"issues": issues if issues else ["No issues detected. Token looks OK."]}
