
from typing import Dict, Any


def basic_troubleshooting(decoded: Dict[str, Any], claims: Dict[str, Any], signature: Dict[str, Any]) -> Dict[str, Any]:
    """
    Basic troubleshooting engine.
    Detects the most common JWT issues.
    """

    issues = []

    # 1. Check for decoding errors
    if "error" in decoded:
        issues.append("Token could not be decoded. It may be malformed.")
        return {"issues": issues}

    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    # 2. Check algorithm
    alg = header.get("alg")
    if alg != "RS256":
        issues.append(f"Token uses algorithm '{alg}'. Expected RS256.")

    # 3. Check for missing claims
    required_claims = ["iss", "aud", "exp"]
    for claim in required_claims:
        if claim not in payload:
            issues.append(f"Missing required claim: {claim}")

    # 4. Check signature result
    if not signature.get("valid", False):
        issues.append(f"Signature invalid: {signature.get('error')}")

    # 5. Check claim validation result
    if not claims.get("overall_valid", False):
        issues.append("One or more standard claims are invalid.")

    # 6. Check if token looks like an ID token used as access token
    if "scp" not in payload and "roles" not in payload:
        issues.append("Token has no 'scp' or 'roles'. It may be an ID token used as an access token.")

    # 7. Check issuer format
    iss = payload.get("iss", "")
    if iss and not iss.startswith("https://"):
        issues.append("Issuer (iss) is not a valid HTTPS URL.")

    return {"issues": issues if issues else ["No basic issues detected. Token looks OK."]}
