import httpx
import jwt
from cachetools import TTLCache
from typing import Dict, Any

# Cache JWKS for 10 minutes (600 seconds)
jwks_cache = TTLCache(maxsize=10, ttl=600)


async def fetch_jwks(issuer: str) -> Dict[str, Any]:
    """
    Fetch JWKS from the issuer's well-known endpoint.
    Example: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
    """
    if issuer in jwks_cache:
        return jwks_cache[issuer]

    # Build OpenID configuration URL
    if not issuer.endswith("/"):
        issuer += "/"

    openid_config_url = issuer + ".well-known/openid-configuration"

    try:
        async with httpx.AsyncClient() as client:
            config_resp = await client.get(openid_config_url)
            config_resp.raise_for_status()
            config = config_resp.json()

            jwks_uri = config["jwks_uri"]

            jwks_resp = await client.get(jwks_uri)
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()

            jwks_cache[issuer] = jwks
            return jwks

    except Exception as e:
        return {"error": f"Failed to fetch JWKS: {str(e)}"}


def get_public_key(jwks: Dict[str, Any], kid: str):
    """Find the public key in JWKS matching the given kid."""
    if "keys" not in jwks:
        return None

    for key in jwks["keys"]:
        if key.get("kid") == kid:
            try:
                return jwt.PyJWK.from_dict(key).key
            except Exception:
                return None

    return None


async def verify_signature(token: str) -> Dict[str, Any]:
    """
    Verify RS256 signature using JWKS.
    Returns structured results for UI.
    """
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return {"valid": False, "error": "Invalid JWT header"}

    kid = header.get("kid")
    if not kid:
        return {"valid": False, "error": "Token header missing 'kid' field"}

    # Decode payload without verifying to extract issuer
    try:
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {"valid": False, "error": "Failed to decode JWT payload"}

    issuer = unverified_payload.get("iss")
    if not issuer:
        return {"valid": False, "error": "Token missing 'iss' claim"}

    # Fetch JWKS
    jwks = await fetch_jwks(issuer)
    if "error" in jwks:
        return {"valid": False, "error": jwks["error"]}

    # Get public key
    public_key = get_public_key(jwks, kid)
    if not public_key:
        return {
            "valid": False,
            "error": f"No matching key found in JWKS for kid: {kid}"
        }

    # Verify signature
    try:
        jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=None,  # Audience is validated separately in validator.py
            options={"verify_aud": False}
        )
        return {"valid": True, "message": "Signature is valid"}
    except Exception as e:
        return {"valid": False, "error": f"Signature verification failed: {str(e)}"}

