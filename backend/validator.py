import base64
import json
import time
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------
# Base64URL decode helper
# ---------------------------------------------------------
def base64url_decode(input_str: str) -> bytes:
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


# ---------------------------------------------------------
# Decode JWT (header + payload only)
# ---------------------------------------------------------
def decode_jwt(token: str) -> Dict[str, Any]:
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
        "signature": signature_b64,
        "header_b64": header_b64,
        "payload_b64": payload_b64
    }


# ---------------------------------------------------------
# Validate standard claims
# ---------------------------------------------------------
def validate_claims(decoded: Dict[str, Any]) -> Dict[str, Any]:
    if "error" in decoded:
        return {"valid": False, "error": decoded["error"]}

    payload = decoded.get("payload", {})
    now = int(time.time())

    results = {
        "iss": payload.get("iss"),
        "aud": payload.get("aud"),
        "exp": payload.get("exp"),
        "nbf": payload.get("nbf"),
        "iat": payload.get("iat"),
        "overall_valid": True,
        "messages": []
    }

    # iss
    if "iss" not in payload:
        results["messages"].append("Missing 'iss' (issuer) claim.")
        results["overall_valid"] = False

    # aud
    if "aud" not in payload:
        results["messages"].append("Missing 'aud' (audience) claim.")
        results["overall_valid"] = False

    # exp
    if "exp" in payload:
        if now > payload["exp"]:
            results["messages"].append(f"Token expired {now - payload['exp']} seconds ago.")
            results["overall_valid"] = False
    else:
        results["messages"].append("Missing 'exp' (expiration) claim.")
        results["overall_valid"] = False

    # nbf
    if "nbf" in payload and now < payload["nbf"]:
        results["messages"].append("Token is not valid yet (nbf in the future).")
        results["overall_valid"] = False

    # iat
    if "iat" in payload and now < payload["iat"]:
        results["messages"].append("Token 'iat' is in the future.")
        results["overall_valid"] = False

    if results["overall_valid"]:
        results["messages"].append("All standard claims are valid.")

    return results


# ---------------------------------------------------------
# Signature Validator Class
# ---------------------------------------------------------
class SignatureValidator:

    def __init__(self, jwks: Optional[Dict[str, Any]] = None,
                 secret: Optional[str] = None,
                 manual_public_key_pem: Optional[str] = None):
        self.jwks = jwks
        self.secret = secret
        self.manual_public_key_pem = manual_public_key_pem

    # -----------------------------------------------------
    # Load manual PEM public key
    # -----------------------------------------------------
    def _load_pem_key(self):
        if not self.manual_public_key_pem:
            return None
        try:
            return serialization.load_pem_public_key(
                self.manual_public_key_pem.encode()
            )
        except Exception:
            return None

    # -----------------------------------------------------
    # Main router
    # -----------------------------------------------------
    def validate(self, decoded: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in decoded:
            return {"valid": False, "error": decoded["error"]}

        header = decoded["header"]
        alg = header.get("alg")
        kid = header.get("kid")

        signature = base64url_decode(decoded["signature"])
        signing_input = f"{decoded['header_b64']}.{decoded['payload_b64']}".encode()

        # Prefer manual PEM key if provided
        if self.manual_public_key_pem and alg.startswith(("RS", "PS", "ES")):
            public_key = self._load_pem_key()
            if public_key:
                return self._validate_with_manual_key(alg, signing_input, signature, public_key)

        # HMAC
        if alg.startswith("HS"):
            return self._validate_hs(alg, signing_input, signature)

        # RSA
        if alg.startswith("RS"):
            return self._validate_rs(alg, signing_input, signature, kid)

        # RSA-PSS
        if alg.startswith("PS"):
            return self._validate_ps(alg, signing_input, signature, kid)

        # ECDSA
        if alg.startswith("ES"):
            return self._validate_es(alg, signing_input, signature, kid)

        return {"valid": False, "error": f"Unsupported algorithm: {alg}"}

    # -----------------------------------------------------
    # Manual PEM key validation
    # -----------------------------------------------------
    def _validate_with_manual_key(self, alg, signing_input, signature, public_key):
        hash_map = {
            "RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512(),
            "PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512(),
            "ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512(),
        }

        try:
            if alg.startswith("RS"):
                public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_map[alg])
                return {"valid": True, "message": "RSA signature valid (manual key)"}

            if alg.startswith("PS"):
                public_key.verify(
                    signature,
                    signing_input,
                    padding.PSS(
                        mgf=padding.MGF1(hash_map[alg]),
                        salt_length=hash_map[alg].digest_size
                    ),
                    hash_map[alg]
                )
                return {"valid": True, "message": "RSA-PSS signature valid (manual key)"}

            if alg.startswith("ES"):
                half = len(signature) // 2
                r = int.from_bytes(signature[:half], "big")
                s = int.from_bytes(signature[half:], "big")
                der_sig = encode_dss_signature(r, s)

                public_key.verify(der_sig, signing_input, ec.ECDSA(hash_map[alg]))
                return {"valid": True, "message": "ECDSA signature valid (manual key)"}

        except Exception as e:
            return {"valid": False, "error": f"Invalid signature using manual key: {str(e)}"}

    # -----------------------------------------------------
    # HS256 / HS384 / HS512
    # -----------------------------------------------------
    def _validate_hs(self, alg, signing_input, signature):
        if not self.secret:
            return {"valid": False, "error": "HS256/384/512 requires a shared secret"}

        hash_map = {
            "HS256": hashes.SHA256(),
            "HS384": hashes.SHA384(),
            "HS512": hashes.SHA512(),
        }

        h = HMAC(self.secret.encode(), hash_map[alg])
        h.update(signing_input)

        try:
            h.verify(signature)
            return {"valid": True, "message": "HMAC signature valid"}
        except Exception:
            return {"valid": False, "error": "Invalid HMAC signature"}

    # -----------------------------------------------------
    # RS256 / RS384 / RS512
    # -----------------------------------------------------
    def _validate_rs(self, alg, signing_input, signature, kid):
        key = self._get_jwk_key(kid)
        if not key:
            return {"valid": False, "error": "Matching RSA key not found in JWKS"}

        public_key = self._load_rsa_key(key)

        hash_map = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
        }

        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hash_map[alg]
            )
            return {"valid": True, "message": "RSA signature valid"}
        except Exception:
            return {"valid": False, "error": "Invalid RSA signature"}

    # -----------------------------------------------------
    # PS256 / PS384 / PS512
    # -----------------------------------------------------
    def _validate_ps(self, alg, signing_input, signature, kid):
        key = self._get_jwk_key(kid)
        if not key:
            return {"valid": False, "error": "Matching RSA key not found in JWKS"}

        public_key = self._load_rsa_key(key)

        hash_map = {
            "PS256": hashes.SHA256(),
            "PS384": hashes.SHA384(),
            "PS512": hashes.SHA512(),
        }

        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hash_map[alg]),
                    salt_length=hash_map[alg].digest_size
                ),
                hash_map[alg]
            )
            return {"valid": True, "message": "RSA-PSS signature valid"}
        except Exception:
            return {"valid": False, "error": "Invalid RSA-PSS signature"}

    # -----------------------------------------------------
    # ES256 / ES384 / ES512
    # -----------------------------------------------------
    def _validate_es(self, alg, signing_input, signature, kid):
        key = self._get_jwk_key(kid)
        if not key:
            return {"valid": False, "error": "Matching EC key not found in JWKS"}

        public_key = self._load_ec_key(key)

        hash_map = {
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }

        half = len(signature) // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        der_sig = encode_dss_signature(r, s)

        try:
            public_key.verify(
                der_sig,
                signing_input,
                ec.ECDSA(hash_map[alg])
            )
            return {"valid": True, "message": "ECDSA signature valid"}
        except Exception:
            return {"valid": False, "error": "Invalid ECDSA signature"}

    # -----------------------------------------------------
    # JWK Helpers
    # -----------------------------------------------------
    def _get_jwk_key(self, kid):
        if not self.jwks:
            return None
        for key in self.jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    def _load_rsa_key(self, jwk):
        n = int.from_bytes(base64url_decode(jwk["n"]), "big")
        e = int.from_bytes(base64url_decode(jwk["e"]), "big")
        public_numbers = rsa.RSAPublicNumbers(e, n)
        return public_numbers.public_key()

    def _load_ec_key(self, jwk):
        x = int.from_bytes(base64url_decode(jwk["x"]), "big")
        y = int.from_bytes(base64url_decode(jwk["y"]), "big")

        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }

        curve = curve_map[jwk["crv"]]
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return public_numbers.public_key()
