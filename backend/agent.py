# agent.py

import requests
from validator import decode_jwt, validate_claims, SignatureValidator
from troubleshooting import basic_troubleshooting


class TokenAgent:

    def __init__(self, token, jwks_url=None, secret=None, manual_key=None):
        self.token = token
        self.jwks_url = jwks_url
        self.secret = secret
        self.manual_key = manual_key

    # -----------------------------
    # Fetch JWKS (optional)
    # -----------------------------
    def _fetch_jwks(self):
        if not self.jwks_url:
            return None

        try:
            return requests.get(self.jwks_url).json()
        except Exception:
            return None

    # -----------------------------
    # Main Agent Execution
    # -----------------------------
    def run(self):
        # 1. Decode
        decoded = decode_jwt(self.token)

        # 2. Claims
        claims = validate_claims(decoded)

        # 3. Signature
        sig_validator = SignatureValidator(
            jwks=self._fetch_jwks(),
            secret=self.secret,
            manual_public_key_pem=self.manual_key
        )
        signature = sig_validator.validate(decoded)

        # 4. Troubleshooting
        troubleshooting = basic_troubleshooting(decoded, claims, signature)

        # 5. Return unified result
        return {
            "decoded": decoded,
            "claims": claims,
            "signature": signature,
            "troubleshooting": troubleshooting
        }
