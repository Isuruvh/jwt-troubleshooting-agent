Token Validation & Troubleshooting Agent (Hybrid Python + Web UI)
A professional-grade tool for decoding, validating, and troubleshooting JWTs used in:

Microsoft Entra ID

Entra B2C

Auth0

Okta

AWS Cognito

Keycloak

PingFederate

This agent helps identify common identity issues such as:

Invalid signatures

Wrong audience

Wrong issuer

Missing roles/scopes

Key rotation problems

ID token used as access token

Wrong tenant

Expired or not‑yet‑valid tokens

Tech Stack
Python (FastAPI backend)

Streamlit or Jinja2 Web UI

PyJWT

httpx

JWKS caching

Modular IAM troubleshooting engine

Features (in progress)
[ ] JWT decoding

[ ] Claim validation

[ ] Signature verification

[ ] JWKS fetching + caching

[ ] Token intelligence (ID vs Access)

[ ] Troubleshooting engine

[ ] Web UI# jwt-troubleshooting-agent
