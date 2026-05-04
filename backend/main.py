from fastapi import FastAPI, Request, Form
from starlette.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os
import requests

from validator import decode_jwt, validate_claims, SignatureValidator
from troubleshooting import basic_troubleshooting
from agent import TokenAgent   # <-- NEW

app = FastAPI()

# -----------------------------
# PATHS
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # backend/

TEMPLATE_DIR = os.path.join(BASE_DIR, "..", "ui", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "..", "ui", "static")

TEMPLATE_DIR = os.path.abspath(TEMPLATE_DIR)
STATIC_DIR = os.path.abspath(STATIC_DIR)

# -----------------------------
# TEMPLATE ENGINE + STATIC
# -----------------------------
import jinja2
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), cache_size=0)
templates = Jinja2Templates(env=jinja_env)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# -----------------------------
# ROUTES
# -----------------------------
@app.get("/")
def home(request: Request):
    t = jinja_env.get_template("index.html")
    html = t.render(request=request)
    return HTMLResponse(html)


@app.post("/validate")
async def validate_token(
    request: Request,
    token: str = Form(...),
    jwks_url: str = Form(None),
    secret: str = Form(None),
    manual_public_key: str = Form(None)
):

    # =====================================================
    # NEW: AGENT-BASED VALIDATION (clean orchestrator)
    # =====================================================
    agent = TokenAgent(
        token=token,
        jwks_url=jwks_url,
        secret=secret,
        manual_key=manual_public_key
    )

    result = agent.run()

    # =====================================================
    # OLD MANUAL VALIDATION (PRESERVED FOR STUDYING)
    # =====================================================
    """
    # -----------------------------
    # Decode + Claim Validation
    # -----------------------------
    decoded = decode_jwt(token)
    claims_result = validate_claims(decoded)

    # -----------------------------
    # Fetch JWKS if URL provided
    # -----------------------------
    jwks_data = None
    if jwks_url:
        try:
            jwks_data = requests.get(jwks_url).json()
        except Exception as e:
            jwks_data = None

    # -----------------------------
    # Signature Validation
    # -----------------------------
    sig_validator = SignatureValidator(
        jwks=jwks_data,
        secret=secret,
        manual_public_key_pem=manual_public_key
    )

    signature_result = sig_validator.validate(decoded)

    # -----------------------------
    # Troubleshooting
    # -----------------------------
    troubleshooting_result = basic_troubleshooting(
        decoded,
        claims_result,
        signature_result
    )
    """

    # =====================================================
    # RENDER RESULTS (using Agent output)
    # =====================================================
    t = jinja_env.get_template("result.html")
    html = t.render(
        request=request,
        decoded=result["decoded"],
        claims_result=result["claims"],
        signature_result=result["signature"],
        troubleshooting_result=result["troubleshooting"],
        jwks_url=jwks_url,
        manual_public_key=manual_public_key,
        secret=secret
    )
    return HTMLResponse(html)