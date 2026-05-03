from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from validator import decode_jwt, validate_claims
from jwks import verify_signature
from troubleshooting import basic_troubleshooting

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
templates = Jinja2Templates(directory=TEMPLATE_DIR)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# -----------------------------
# ROUTES
# -----------------------------
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request},
        status_code=200
    )

@app.post("/validate")
async def validate_token(request: Request, token: str = Form(...)):
    decoded = decode_jwt(token)
    claims_result = validate_claims(decoded)
    signature_result = await verify_signature(token)
    troubleshooting_result = basic_troubleshooting(decoded, claims_result, signature_result)

    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "request": request,
            "decoded": decoded,
            "claims_result": claims_result,
            "signature_result": signature_result,
            "troubleshooting_result": troubleshooting_result,
        },
        status_code=200
    )
