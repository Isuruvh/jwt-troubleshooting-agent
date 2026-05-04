# **JWT Troubleshooting Agent**

A FastAPI‑powered web tool that decodes, validates, and troubleshoots JSON Web Tokens (JWTs).  
Built for developers who want instant clarity when debugging authentication issues.

---

## 🔰 Badges  
```
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)
```

---

## 📝 Description  
The **JWT Troubleshooting Agent** helps developers quickly understand why a JWT is failing.  
It provides:

- Full token decoding  
- Claim validation  
- Signature verification  
- A troubleshooting engine that explains issues in plain English  

Perfect for API developers, identity engineers, and anyone working with OAuth2/OIDC.

---

## 🎥 Demo (GIF Placeholder)

> Add a GIF here once you record one.  
> Example placeholder:

```
![Demo](https://dummyimage.com/800x400/000/fff&text=Demo+Coming+Soon)
```

---

## 🚀 Features  
- Decode JWT header, payload, and signature  
- Validate standard claims (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`)  
- Detect missing or invalid `kid`  
- Detect algorithm mismatches (HS256 vs RS256)  
- Validate issuer format (HTTPS required)  
- Provide human‑readable troubleshooting messages  
- Clean, simple UI using Jinja2 templates  

---

## 🧩 Project Structure  
```
jwt-troubleshooting-agent/
│
├── backend/
│   ├── main.py
│   ├── validators/
│   │   ├── claims.py
│   │   ├── signature.py
│   │   └── troubleshooting.py
│   ├── templates/
│   │   ├── index.html
│   │   └── result.html
│   └── static/
│       └── styles.css
│
└── README.md
```

---

## 🛠️ Tech Stack  
- **FastAPI** — backend  
- **Jinja2** — templating  
- **PyJWT / JOSE** — token decoding  
- **Uvicorn** — ASGI server  
- **HTML + CSS** — UI  

---

## ▶️ Getting Started

### 1. Create a virtual environment  
```bash
python -m venv .venv
```

### 2. Activate it  
```bash
.\.venv\Scripts\activate
```

### 3. Install dependencies  
```bash
pip install fastapi uvicorn jinja2 python-multipart pyjwt
```

### 4. Run the server  
```bash
python -m uvicorn main:app --reload
```

### 5. Open the UI  
```
http://127.0.0.1:8000
```

---

## 🧪 Example Output  
The tool displays:

- **Decoded Token**  
- **Claim Validation**  
- **Signature Verification**  
- **Troubleshooting Guidance**

This helps pinpoint issues like:

- Wrong signing algorithm  
- Missing `kid`  
- Expired token  
- Invalid issuer  
- Incorrect audience  

---

## 📌 Roadmap  
- JWKS (JSON Web Key Set) auto‑fetch  
- RS256 verification with public keys  
- Azure AD / Auth0 / Cognito presets  
- Token introspection endpoint  
- Dark mode UI  
- Exportable validation report  

---

## 🤝 Contribution Guide  
1. Fork the repository  
2. Create a feature branch  
3. Commit changes with clear messages  
4. Submit a pull request  
5. Ensure new features include tests (if applicable)

---

## 📄 License  
This project is licensed under the **MIT License**.

---

## 🌟 GitHub Short Description  
> A FastAPI‑powered tool that decodes, validates, and troubleshoots JWTs with clear explanations and a simple UI.
