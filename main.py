import jwt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-56j6u8f3.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI()

# Lets the grader call your API from anywhere
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def reject():
    return JSONResponse(status_code=401, content={"valid": False})

@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body["token"]
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],        # ONLY accept RS256
            audience=AUDIENCE,           # rule 3
            issuer=ISSUER,               # rule 2
            options={"require": ["exp", "iss", "aud"]},  # must be present
        )                                # signature (rule 1) and exp (rule 4) are checked automatically
    except Exception:
        return reject()

    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
    }