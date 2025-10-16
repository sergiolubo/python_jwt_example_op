# secure_auth.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS = {
    "alice@example.com": {"password": pwd_context.hash("password123"), "role": "user"},
    "admin@example.com": {"password": pwd_context.hash("adminpass"), "role": "admin"},
}

with open("private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
with open("public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

ISS = "mi-curso-ucc"
AUD = "ucc-client"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

BLACKLIST = set()

class LoginIn(BaseModel):
    email: str
    password: str
    totp: Optional[str] = None

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now, "iss": ISS, "aud": AUD})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm="RS256")
    return encoded_jwt

@app.post("/login")
def login(data: LoginIn):
    user = USERS.get(data.email)
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    payload = {"sub": data.email, "role": user["role"]}
    access_token = create_access_token(payload, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_access_token(payload, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

def verify_token(token: str):
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=AUD, issuer=ISS)
        jti = jwt.get_unverified_claims(token).get("jti")
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Token inválido")
    if token in BLACKLIST:
        raise HTTPException(status_code=401, detail="Token revocado")
    return payload

@app.get("/admin")
def admin_panel(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(401, "Missing token")
    token = authorization.split(" ")[1]
    payload = verify_token(token)
    if payload.get("role") != "admin":
        raise HTTPException(403, "Forbidden")
    return {"secret": "sólo admins pueden ver esto (versión segura)"}

@app.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(401, "Missing token")
    token = authorization.split(" ")[1]
    BLACKLIST.add(token)
    return {"msg": "logged out"}