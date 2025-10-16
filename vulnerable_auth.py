# vulnerable_auth.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import jwt
from typing import Optional

app = FastAPI()

USERS = {
    "alice@example.com": {"password": "password123", "role": "user"},
    "admin@example.com": {"password": "adminpass", "role": "admin"},
}

JWT_SECRET = "supersecret"
JWT_ALGORITHM = "HS256"

class LoginIn(BaseModel):
    email: str
    password: str

@app.post("/login")
def login(data: LoginIn):
    user = USERS.get(data.email)
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    token = jwt.encode({"sub": data.email, "role": user["role"]}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

def insecure_decode_token(token: str):
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload

@app.get("/admin")
def admin_panel(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(401, "Missing token")
    
    token = authorization.split(" ")[1]
    payload = insecure_decode_token(token)
    
    if payload.get("role") != "admin":
        raise HTTPException(403, "Forbidden")
    return {"secret": "sólo admins pueden ver esto"}