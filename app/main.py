import os
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"

ADMIN_USER = os.getenv("ADMIN_USER", "admin").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def now_utc():
    return datetime.now(timezone.utc)

def create_tables():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          email TEXT,
          matricula TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          approved_at TIMESTAMPTZ,
          expires_at TIMESTAMPTZ,
          session_limit INT NOT NULL DEFAULT 0,
          is_active BOOLEAN NOT NULL DEFAULT false,
          is_admin BOOLEAN NOT NULL DEFAULT false
        );
        """))

def seed_admin():
    with engine.begin() as conn:
        r = conn.execute(
            text("SELECT id FROM users WHERE username=:u"),
            {"u": ADMIN_USER},
        ).fetchone()

        if not r:
            ph = pwd.hash(ADMIN_PASSWORD)
            conn.execute(text("""
              INSERT INTO users (username, password_hash, expires_at, session_limit, is_active, is_admin, approved_at)
              VALUES (:u, :p, :e, :l, true, true, now())
            """), {
                "u": ADMIN_USER,
                "p": ph,
                "e": now_utc() + timedelta(days=3650),
                "l": 999,
            })

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não definido")
    create_tables()
    seed_admin()
    yield

app = FastAPI(title="PMESP API", lifespan=lifespan)

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    email: str | None = None
    matricula: str | None = None

class LoginIn(BaseModel):
    username: str
    password: str

class ApproveIn(BaseModel):
    days: int = Field(ge=1, le=3650)
    session_limit: int = Field(ge=1, le=999)

def make_token(username: str):
    payload = {
        "sub": username,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(hours=8)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_user(username: str):
    with engine.begin() as conn:
        return conn.execute(text("""
            SELECT id, username, password_hash, email, matricula, created_at, approved_at,
                   expires_at, session_limit, is_active, is_admin
            FROM users
            WHERE username=:u
        """), {"u": username}).mappings().fetchone()

def bearer_token(req: Request) -> str:
    h = req.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    return h.split(" ", 1)[1].strip()

def require_user(req: Request):
    token = bearer_token(req)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username = (payload.get("sub") or "").strip().lower()
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    u = get_user(username)
    if not u:
        raise HTTPException(status_code=401, detail="Token inválido")
    return u

def require_admin(u=Depends(require_user)):
    if not u["is_admin"]:
        raise HTTPException(status_code=403, detail="Apenas ADMIN")
    return u

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/public/register")
def public_register(data: RegisterIn):
    uname = data.username.strip().lower()

    if uname in {"admin", ADMIN_USER}:
        raise HTTPException(status_code=400, detail="Username reservado")

    ph = pwd.hash(data.password)

    with engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM users WHERE username=:u"),
            {"u": uname},
        ).fetchone()
        if exists:
            raise HTTPException(status_code=400, detail="Usuário já existe")

        # PENDENTE: validade 0 => expira agora, inativo, sem sessão
        conn.execute(text("""
            INSERT INTO users (username, password_hash, email, matricula, expires_at, session_limit, is_active, is_admin)
            VALUES (:u, :p, :email, :mat, :exp, 0, false, false)
        """), {
            "u": uname,
            "p": ph,
            "email": data.email,
            "mat": data.matricula,
            "exp": now_utc(),
        })

    return {"ok": True, "message": "Solicitação criada como PENDENTE (validade 0). Aguarde aprovação do ADMIN."}

@app.post("/auth/login")
def login(data: LoginIn):
    uname = data.username.strip().lower()
    u = get_user(uname)
    if not u or not pwd.verify(data.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")

    if (not u["is_active"]) or (u["expires_at"] is None) or (u["expires_at"] <= now_utc()):
        raise HTTPException(status_code=403, detail="Conta pendente, desativada ou expirada")

    return {"access_token": make_token(uname), "token_type": "bearer"}

@app.get("/me")
def me(u=Depends(require_user)):
    return {
        "username": u["username"],
        "email": u["email"],
        "matricula": u["matricula"],
        "expires_at": str(u["expires_at"]) if u["expires_at"] else None,
        "session_limit": u["session_limit"],
        "is_active": u["is_active"],
        "is_admin": u["is_admin"],
    }

@app.get("/admin/users/pending")
def list_pending(admin=Depends(require_admin)):
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT username, email, matricula, created_at
            FROM users
            WHERE is_active = false AND is_admin = false
            ORDER BY created_at ASC
        """)).mappings().all()
    return {"ok": True, "pending": list(rows)}

@app.post("/admin/users/{username}/approve")
def approve_user(username: str, body: ApproveIn, admin=Depends(require_admin)):
    uname = username.strip().lower()
    u = get_user(uname)
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if u["is_admin"]:
        raise HTTPException(status_code=400, detail="Não aprovar admin por aqui")

    exp = now_utc() + timedelta(days=body.days)

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET is_active=true,
                approved_at=now(),
                expires_at=:exp,
                session_limit=:lim
            WHERE username=:u
        """), {"u": uname, "exp": exp, "lim": body.session_limit})

    return {"ok": True, "message": f"{uname} aprovado", "expires_at": str(exp)}
