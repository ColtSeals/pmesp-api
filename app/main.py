import os
import uuid
import hashlib
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

HWID_PEPPER = os.getenv("HWID_PEPPER", "change-me")  # <-- add no .env
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "8"))

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def now_utc():
    return datetime.now(timezone.utc)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hwid_hash(hwid: str) -> str:
    # nunca guarda HWID puro, só hash com pepper
    return sha256_hex(hwid.strip() + HWID_PEPPER)

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

        # migração leve (sem Alembic) — adiciona colunas se não existirem
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS hwid_hash TEXT;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS hwid_bound_at TIMESTAMPTZ;"))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS sessions (
          id UUID PRIMARY KEY,
          username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
          hwid_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
          expires_at TIMESTAMPTZ NOT NULL,
          revoked_at TIMESTAMPTZ
        );
        """))

        conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_sessions_user_active
        ON sessions(username)
        WHERE revoked_at IS NULL;
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

# -------------------- Schemas --------------------

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    email: str | None = None
    matricula: str | None = None

class LoginIn(BaseModel):
    username: str
    password: str
    hwid: str = Field(min_length=8, max_length=256)

class ApproveIn(BaseModel):
    days: int = Field(ge=1, le=3650)
    session_limit: int = Field(ge=1, le=999)

class SetHWIDIn(BaseModel):
    hwid: str = Field(min_length=8, max_length=256)

# -------------------- Auth helpers --------------------

def make_token(username: str, session_id: str):
    payload = {
        "sub": username,
        "sid": session_id,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(hours=TOKEN_TTL_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def bearer_token(req: Request) -> str:
    h = req.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    return h.split(" ", 1)[1].strip()

def require_hwid_header(req: Request) -> str:
    # cliente deve mandar sempre o mesmo HWID no header
    hwid = (req.headers.get("X-HWID") or "").strip()
    if not hwid:
        raise HTTPException(status_code=401, detail="HWID ausente (header X-HWID)")
    return hwid

def get_user(username: str):
    with engine.begin() as conn:
        return conn.execute(text("""
            SELECT id, username, password_hash, email, matricula, created_at, approved_at,
                   expires_at, session_limit, is_active, is_admin, hwid_hash, hwid_bound_at
            FROM users
            WHERE username=:u
        """), {"u": username}).mappings().fetchone()

def revoke_all_sessions(username: str):
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE sessions
            SET revoked_at = now()
            WHERE username = :u AND revoked_at IS NULL
        """), {"u": username})

def require_user(req: Request):
    token = bearer_token(req)
    hwid = require_hwid_header(req)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username = (payload.get("sub") or "").strip().lower()
        sid = (payload.get("sid") or "").strip()
        if not username or not sid:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    with engine.begin() as conn:
        sess = conn.execute(text("""
            SELECT id, username, hwid_hash, expires_at, revoked_at
            FROM sessions
            WHERE id = :sid
        """), {"sid": sid}).mappings().fetchone()

        if not sess:
            raise HTTPException(status_code=401, detail="Sessão inválida")
        if sess["revoked_at"] is not None:
            raise HTTPException(status_code=401, detail="Sessão revogada pelo ADMIN")
        if sess["expires_at"] <= now_utc():
            raise HTTPException(status_code=401, detail="Sessão expirada")

        if sess["hwid_hash"] != hwid_hash(hwid):
            raise HTTPException(status_code=401, detail="HWID não confere")

        # atualiza last_seen
        conn.execute(text("""
            UPDATE sessions SET last_seen = now()
            WHERE id = :sid
        """), {"sid": sid})

    u = get_user(username)
    if not u:
        raise HTTPException(status_code=401, detail="Token inválido")

    # regra de conta
    if (not u["is_active"]) or (u["expires_at"] is None) or (u["expires_at"] <= now_utc()):
        raise HTTPException(status_code=403, detail="Conta pendente, desativada ou expirada")

    return u

def require_admin(u=Depends(require_user)):
    if not u["is_admin"]:
        raise HTTPException(status_code=403, detail="Apenas ADMIN")
    return u

# -------------------- Public --------------------

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

# -------------------- Auth --------------------

@app.post("/auth/login")
def login(data: LoginIn):
    uname = data.username.strip().lower()
    u = get_user(uname)
    if not u or not pwd.verify(data.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")

    if (not u["is_active"]) or (u["expires_at"] is None) or (u["expires_at"] <= now_utc()):
        raise HTTPException(status_code=403, detail="Conta pendente, desativada ou expirada")

    # HWID bind/check
    incoming_hwid_hash = hwid_hash(data.hwid)

    with engine.begin() as conn:
        u2 = conn.execute(text("""
            SELECT username, hwid_hash, session_limit
            FROM users
            WHERE username=:u
        """), {"u": uname}).mappings().fetchone()

        if not u2:
            raise HTTPException(status_code=401, detail="Usuário inválido")

        if u2["hwid_hash"] is None:
            conn.execute(text("""
                UPDATE users
                SET hwid_hash=:h, hwid_bound_at=now()
                WHERE username=:u
            """), {"u": uname, "h": incoming_hwid_hash})
        else:
            if u2["hwid_hash"] != incoming_hwid_hash:
                raise HTTPException(status_code=403, detail="HWID não autorizado (peça reset ao ADMIN)")

        # enforce session_limit (somente para não-admin)
        if not u["is_admin"]:
            limit = int(u2["session_limit"] or 0)
            if limit <= 0:
                raise HTTPException(status_code=403, detail="Conta sem limite de sessão definido (pendente de ajuste do ADMIN)")

            active = conn.execute(text("""
                SELECT count(*)::int AS c
                FROM sessions
                WHERE username=:u AND revoked_at IS NULL AND expires_at > now()
            """), {"u": uname}).mappings().fetchone()["c"]

            if active >= limit:
                raise HTTPException(status_code=403, detail="Limite de sessões atingido")

        # cria session
        sid = str(uuid.uuid4())
        sess_exp = now_utc() + timedelta(hours=TOKEN_TTL_HOURS)

        conn.execute(text("""
            INSERT INTO sessions (id, username, hwid_hash, expires_at)
            VALUES (:id, :u, :h, :e)
        """), {"id": sid, "u": uname, "h": incoming_hwid_hash, "e": sess_exp})

    return {"access_token": make_token(uname, sid), "token_type": "bearer"}

@app.post("/auth/logout")
def logout(req: Request):
    token = bearer_token(req)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sid = (payload.get("sid") or "").strip()
        if not sid:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE sessions SET revoked_at = now()
            WHERE id = :sid AND revoked_at IS NULL
        """), {"sid": sid})

    return {"ok": True}

@app.post("/me/ping")
def ping(u=Depends(require_user)):
    return {"ok": True}

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
        "hwid_bound_at": str(u["hwid_bound_at"]) if u["hwid_bound_at"] else None,
    }

# -------------------- Admin --------------------

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

    # opcional: ao aprovar você pode "kickar" (se tiver sessões antigas)
    revoke_all_sessions(uname)

    return {"ok": True, "message": f"{uname} aprovado", "expires_at": str(exp)}

@app.post("/admin/users/{username}/kick")
def kick_user(username: str, admin=Depends(require_admin)):
    uname = username.strip().lower()
    u = get_user(uname)
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if u["is_admin"]:
        raise HTTPException(status_code=400, detail="Não derrubar admin por aqui")
    revoke_all_sessions(uname)
    return {"ok": True, "message": f"{uname} derrubado (sessões revogadas)"}

@app.post("/admin/users/{username}/disable")
def disable_user(username: str, admin=Depends(require_admin)):
    uname = username.strip().lower()
    u = get_user(uname)
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if u["is_admin"]:
        raise HTTPException(status_code=400, detail="Não desativar admin por aqui")

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET is_active=false,
                expires_at=now()
            WHERE username=:u
        """), {"u": uname})

    revoke_all_sessions(uname)
    return {"ok": True, "message": f"{uname} desativado e derrubado"}

@app.post("/admin/users/{username}/reset-hwid")
def reset_hwid(username: str, admin=Depends(require_admin)):
    uname = username.strip().lower()
    u = get_user(uname)
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if u["is_admin"]:
        raise HTTPException(status_code=400, detail="Não resetar HWID do admin por aqui")

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET hwid_hash=NULL, hwid_bound_at=NULL
            WHERE username=:u
        """), {"u": uname})

    revoke_all_sessions(uname)
    return {"ok": True, "message": f"HWID resetado para {uname} (próximo login faz bind novo)"}

@app.post("/admin/users/{username}/set-hwid")
def set_hwid(username: str, body: SetHWIDIn, admin=Depends(require_admin)):
    uname = username.strip().lower()
    u = get_user(uname)
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if u["is_admin"]:
        raise HTTPException(status_code=400, detail="Não setar HWID do admin por aqui")

    h = hwid_hash(body.hwid)

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET hwid_hash=:h, hwid_bound_at=now()
            WHERE username=:u
        """), {"u": uname, "h": h})

    revoke_all_sessions(uname)
    return {"ok": True, "message": f"HWID atualizado e sessões derrubadas para {uname}"}

@app.get("/admin/sessions/online")
def sessions_online(admin=Depends(require_admin)):
    # online = last_seen nos últimos 60s e não revogada
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT username, created_at, last_seen, expires_at
            FROM sessions
            WHERE revoked_at IS NULL
              AND expires_at > now()
              AND last_seen > now() - interval '60 seconds'
            ORDER BY last_seen DESC
        """)).mappings().all()
    return {"ok": True, "online": list(rows)}
