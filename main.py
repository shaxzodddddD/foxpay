"""
FoxPay Backend — main.py
Render-ready. Python 3.12 da ishlaydi.

Start command (Render):
  uvicorn main:app --host 0.0.0.0 --port $PORT
"""

import os
import re
import sys
import time
import json
import hmac
import hashlib
import secrets
import logging
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean, BigInteger,
    ForeignKey, Text, UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("foxpay")

# ============================================================
# CONFIG
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
PORT = int(os.getenv("PORT", "9988"))
HOST = os.getenv("HOST", "0.0.0.0")
SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
TOKEN_EXPIRE_HOURS = 24
FEE_RATE_BPS = int(os.getenv("FOXPAY_FEE_BPS", "150"))  # 1.5%
DEV_MODE = os.getenv("FOXPAY_DEV", "1") == "1"
INDEX_HTML = BASE_DIR / "index.html"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Email formati noto'g'ri")
    return email


# ============================================================
# DATABASE
# ============================================================
def _writable(path: str) -> bool:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        probe = p.parent / f".test_{secrets.token_hex(4)}"
        probe.write_text("x")
        probe.unlink()
        return True
    except Exception as e:
        logger.warning(f"[db] {path} not writable: {e}")
        return False


def _resolve_db() -> str:
    for c in [
        os.getenv("FOXPAY_DB"),
        str(BASE_DIR / "foxpay.db"),
        "/var/data/foxpay.db",
        "/tmp/foxpay.db",
        str(Path.cwd() / "foxpay.db"),
    ]:
        if c and _writable(c):
            return c
    return "/tmp/foxpay.db"


DB_PATH = _resolve_db()
logger.info(f"[db] using {DB_PATH}")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# MODELS
# ============================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    phone = Column(String(32), index=True)
    company = Column(String(200), default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    currency = Column(String(8), default="UZS")
    balance_tiyin = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("user_id", "currency", name="uq_wallet"),)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True)
    group_id = Column(String(40), index=True, nullable=False)
    account = Column(String(80), index=True, nullable=False)
    direction = Column(String(8), nullable=False)  # debit|credit
    amount_tiyin = Column(BigInteger, nullable=False)
    ref_type = Column(String(32), index=True)
    ref_id = Column(String(64), index=True)
    note = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, index=True)


class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    transfer_id = Column(String(32), unique=True, index=True)
    from_user_id = Column(Integer, ForeignKey("users.id"), index=True)
    to_user_id = Column(Integer, ForeignKey("users.id"), index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    status = Column(String(16), default="pending")
    note = Column(String(255), default="")
    idempotency_key = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id = Column(Integer, primary_key=True)
    intent_id = Column(String(32), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    status = Column(String(20), default="requires_payment")
    description = Column(String(255), default="")
    customer_name = Column(String(120))
    customer_email = Column(String(200))
    psp_ref = Column(String(64))
    fee_tiyin = Column(BigInteger, default=0)
    idempotency_key = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    prefix = Column(String(20), index=True, nullable=False)
    key_hash = Column(String(255), nullable=False)
    label = Column(String(64), default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Webhook(Base):
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(100), nullable=False)
    events = Column(String(255), default="*")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


Base.metadata.create_all(bind=engine)
logger.info("[db] tables created")


# ============================================================
# SECURITY
# ============================================================
def hash_password(raw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt, 100_000)
    return f"pbkdf2_sha256$100000${salt.hex()}${dk.hex()}"


def verify_password(raw: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", raw.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def create_access_token(user_id: int) -> str:
    now = datetime.utcnow()
    return jwt.encode(
        {"sub": str(user_id), "iat": now,
         "exp": now + timedelta(hours=TOKEN_EXPIRE_HOURS)},
        SECRET_KEY, algorithm=JWT_ALG,
    )


def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Token noto'g'ri yoki muddati o'tgan")


def generate_api_key():
    full = "fox_live_" + secrets.token_hex(24)
    return full, full[:20], hashlib.sha256(full.encode()).hexdigest()


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header kerak")
    token = authorization[7:].strip()

    if token.startswith("fox_live_"):
        k = db.query(ApiKey).filter(
            ApiKey.prefix == token[:20],
            ApiKey.key_hash == hashlib.sha256(token.encode()).hexdigest(),
            ApiKey.is_active == True,
        ).first()
        if not k:
            raise HTTPException(401, "API kalit noto'g'ri")
        user = db.get(User, k.user_id)
    else:
        user = db.get(User, decode_token(token))

    if not user or not user.is_active:
        raise HTTPException(401, "Foydalanuvchi topilmadi")
    return user


# ============================================================
# SCHEMAS
# ============================================================
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=6, max_length=128)
    phone: Optional[str] = None
    company: Optional[str] = ""


class LoginIn(BaseModel):
    email: str
    password: str


class ProfileIn(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None


class TransferIn(BaseModel):
    to_email: Optional[str] = None
    amount_tiyin: int = Field(gt=0)
    note: str = ""


class IntentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    description: str = ""
    customer_name: Optional[str] = None
    customer_email: Optional[str] = None


class KeyIn(BaseModel):
    label: str = "default"


class HookIn(BaseModel):
    url: str
    events: str = "*"


class FundIn(BaseModel):
    amount_tiyin: int = Field(gt=0)


# ============================================================
# LEDGER
# ============================================================
def post_entries(db: Session, entries, ref_type: str, ref_id: str, note: str = ""):
    group = "lg_" + secrets.token_hex(10)
    debit = sum(e["amount_tiyin"] for e in entries if e["direction"] == "debit")
    credit = sum(e["amount_tiyin"] for e in entries if e["direction"] == "credit")
    if debit != credit or debit <= 0:
        raise ValueError(f"Unbalanced ledger: debit={debit} credit={credit}")

    for e in entries:
        db.add(LedgerEntry(
            group_id=group, account=e["account"], direction=e["direction"],
            amount_tiyin=e["amount_tiyin"], ref_type=ref_type, ref_id=ref_id, note=note,
        ))
        if e["account"].startswith("user:"):
            _, uid, cur = e["account"].split(":")
            w = db.query(Wallet).filter(
                Wallet.user_id == int(uid), Wallet.currency == cur
            ).first()
            if not w:
                w = Wallet(user_id=int(uid), currency=cur, balance_tiyin=0)
                db.add(w)
                db.flush()
            delta = e["amount_tiyin"] if e["direction"] == "credit" else -e["amount_tiyin"]
            w.balance_tiyin += delta
    db.flush()
    return group


def get_balance(db: Session, user_id: int, currency: str = "UZS") -> int:
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.account == f"user:{user_id}:{currency}"
    ).all()
    return (
        sum(r.amount_tiyin for r in rows if r.direction == "credit")
        - sum(r.amount_tiyin for r in rows if r.direction == "debit")
    )


def _fee(amount: int) -> int:
    return (amount * FEE_RATE_BPS) // 10_000


# ============================================================
# APP
# ============================================================
app = FastAPI(title="FoxPay API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HEALTH / DEBUG
# ============================================================
@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "foxpay",
        "version": "3.0.0",
        "python": sys.version.split()[0],
        "db": DB_PATH,
        "dev": DEV_MODE,
    }


@app.get("/api/debug")
def debug():
    """Muammolarni aniqlash uchun."""
    info = {
        "python": sys.version,
        "db_path": DB_PATH,
        "db_ok": False,
        "users_count": 0,
    }
    try:
        db = SessionLocal()
        try:
            db.execute("SELECT 1")
            info["db_ok"] = True
            info["users_count"] = db.query(User).count()
        finally:
            db.close()
    except Exception as e:
        info["db_error"] = str(e)
    return info


# ============================================================
# AUTH — ASOSIY ENDPOINT
# ============================================================
@app.post("/api/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    logger.info(f"[register] email={body.email}")
    try:
        email = validate_email(body.email)

        # Email band emasmi
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(400, "Bu email allaqachon ro'yxatdan o'tgan")

        # User yaratish
        user = User(
            name=(body.name or "").strip(),
            email=email,
            password_hash=hash_password(body.password),
            phone=(body.phone or "").strip() or None,
            company=(body.company or "").strip(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"[register] user created id={user.id}")

        # Wallet
        wallet = Wallet(user_id=user.id, currency="UZS", balance_tiyin=0)
        db.add(wallet)
        db.commit()
        logger.info(f"[register] wallet created for user_id={user.id}")

        return {
            "token": create_access_token(user.id),
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "phone": user.phone,
                "company": user.company,
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"[register] UNEXPECTED:\n{traceback.format_exc()}")
        raise HTTPException(500, f"Server xatosi: {type(e).__name__}: {str(e)[:200]}")


@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    email = validate_email(body.email)
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Email yoki parol noto'g'ri")
    return {
        "token": create_access_token(user.id),
        "user": {
            "id": user.id, "name": user.name, "email": user.email,
            "phone": user.phone, "company": user.company,
        },
    }


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id, "name": user.name, "email": user.email,
        "phone": user.phone, "company": user.company,
    }


# ============================================================
# WALLET
# ============================================================
@app.get("/api/wallet")
def wallet(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    bal = get_balance(db, user.id)
    return {
        "currency": "UZS",
        "balance_tiyin": bal,
        "balance_uzs": bal / 100,
    }


@app.get("/api/wallet/ledger")
def ledger(
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.account == f"user:{user.id}:UZS"
    ).order_by(LedgerEntry.created_at.desc()).limit(limit).all()
    return [
        {
            "group_id": r.group_id,
            "direction": r.direction,
            "amount_tiyin": r.amount_tiyin,
            "ref_type": r.ref_type,
            "ref_id": r.ref_id,
            "note": r.note,
            "created_at": iso(r.created_at),
        }
        for r in rows
    ]


# ============================================================
# P2P
# ============================================================
@app.post("/api/p2p/transfers", status_code=201)
def send_money(
    body: TransferIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    to_email = validate_email(body.to_email) if body.to_email else None
    if not to_email:
        raise HTTPException(400, "to_email kerak")

    to_user = db.query(User).filter(User.email == to_email).first()
    if not to_user:
        raise HTTPException(404, "Qabul qiluvchi topilmadi")
    if to_user.id == user.id:
        raise HTTPException(400, "O'zingizga pul o'tkaza olmaysiz")

    fee = _fee(body.amount_tiyin)
    total = body.amount_tiyin + fee
    bal = get_balance(db, user.id)
    if bal < total:
        raise HTTPException(
            400,
            f"Balans yetarli emas: bor {bal/100:,.0f} so'm, kerak {total/100:,.0f} so'm",
        )

    t = Transfer(
        transfer_id="tr_" + secrets.token_hex(10),
        from_user_id=user.id,
        to_user_id=to_user.id,
        amount_tiyin=body.amount_tiyin,
        fee_tiyin=fee,
        status="succeeded",
        note=body.note[:250],
        completed_at=utcnow(),
    )
    db.add(t)
    db.flush()

    post_entries(db, [
        {"account": f"user:{user.id}:UZS", "direction": "debit", "amount_tiyin": total},
        {"account": f"user:{to_user.id}:UZS", "direction": "credit", "amount_tiyin": body.amount_tiyin},
        {"account": "platform:fees:UZS", "direction": "credit", "amount_tiyin": fee},
    ], ref_type="p2p", ref_id=t.transfer_id, note=body.note)

    db.commit()
    db.refresh(t)
    return {
        "transfer_id": t.transfer_id,
        "from_user_id": t.from_user_id,
        "to_user_id": t.to_user_id,
        "amount_tiyin": t.amount_tiyin,
        "fee_tiyin": t.fee_tiyin,
        "status": t.status,
        "created_at": iso(t.created_at),
    }


@app.get("/api/p2p/transfers")
def list_transfers(
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(Transfer).filter(
        (Transfer.from_user_id == user.id) | (Transfer.to_user_id == user.id)
    ).order_by(Transfer.created_at.desc()).limit(limit).all()
    return [
        {
            "transfer_id": t.transfer_id,
            "from_user_id": t.from_user_id,
            "to_user_id": t.to_user_id,
            "amount_tiyin": t.amount_tiyin,
            "fee_tiyin": t.fee_tiyin,
            "status": t.status,
            "created_at": iso(t.created_at),
        }
        for t in rows
    ]


# ============================================================
# PAYMENT INTENTS
# ============================================================
@app.post("/api/pay/intents", status_code=201)
def new_intent(
    body: IntentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    i = PaymentIntent(
        intent_id="pi_" + secrets.token_hex(10),
        user_id=user.id,
        amount_tiyin=body.amount_tiyin,
        status="requires_payment",
        description=body.description[:250],
        customer_name=body.customer_name,
        customer_email=body.customer_email,
        psp_ref="mock_" + secrets.token_hex(8),
        fee_tiyin=_fee(body.amount_tiyin),
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return {
        "intent_id": i.intent_id,
        "amount_tiyin": i.amount_tiyin,
        "status": i.status,
        "description": i.description,
        "fee_tiyin": i.fee_tiyin,
        "created_at": iso(i.created_at),
    }


@app.post("/api/pay/intents/{intent_id}/confirm")
def confirm_intent(
    intent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    i = db.query(PaymentIntent).filter(
        PaymentIntent.intent_id == intent_id,
        PaymentIntent.user_id == user.id,
    ).first()
    if not i:
        raise HTTPException(404, "Intent topilmadi")
    if i.status == "succeeded":
        return {"intent_id": i.intent_id, "status": "succeeded"}

    net = i.amount_tiyin - i.fee_tiyin
    post_entries(db, [
        {"account": "external:psp", "direction": "debit", "amount_tiyin": i.amount_tiyin},
        {"account": f"user:{user.id}:UZS", "direction": "credit", "amount_tiyin": net},
        {"account": "platform:fees:UZS", "direction": "credit", "amount_tiyin": i.fee_tiyin},
    ], ref_type="intent", ref_id=i.intent_id)

    i.status = "succeeded"
    i.completed_at = utcnow()
    db.commit()
    return {"intent_id": i.intent_id, "status": "succeeded"}


@app.get("/api/pay/intents")
def list_intents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(PaymentIntent).filter(
        PaymentIntent.user_id == user.id
    ).order_by(PaymentIntent.created_at.desc()).limit(50).all()
    return [
        {
            "intent_id": i.intent_id,
            "amount_tiyin": i.amount_tiyin,
            "status": i.status,
            "description": i.description,
            "created_at": iso(i.created_at),
        }
        for i in rows
    ]


# ============================================================
# API KEYS
# ============================================================
@app.get("/api/keys")
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(
        ApiKey.user_id == user.id
    ).order_by(ApiKey.created_at.desc()).all()
    return [
        {
            "id": k.id, "prefix": k.prefix, "label": k.label,
            "is_active": k.is_active, "created_at": iso(k.created_at),
        }
        for k in rows
    ]


@app.post("/api/keys", status_code=201)
def create_key(
    body: KeyIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    full, prefix, key_hash = generate_api_key()
    k = ApiKey(
        user_id=user.id, prefix=prefix, key_hash=key_hash, label=body.label,
    )
    db.add(k)
    db.commit()
    db.refresh(k)
    return {
        "id": k.id, "prefix": k.prefix, "label": k.label,
        "is_active": k.is_active, "created_at": iso(k.created_at),
        "full_key": full,
    }


@app.delete("/api/keys/{key_id}", status_code=204)
def revoke_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    k = db.query(ApiKey).filter(
        ApiKey.id == key_id, ApiKey.user_id == user.id
    ).first()
    if not k:
        raise HTTPException(404, "Topilmadi")
    k.is_active = False
    db.commit()


# ============================================================
# WEBHOOKS
# ============================================================
@app.get("/api/hooks")
def list_hooks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Webhook).filter(Webhook.user_id == user.id).all()
    return [
        {"id": w.id, "url": w.url, "events": w.events, "created_at": iso(w.created_at)}
        for w in rows
    ]


@app.post("/api/hooks", status_code=201)
def create_hook(
    body: HookIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    w = Webhook(
        user_id=user.id, url=body.url,
        secret="whsec_" + secrets.token_hex(20), events=body.events,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return {"id": w.id, "url": w.url, "events": w.events, "created_at": iso(w.created_at)}


@app.delete("/api/hooks/{hook_id}", status_code=204)
def delete_hook(
    hook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    w = db.query(Webhook).filter(
        Webhook.id == hook_id, Webhook.user_id == user.id
    ).first()
    if not w:
        raise HTTPException(404, "Topilmadi")
    db.delete(w)
    db.commit()


# ============================================================
# SETTINGS
# ============================================================
@app.get("/api/settings")
def get_settings(user: User = Depends(get_current_user)):
    return {
        "id": user.id, "name": user.name, "email": user.email,
        "phone": user.phone, "company": user.company,
    }


@app.put("/api/settings")
def update_settings(
    body: ProfileIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.email and body.email != user.email:
        new_email = validate_email(body.email)
        clash = db.query(User).filter(
            User.email == new_email, User.id != user.id
        ).first()
        if clash:
            raise HTTPException(400, "Bu email band")
        user.email = new_email
    if body.name:
        user.name = body.name.strip()
    if body.phone is not None:
        user.phone = body.phone.strip() or None
    if body.company is not None:
        user.company = body.company.strip()
    db.commit()
    db.refresh(user)
    return {"id": user.id, "name": user.name, "email": user.email, "phone": user.phone, "company": user.company}


# ============================================================
# DEV
# ============================================================
@app.post("/api/dev/fund")
def fund(
    body: FundIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not DEV_MODE:
        raise HTTPException(403, "Dev mode o'chirilgan")
    post_entries(db, [
        {"account": "external:psp", "direction": "debit", "amount_tiyin": body.amount_tiyin},
        {"account": f"user:{user.id}:UZS", "direction": "credit", "amount_tiyin": body.amount_tiyin},
    ], ref_type="deposit", ref_id="dep_" + secrets.token_hex(8))
    db.commit()
    return {"ok": True, "amount_tiyin": body.amount_tiyin}


# ============================================================
# STATIC FILES
# ============================================================
def _serve(filename: str, media_type: str):
    p = BASE_DIR / filename
    if p.exists():
        return FileResponse(p, media_type=media_type)
    raise HTTPException(404, f"{filename} topilmadi")


@app.get("/robots.txt")
def robots():
    return _serve("robots.txt", "text/plain")


@app.get("/sitemap.xml")
def sitemap():
    return _serve("sitemap.xml", "application/xml")


@app.get("/manifest.webmanifest")
def manifest():
    return _serve("manifest.webmanifest", "application/manifest+json")


@app.get("/")
def index():
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML, media_type="text/html")
    return JSONResponse({"message": "FoxPay API", "health": "/api/health"})


@app.get("/{path:path}")
def catch_all(path: str):
    if path.startswith(("api/", "docs", "openapi")):
        raise HTTPException(404, "Endpoint topilmadi")
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML, media_type="text/html")
    raise HTTPException(404)


# ============================================================
# ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import uvicorn
    logger.info(f"FoxPay starting on {HOST}:{PORT}")
    logger.info(f"DB: {DB_PATH}")
    logger.info(f"Dev: {DEV_MODE}")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False)
