"""
FoxPay — Render-ready backend (single file)

Render Settings:
  Build Command:  pip install -r requirements.txt
  Start Command:  uvicorn main:app --host 0.0.0.0 --port $PORT
  (yoki: python main.py)

Ixtiyoriy env vars:
  FOXPAY_SECRET   — JWT secret (prod da majburiy)
  FOXPAY_DB       — SQLite yo'li (default: /tmp/foxpay.db yoki yonidagi papka)
  FOXPAY_DEV      — "0" bo'lsa /api/dev/* o'chiriladi
  PYTHON_VERSION  — "3.12.11" (runtime.txt bilan bir xil)
"""

import os
import secrets
import hashlib
import hmac as hmac_lib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import (
    FastAPI, Depends, HTTPException, Header, BackgroundTasks, Query, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean, BigInteger,
    ForeignKey, Text, UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base


# ============================================================
# CONFIG (Render-aware)
# ============================================================
BASE_DIR = Path(__file__).resolve().parent

# Render $PORT ni beradi; lokal default 9988
PORT = int(os.getenv("PORT", "9988"))
HOST = os.getenv("HOST", "0.0.0.0")

SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
TOKEN_EXPIRE_HOURS = 24
FEE_RATE_BPS = int(os.getenv("FOXPAY_FEE_BPS", "150"))  # 1.5%
DEV_MODE = os.getenv("FOXPAY_DEV", "1") == "1"
PSP_PROVIDER = os.getenv("FOXPAY_PSP", "mock")
INDEX_HTML = BASE_DIR / "index.html"


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


# ============================================================
# DATABASE — writable joyni topish
# ============================================================
def _test_path(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        test = path.parent / ".write_test"
        test.write_text("x")
        test.unlink()
        return True
    except Exception:
        return False


def _resolve_db_path() -> str:
    """Priority: env var > yonidagi papka > /tmp > cwd"""
    candidates = []
    if os.getenv("FOXPAY_DB"):
        candidates.append(os.getenv("FOXPAY_DB"))
    candidates.append(str(BASE_DIR / "foxpay.db"))
    candidates.append("/tmp/foxpay.db")
    candidates.append(str(Path.cwd() / "foxpay.db"))

    for c in candidates:
        if _test_path(Path(c)):
            return c
    return "/tmp/foxpay.db"  # oxirgi fallback


DB_PATH = _resolve_db_path()
print(f"[db] ishlatiladi: {DB_PATH}")

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


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    prefix = Column(String(20), index=True, nullable=False)
    key_hash = Column(String(255), nullable=False)
    label = Column(String(64), default="default")
    scopes = Column(String(200), default="read,write,p2p,collect")
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime)
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
    currency = Column(String(8), default="UZS")
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
    currency = Column(String(8), default="UZS")
    status = Column(String(20), default="requires_payment")
    description = Column(String(255), default="")
    customer_name = Column(String(120))
    customer_email = Column(String(200))
    psp_provider = Column(String(32), default="mock")
    psp_ref = Column(String(64))
    fee_tiyin = Column(BigInteger, default=0)
    idempotency_key = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(100), nullable=False)
    events = Column(String(255), default="*")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


Base.metadata.create_all(bind=engine)


# ============================================================
# SECURITY (faqat builtin + PyJWT)
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
        return hmac_lib.compare_digest(dk.hex(), hash_hex)
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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")


def generate_api_key():
    full = "fox_live_" + secrets.token_hex(24)
    return full, full[:20], hashlib.sha256(full.encode()).hexdigest()


def hash_api_key(full: str) -> str:
    return hashlib.sha256(full.encode()).hexdigest()


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    token = authorization[7:].strip()

    if token.startswith("fox_live_"):
        k = db.query(ApiKey).filter(
            ApiKey.prefix == token[:20],
            ApiKey.key_hash == hash_api_key(token),
            ApiKey.is_active == True,
        ).first()
        if not k:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
        k.last_used_at = utcnow()
        db.commit()
        user = db.get(User, k.user_id)
    else:
        user = db.get(User, decode_token(token))

    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


# ============================================================
# SCHEMAS
# ============================================================
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    phone: Optional[str] = None
    company: Optional[str] = ""


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ProfileIn(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None


class ApiKeyCreateIn(BaseModel):
    label: str = "default"
    scopes: str = "read,write,p2p,collect"


class TransferIn(BaseModel):
    to_email: Optional[EmailStr] = None
    to_phone: Optional[str] = None
    amount_tiyin: int = Field(gt=0)
    note: str = ""
    idempotency_key: Optional[str] = None


class IntentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    description: str = ""
    customer_name: Optional[str] = None
    customer_email: Optional[EmailStr] = None
    idempotency_key: Optional[str] = None


class ConfirmIn(BaseModel):
    outcome: str = "succeed"


class WebhookIn(BaseModel):
    url: str
    events: str = "*"


class DepositIn(BaseModel):
    amount_tiyin: int = Field(gt=0)


# ============================================================
# SERIALIZERS
# ============================================================
def user_dict(u: User) -> dict:
    return {
        "id": u.id, "name": u.name, "email": u.email,
        "phone": u.phone, "company": u.company or "",
        "created_at": iso(u.created_at),
    }


def transfer_dict(t: Transfer) -> dict:
    return {
        "transfer_id": t.transfer_id,
        "from_user_id": t.from_user_id,
        "to_user_id": t.to_user_id,
        "amount_tiyin": t.amount_tiyin,
        "amount_uzs": t.amount_tiyin / 100,
        "fee_tiyin": t.fee_tiyin,
        "status": t.status,
        "note": t.note,
        "created_at": iso(t.created_at),
        "completed_at": iso(t.completed_at),
    }


def intent_dict(i: PaymentIntent) -> dict:
    return {
        "intent_id": i.intent_id,
        "user_id": i.user_id,
        "amount_tiyin": i.amount_tiyin,
        "amount_uzs": i.amount_tiyin / 100,
        "currency": i.currency,
        "status": i.status,
        "description": i.description,
        "fee_tiyin": i.fee_tiyin,
        "psp_provider": i.psp_provider,
        "psp_ref": i.psp_ref,
        "customer_name": i.customer_name,
        "customer_email": i.customer_email,
        "created_at": iso(i.created_at),
        "completed_at": iso(i.completed_at),
    }


def key_dict(k: ApiKey) -> dict:
    return {
        "id": k.id, "prefix": k.prefix, "label": k.label,
        "scopes": k.scopes, "is_active": k.is_active,
        "last_used_at": iso(k.last_used_at),
        "created_at": iso(k.created_at),
    }


def hook_dict(w: WebhookEndpoint) -> dict:
    return {
        "id": w.id, "url": w.url, "events": w.events,
        "is_active": w.is_active, "created_at": iso(w.created_at),
    }


# ============================================================
# LEDGER
# ============================================================
def post_entries(db: Session, entries: list, ref_type: str, ref_id: str, note: str = "") -> str:
    group = "lg_" + secrets.token_hex(10)
    debit = sum(e["amount_tiyin"] for e in entries if e["direction"] == "debit")
    credit = sum(e["amount_tiyin"] for e in entries if e["direction"] == "credit")
    if debit != credit:
        raise ValueError(f"Unbalanced ledger: debit={debit} credit={credit}")
    if debit <= 0:
        raise ValueError("Ledger amount must be positive")

    for e in entries:
        db.add(LedgerEntry(
            group_id=group, account=e["account"],
            direction=e["direction"], amount_tiyin=e["amount_tiyin"],
            ref_type=ref_type, ref_id=ref_id, note=note,
        ))

    for e in entries:
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


def ensure_wallet(db: Session, user_id: int, currency: str = "UZS") -> Wallet:
    w = db.query(Wallet).filter(
        Wallet.user_id == user_id, Wallet.currency == currency
    ).first()
    if not w:
        w = Wallet(user_id=user_id, currency=currency, balance_tiyin=0)
        db.add(w)
        db.commit()
        db.refresh(w)
    return w


def _fee(amount_tiyin: int) -> int:
    return (amount_tiyin * FEE_RATE_BPS) // 10_000


# ============================================================
# PAYMENTS
# ============================================================
def create_transfer(
    db: Session, from_user: User,
    to_email: Optional[str], to_phone: Optional[str],
    amount_tiyin: int, note: str, idempotency_key: Optional[str],
) -> Transfer:
    if amount_tiyin <= 0:
        raise HTTPException(400, "amount_tiyin > 0 bo'lishi kerak")
    if not to_email and not to_phone:
        raise HTTPException(400, "to_email yoki to_phone kerak")

    if idempotency_key:
        existing = db.query(Transfer).filter(
            Transfer.idempotency_key == idempotency_key
        ).first()
        if existing:
            return existing

    to_user = None
    if to_email:
        to_user = db.query(User).filter(User.email == to_email.lower()).first()
    else:
        to_user = db.query(User).filter(User.phone == to_phone).first()

    if not to_user:
        raise HTTPException(404, "Qabul qiluvchi topilmadi")
    if to_user.id == from_user.id:
        raise HTTPException(400, "O'zingizga pul o'tkaza olmaysiz")

    fee = _fee(amount_tiyin)
    total = amount_tiyin + fee
    bal = get_balance(db, from_user.id)
    if bal < total:
        raise HTTPException(
            400,
            f"Balans yetarli emas: bor {bal/100:,.2f} so'm, kerak {total/100:,.2f} so'm",
        )

    t = Transfer(
        transfer_id="tr_" + secrets.token_hex(10),
        from_user_id=from_user.id, to_user_id=to_user.id,
        amount_tiyin=amount_tiyin, fee_tiyin=fee,
        status="pending", note=note[:250],
        idempotency_key=idempotency_key,
    )
    db.add(t)
    db.flush()

    post_entries(db, [
        {"account": f"user:{from_user.id}:UZS", "direction": "debit", "amount_tiyin": total},
        {"account": f"user:{to_user.id}:UZS",   "direction": "credit", "amount_tiyin": amount_tiyin},
        {"account": "platform:fees:UZS",        "direction": "credit", "amount_tiyin": fee},
    ], ref_type="p2p_transfer", ref_id=t.transfer_id, note=note)

    t.status = "succeeded"
    t.completed_at = utcnow()
    db.commit()
    db.refresh(t)
    return t


def create_intent(
    db: Session, user: User,
    amount_tiyin: int, description: str,
    customer_name: Optional[str], customer_email: Optional[str],
    idempotency_key: Optional[str],
) -> PaymentIntent:
    if amount_tiyin <= 0:
        raise HTTPException(400, "amount_tiyin > 0 bo'lishi kerak")
    if idempotency_key:
        existing = db.query(PaymentIntent).filter(
            PaymentIntent.idempotency_key == idempotency_key
        ).first()
        if existing:
            return existing

    i = PaymentIntent(
        intent_id="pi_" + secrets.token_hex(10),
        user_id=user.id, amount_tiyin=amount_tiyin,
        status="requires_payment",
        description=description[:250],
        customer_name=customer_name, customer_email=customer_email,
        psp_provider=PSP_PROVIDER,
        psp_ref="mock_" + secrets.token_hex(8),
        fee_tiyin=_fee(amount_tiyin),
        idempotency_key=idempotency_key,
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def confirm_intent(db: Session, intent_id: str, outcome: str) -> PaymentIntent:
    i = db.query(PaymentIntent).filter(PaymentIntent.intent_id == intent_id).first()
    if not i:
        raise HTTPException(404, "Payment intent topilmadi")
    if i.status in ("succeeded", "failed", "canceled"):
        return i

    if outcome == "fail":
        i.status = "failed"
        i.completed_at = utcnow()
        db.commit()
        db.refresh(i)
        return i

    i.status = "processing"
    db.flush()

    net = i.amount_tiyin - i.fee_tiyin
    post_entries(db, [
        {"account": "external:psp",              "direction": "debit",  "amount_tiyin": i.amount_tiyin},
        {"account": f"user:{i.user_id}:UZS",     "direction": "credit", "amount_tiyin": net},
        {"account": "platform:fees:UZS",         "direction": "credit", "amount_tiyin": i.fee_tiyin},
    ], ref_type="payment_intent", ref_id=i.intent_id, note=i.description)

    i.status = "succeeded"
    i.completed_at = utcnow()
    db.commit()
    db.refresh(i)
    return i


def mock_deposit(db: Session, user: User, amount_tiyin: int) -> dict:
    if amount_tiyin <= 0:
        raise HTTPException(400, "amount_tiyin > 0 bo'lishi kerak")
    group = post_entries(db, [
        {"account": "external:psp",          "direction": "debit",  "amount_tiyin": amount_tiyin},
        {"account": f"user:{user.id}:UZS",   "direction": "credit", "amount_tiyin": amount_tiyin},
    ], ref_type="mock_deposit", ref_id="dep_" + secrets.token_hex(8), note="Dev funding")
    db.commit()
    return {"group_id": group, "amount_tiyin": amount_tiyin}


# ============================================================
# WEBHOOK
# ============================================================
def dispatch_webhook(user_id: int, event: str, data: dict):
    try:
        import httpx
    except ImportError:
        return
    db = SessionLocal()
    try:
        endpoints = db.query(WebhookEndpoint).filter(
            WebhookEndpoint.user_id == user_id,
            WebhookEndpoint.is_active == True,
        ).all()
        if not endpoints:
            return
        payload = json.dumps({"event": event, "data": data},
                              separators=(",", ":")).encode()
        t = str(int(time.time()))
        for ep in endpoints:
            if ep.events != "*" and event not in ep.events.split(","):
                continue
            sig = hmac_lib.new(
                ep.secret.encode(),
                f"{t}.{payload.decode()}".encode(),
                hashlib.sha256,
            ).hexdigest()
            try:
                httpx.post(ep.url, content=payload, timeout=8, headers={
                    "Content-Type": "application/json",
                    "X-FoxPay-Signature": f"t={t},v1={sig}",
                    "X-FoxPay-Event": event,
                })
            except Exception as e:
                print(f"[webhook] {ep.url} failed: {e}")
    finally:
        db.close()


# ============================================================
# FASTAPI APP
# ============================================================
app = FastAPI(
    title="FoxPay API",
    version="2.0.0",
    description="FoxPay — shaxsiy to'lovlar API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Health (Render health check uchun) ----------
@app.get("/api/health")
@app.get("/healthz")
def health():
    return {
        "ok": True, "service": "foxpay", "version": "2.0.0",
        "port": PORT, "db": DB_PATH, "dev": DEV_MODE,
    }


# ---------- AUTH ----------
@app.post("/api/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(400, "Bu email allaqachon ro'yxatdan o'tgan")
    u = User(
        name=body.name.strip(),
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        phone=body.phone,
        company=(body.company or "").strip(),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    ensure_wallet(db, u.id)
    return {"token": create_access_token(u.id), "user": user_dict(u)}


@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == body.email.lower()).first()
    if not u or not verify_password(body.password, u.password_hash):
        raise HTTPException(401, "Email yoki parol noto'g'ri")
    return {"token": create_access_token(u.id), "user": user_dict(u)}


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return user_dict(user)


# ---------- WALLET ----------
@app.get("/api/wallet")
def wallet(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    bal = get_balance(db, user.id)
    return {
        "currency": "UZS",
        "balance_tiyin": bal,
        "balance_uzs": bal / 100,
        "balance_display": f"{bal/100:,.2f} so'm",
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
    return [{
        "group_id": r.group_id, "account": r.account,
        "direction": r.direction, "amount_tiyin": r.amount_tiyin,
        "ref_type": r.ref_type, "ref_id": r.ref_id,
        "note": r.note, "created_at": iso(r.created_at),
    } for r in rows]


# ---------- P2P ----------
@app.post("/api/p2p/transfers", status_code=201)
def send_money(
    body: TransferIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    t = create_transfer(
        db, user,
        to_email=body.to_email, to_phone=body.to_phone,
        amount_tiyin=body.amount_tiyin, note=body.note,
        idempotency_key=idempotency_key or body.idempotency_key,
    )
    payload = transfer_dict(t)
    background.add_task(dispatch_webhook, user.id, "transfer.succeeded", payload)
    return payload


@app.get("/api/p2p/transfers")
def list_transfers(
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(Transfer).filter(
        (Transfer.from_user_id == user.id) | (Transfer.to_user_id == user.id)
    ).order_by(Transfer.created_at.desc()).limit(limit).all()
    return [transfer_dict(t) for t in rows]


@app.get("/api/p2p/transfers/{transfer_id}")
def get_transfer(
    transfer_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = db.query(Transfer).filter(Transfer.transfer_id == transfer_id).first()
    if not t or user.id not in (t.from_user_id, t.to_user_id):
        raise HTTPException(404, "Topilmadi")
    return transfer_dict(t)


# ---------- PAYMENTS ----------
@app.post("/api/pay/intents", status_code=201)
def new_intent(
    body: IntentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    i = create_intent(
        db, user,
        amount_tiyin=body.amount_tiyin, description=body.description,
        customer_name=body.customer_name, customer_email=body.customer_email,
        idempotency_key=idempotency_key or body.idempotency_key,
    )
    return intent_dict(i)


@app.post("/api/pay/intents/{intent_id}/confirm")
def confirm(
    intent_id: str,
    body: ConfirmIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    i = db.query(PaymentIntent).filter(PaymentIntent.intent_id == intent_id).first()
    if not i or i.user_id != user.id:
        raise HTTPException(404, "Topilmadi")
    i = confirm_intent(db, intent_id, body.outcome)
    payload = intent_dict(i)
    background.add_task(dispatch_webhook, user.id, f"payment_intent.{i.status}", payload)
    return payload


@app.get("/api/pay/intents")
def list_intents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(PaymentIntent).filter(
        PaymentIntent.user_id == user.id
    ).order_by(PaymentIntent.created_at.desc()).limit(50).all()
    return [intent_dict(i) for i in rows]


@app.get("/api/pay/intents/{intent_id}")
def get_intent(
    intent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    i = db.query(PaymentIntent).filter(PaymentIntent.intent_id == intent_id).first()
    if not i or i.user_id != user.id:
        raise HTTPException(404, "Topilmadi")
    return intent_dict(i)


# ---------- API KEYS ----------
@app.get("/api/keys")
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(
        ApiKey.user_id == user.id
    ).order_by(ApiKey.created_at.desc()).all()
    return [key_dict(k) for k in rows]


@app.post("/api/keys", status_code=201)
def create_key(
    body: ApiKeyCreateIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    full, prefix, key_hash = generate_api_key()
    k = ApiKey(
        user_id=user.id, prefix=prefix, key_hash=key_hash,
        label=body.label, scopes=body.scopes,
    )
    db.add(k)
    db.commit()
    db.refresh(k)
    d = key_dict(k)
    d["full_key"] = full
    return d


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


# ---------- WEBHOOKS ----------
@app.get("/api/hooks/endpoints")
def list_hooks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.user_id == user.id
    ).all()
    return [hook_dict(w) for w in rows]


@app.post("/api/hooks/endpoints", status_code=201)
def create_hook(
    body: WebhookIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    w = WebhookEndpoint(
        user_id=user.id, url=body.url,
        secret="whsec_" + secrets.token_hex(20), events=body.events,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return hook_dict(w)


@app.delete("/api/hooks/endpoints/{hook_id}", status_code=204)
def delete_hook(
    hook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    w = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.id == hook_id,
        WebhookEndpoint.user_id == user.id,
    ).first()
    if not w:
        raise HTTPException(404, "Topilmadi")
    db.delete(w)
    db.commit()


# ---------- SETTINGS ----------
@app.get("/api/settings")
def get_settings(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.put("/api/settings")
def update_settings(
    body: ProfileIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.email and body.email.lower() != user.email:
        clash = db.query(User).filter(
            User.email == body.email.lower(), User.id != user.id
        ).first()
        if clash:
            raise HTTPException(400, "Bu email band")
        user.email = body.email.lower()
    if body.name:
        user.name = body.name.strip()
    if body.phone is not None:
        user.phone = body.phone.strip() or None
    if body.company is not None:
        user.company = body.company.strip()
    db.commit()
    db.refresh(user)
    return user_dict(user)


# ---------- DEV FUND ----------
@app.post("/api/dev/fund")
def fund(
    body: DepositIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not DEV_MODE:
        raise HTTPException(403, "Dev mode o'chirilgan (FOXPAY_DEV=0)")
    return mock_deposit(db, user, body.amount_tiyin)


# ---------- BOOTSTRAP ----------
@app.get("/api/bootstrap")
def bootstrap(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    bal = get_balance(db, user.id)
    transfers = db.query(Transfer).filter(
        (Transfer.from_user_id == user.id) | (Transfer.to_user_id == user.id)
    ).order_by(Transfer.created_at.desc()).limit(20).all()
    intents = db.query(PaymentIntent).filter(
        PaymentIntent.user_id == user.id
    ).order_by(PaymentIntent.created_at.desc()).limit(20).all()
    return {
        "user": user_dict(user),
        "wallet": {"currency": "UZS", "balance_tiyin": bal, "balance_uzs": bal / 100},
        "transfers": [transfer_dict(t) for t in transfers],
        "payment_intents": [intent_dict(i) for i in intents],
    }


# ============================================================
# FRONTEND SERVING
# ============================================================
@app.get("/")
def index():
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML)
    return JSONResponse({
        "message": "FoxPay API ishlamoqda",
        "docs": "/docs",
        "health": "/api/health",
    })


@app.get("/{path:path}")
def catch_all(path: str):
    if path.startswith("api/") or path == "healthz":
        raise HTTPException(404, "API endpoint topilmadi")
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML)
    raise HTTPException(404, "Fayl topilmadi")


# ============================================================
# ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import uvicorn
    print(f"\n  FoxPay API   →  http://localhost:{PORT}")
    print(f"  Swagger      →  http://localhost:{PORT}/docs")
    print(f"  Health       →  http://localhost:{PORT}/api/health")
    print(f"  DB           →  {DB_PATH}")
    print(f"  Dev mode     →  {'ON' if DEV_MODE else 'OFF'}\n")
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
        access_log=True,
    )
