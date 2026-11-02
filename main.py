"""
═══════════════════════════════════════════════════════════════════════════════
FoxPay — Full Backend v5.0.0
═══════════════════════════════════════════════════════════════════════════════

Integrations:
  - Stripe (cards, subscriptions, refunds)
  - J.P. Morgan Payments (OAuth2, transactions, FX)
  - Internal double-entry ledger

Features:
  Auth, wallet, P2P, intents, API keys, webhooks,
  notifications, analytics, KYC, admin, export, audit.

Render:
  Build: pip install -r requirements.txt
  Start: uvicorn main:app --host 0.0.0.0 --port $PORT

Environment:
  FOXPAY_SECRET       JWT signing key (required)
  FOXPAY_DB           SQLite path (default /tmp/foxpay_v5.db)
  FOXPAY_DEV          "1" enables /api/dev/* endpoints
  SITE_URL            canonical URL
  ADMIN_EMAIL         admin login email
  ADMIN_PASSWORD      admin password
  STRIPE_SECRET_KEY   Stripe secret (optional)
  STRIPE_WEBHOOK_SECRET  Stripe webhook signing
  JPM_CLIENT_ID       JPMorgan OAuth client id (optional)
  JPM_CLIENT_SECRET   JPMorgan OAuth secret
  JPM_MERCHANT_ID     JPMorgan merchant id
═══════════════════════════════════════════════════════════════════════════════
"""

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

import os
import re
import sys
import json
import csv
import io
import time
import hmac
import html
import uuid
import base64
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict

import jwt
import httpx
from fastapi import (
    FastAPI, Depends, HTTPException, Header, Request, Response,
    status, Query, BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    FileResponse, JSONResponse, PlainTextResponse, HTMLResponse,
    StreamingResponse, Response as FastResponse,
)
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    BigInteger, ForeignKey, Text, Float, Index, text,
    func, or_, and_, desc,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.exc import SQLAlchemyError

# Optional Stripe
try:
    import stripe as _stripe
    STRIPE_AVAILABLE = True
except ImportError:
    _stripe = None
    STRIPE_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

DB_VERSION = "v5"
BASE_DIR = Path(__file__).resolve().parent

SITE_NAME = os.getenv("SITE_NAME", "FoxPay")
SITE_URL = os.getenv("SITE_URL", "https://foxpay.uz")
SITE_DESCRIPTION = (
    "Xalqaro to'lov platformasi. Stripe, J.P. Morgan, P2P o'tkazmalar, "
    "multi-currency hamyon. Freelancerlar va biznes uchun."
)
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "hello@foxpay.uz")

PORT = int(os.getenv("PORT", "9988"))
HOST = os.getenv("HOST", "0.0.0.0")
SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
ACCESS_TOKEN_MIN = 60 * 24 * 7
REFRESH_TOKEN_DAYS = 30

DEV_MODE = os.getenv("FOXPAY_DEV", "1") == "1"
RENDER_MODE = os.getenv("RENDER") is not None

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@foxpay.uz").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
ADMIN_NAME = os.getenv("ADMIN_NAME", "Admin")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
JPM_CLIENT_ID = os.getenv("JPM_CLIENT_ID", "")
JPM_CLIENT_SECRET = os.getenv("JPM_CLIENT_SECRET", "")
JPM_MERCHANT_ID = os.getenv("JPM_MERCHANT_ID", "")
JPM_API_BASE = os.getenv("JPM_API_BASE", "https://api.payments.jpmorgan.com")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("foxpay")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_db_path() -> str:
    if os.getenv("FOXPAY_DB"):
        return os.getenv("FOXPAY_DB")

    candidates = []
    candidates.append(str(BASE_DIR / f"foxpay_{DB_VERSION}.db"))
    if RENDER_MODE:
        candidates.append(f"/tmp/foxpay_{DB_VERSION}.db")
    candidates.append(f"/tmp/foxpay_{DB_VERSION}.db")

    for path in candidates:
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            probe = p.parent / f".write_probe_{secrets.token_hex(3)}"
            probe.write_text("x")
            probe.unlink()
            return path
        except Exception:
            continue
    return f"/tmp/foxpay_{DB_VERSION}.db"


DB_PATH = _resolve_db_path()
log.info(f"Database: {DB_PATH}")

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


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False, default="")
    password_hash = Column(String(255), nullable=False, default="")
    phone = Column(String(32), nullable=True)
    company = Column(String(200), default="")
    role = Column(String(16), default="user", index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, index=True)
    language = Column(String(8), default="uz")
    kyc_status = Column(String(16), default="none", index=True)
    kyc_submitted_at = Column(DateTime, nullable=True)
    kyc_verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    currency = Column(String(8), default="UZS", nullable=False)
    balance_tiyin = Column(BigInteger, default=0, nullable=False)
    frozen_tiyin = Column(BigInteger, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


Index("ix_wallet_user_currency", Wallet.user_id, Wallet.currency, unique=True)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    currency = Column(String(8), default="UZS")
    direction = Column(String(8), nullable=False)
    amount_tiyin = Column(BigInteger, nullable=False)
    balance_after = Column(BigInteger, default=0)
    ref_type = Column(String(32), default="", index=True)
    ref_id = Column(String(64), default="", index=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, index=True)


class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    transfer_id = Column(String(32), unique=True, index=True, nullable=False)
    from_user_id = Column(Integer, index=True)
    to_user_id = Column(Integer, index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    currency = Column(String(8), default="UZS")
    status = Column(String(16), default="succeeded", index=True)
    note = Column(String(255), default="")
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id = Column(Integer, primary_key=True)
    intent_id = Column(String(32), unique=True, index=True, nullable=False)
    user_id = Column(Integer, index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    net_tiyin = Column(BigInteger, default=0)
    currency = Column(String(8), default="UZS")
    status = Column(String(20), default="requires_payment", index=True)
    provider = Column(String(16), default="internal")
    provider_ref = Column(String(128), nullable=True, index=True)
    description = Column(String(255), default="")
    customer_email = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    prefix = Column(String(20), index=True)
    key_hash = Column(String(64), nullable=False)
    label = Column(String(64), default="default")
    scopes = Column(String(200), default="read,write,p2p,collect")
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(100), nullable=False)
    events = Column(String(255), default="*")
    is_active = Column(Boolean, default=True)
    failure_count = Column(Integer, default=0)
    last_success_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    title = Column(String(200), nullable=False)
    message = Column(Text, default="")
    type = Column(String(32), default="info")
    is_read = Column(Boolean, default=False, index=True)
    link = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=True)
    action = Column(String(64), index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, index=True)


class KYCSubmission(Base):
    __tablename__ = "kyc_submissions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    full_name = Column(String(200), default="")
    passport_number = Column(String(32), default="")
    birth_date = Column(String(16), default="")
    address = Column(String(500), default="")
    document_url = Column(String(500), nullable=True)
    status = Column(String(16), default="pending", index=True)
    rejection_reason = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(Integer, nullable=True)


class ExchangeRate(Base):
    __tablename__ = "exchange_rates"
    id = Column(Integer, primary_key=True)
    from_currency = Column(String(8), index=True)
    to_currency = Column(String(8), index=True)
    rate = Column(Float, default=1.0)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class StripeCustomer(Base):
    __tablename__ = "stripe_customers"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, unique=True)
    stripe_customer_id = Column(String(64), index=True)
    created_at = Column(DateTime, default=utcnow)


class StripePayment(Base):
    __tablename__ = "stripe_payments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    payment_intent_id = Column(String(64), unique=True, index=True)
    amount_tiyin = Column(BigInteger)
    currency = Column(String(8), default="usd")
    status = Column(String(20), default="pending")
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class JPMPayment(Base):
    __tablename__ = "jpm_payments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    transaction_id = Column(String(64), unique=True, index=True)
    amount_tiyin = Column(BigInteger)
    currency = Column(String(8), default="USD")
    status = Column(String(20), default="pending")
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


Base.metadata.create_all(bind=engine)
log.info("Tables created")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SUPPORTED_CURRENCIES = ["UZS", "USD", "EUR", "GBP", "RUB"]

DEFAULT_RATES = {
    ("UZS", "USD"): 0.00008,
    ("UZS", "EUR"): 0.000074,
    ("UZS", "GBP"): 0.000064,
    ("UZS", "RUB"): 0.0073,
    ("USD", "UZS"): 12500.0,
    ("EUR", "UZS"): 13500.0,
    ("GBP", "UZS"): 15800.0,
    ("RUB", "UZS"): 137.0,
    ("USD", "EUR"): 0.92,
    ("EUR", "USD"): 1.09,
    ("USD", "GBP"): 0.79,
    ("GBP", "USD"): 1.26,
    ("EUR", "GBP"): 0.86,
    ("GBP", "EUR"): 1.16,
}

FEE_RATE_BPS = 150
MIN_TRANSFER_TIYIN = 100
MAX_TRANSFER_TIYIN = 10_000_000_000_000

BOT_PATTERNS = [
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebookexternalhit", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "applebot",
]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email format")
    if len(email) > 200:
        raise HTTPException(400, "Email too long")
    return email


def hash_password(raw: str) -> str:
    if not raw or len(raw) < 6:
        raise ValueError("Password too short")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt, 100_000)
    return f"pbkdf2_sha256$100000${salt.hex()}${dk.hex()}"


def verify_password(raw: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", raw.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def make_token(uid: int, token_type: str = "access") -> str:
    days = REFRESH_TOKEN_DAYS if token_type == "refresh" else 7
    return jwt.encode(
        {
            "sub": str(uid),
            "type": token_type,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=days),
        },
        SECRET_KEY, algorithm=JWT_ALG,
    )


def decode_token(token: str, expected: str = "access") -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        if payload.get("type") != expected:
            raise HTTPException(401, "Invalid token type")
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    except (KeyError, ValueError):
        raise HTTPException(401, "Malformed token")


def hash_api_key(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def generate_api_key() -> Tuple[str, str, str]:
    full = "fox_live_" + secrets.token_hex(24)
    return full, full[:20], hash_api_key(full)


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization header")
    token = authorization[7:].strip()

    if token.startswith("fox_live_"):
        prefix = token[:20]
        kh = hash_api_key(token)
        key = db.query(ApiKey).filter(
            ApiKey.prefix == prefix,
            ApiKey.key_hash == kh,
            ApiKey.is_active == True,
        ).first()
        if not key:
            raise HTTPException(401, "Invalid API key")
        key.last_used_at = utcnow()
        db.commit()
        user = db.get(User, key.user_id)
    else:
        user = db.get(User, decode_token(token, "access"))

    if not user:
        raise HTTPException(401, "User not found")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Admin access required")
    return user


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

_rate_store: Dict[str, List[float]] = defaultdict(list)


def rate_limit(key: str, limit: int = 60, window: int = 60) -> None:
    now = time.time()
    _rate_store[key] = [t for t in _rate_store[key] if t > now - window]
    if len(_rate_store[key]) >= limit:
        raise HTTPException(429, "Too many requests")
    _rate_store[key].append(now)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def get_balance(db: Session, user_id: int, currency: str = "UZS") -> int:
    rows = db.query(LedgerEntry.direction, LedgerEntry.amount_tiyin).filter(
        LedgerEntry.user_id == user_id,
        LedgerEntry.currency == currency,
    ).all()
    credits = sum(r[1] for r in rows if r[0] == "credit")
    debits = sum(r[1] for r in rows if r[0] == "debit")
    return credits - debits


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


def post_ledger(
    db: Session,
    user_id: int,
    direction: str,
    amount: int,
    ref_type: str = "",
    ref_id: str = "",
    description: str = "",
    currency: str = "UZS",
) -> LedgerEntry:
    if direction not in ("credit", "debit") or amount <= 0:
        raise ValueError("Invalid ledger entry")

    ensure_wallet(db, user_id, currency)
    current = get_balance(db, user_id, currency)
    new_balance = current + (amount if direction == "credit" else -amount)

    entry = LedgerEntry(
        user_id=user_id,
        currency=currency,
        direction=direction,
        amount_tiyin=amount,
        balance_after=new_balance,
        ref_type=ref_type,
        ref_id=ref_id,
        description=description,
    )
    db.add(entry)

    wallet = db.query(Wallet).filter(
        Wallet.user_id == user_id, Wallet.currency == currency
    ).first()
    if wallet:
        wallet.balance_tiyin = new_balance

    return entry


def calc_fee(amount: int, bps: int = FEE_RATE_BPS) -> int:
    return amount * bps // 10_000


def create_audit(db: Session, user_id: Optional[int], action: str,
                 request: Optional[Request] = None, details: str = "") -> None:
    try:
        db.add(AuditLog(
            user_id=user_id,
            action=action,
            ip_address=client_ip(request) if request else None,
            user_agent=(request.headers.get("user-agent") or "")[:500] if request else None,
            details=details,
        ))
        db.commit()
    except Exception as e:
        log.warning(f"Audit failed: {e}")


def notify(db: Session, user_id: int, title: str,
           message: str = "", ntype: str = "info",
           link: Optional[str] = None) -> None:
    try:
        db.add(Notification(
            user_id=user_id,
            title=title[:200],
            message=message,
            type=ntype,
            link=link,
        ))
        db.commit()
    except Exception as e:
        log.warning(f"Notification failed: {e}")


def get_rate(from_cur: str, to_cur: str, db: Session) -> float:
    if from_cur == to_cur:
        return 1.0
    r = db.query(ExchangeRate).filter(
        ExchangeRate.from_currency == from_cur,
        ExchangeRate.to_currency == to_cur,
    ).first()
    if r:
        return r.rate
    return DEFAULT_RATES.get((from_cur, to_cur), 0.0)


def convert_amount(amount: int, from_cur: str, to_cur: str, db: Session) -> int:
    if from_cur == to_cur:
        return amount
    rate = get_rate(from_cur, to_cur, db)
    if rate == 0:
        raise HTTPException(400, f"No rate for {from_cur}->{to_cur}")
    return int(amount * rate)


def user_dict(u: User) -> Dict[str, Any]:
    return {
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "phone": u.phone,
        "company": u.company,
        "role": u.role,
        "language": u.language,
        "is_admin": u.is_admin,
        "is_active": u.is_active,
        "kyc_status": u.kyc_status,
        "created_at": iso(u.created_at),
    }


def transfer_dict(t: Transfer) -> Dict[str, Any]:
    return {
        "id": t.transfer_id,
        "from_user_id": t.from_user_id,
        "to_user_id": t.to_user_id,
        "amount_tiyin": t.amount_tiyin,
        "amount": t.amount_tiyin / 100,
        "fee_tiyin": t.fee_tiyin,
        "currency": t.currency,
        "status": t.status,
        "note": t.note,
        "created_at": iso(t.created_at),
        "completed_at": iso(t.completed_at),
    }


def intent_dict(i: PaymentIntent) -> Dict[str, Any]:
    return {
        "id": i.intent_id,
        "amount_tiyin": i.amount_tiyin,
        "amount": i.amount_tiyin / 100,
        "fee_tiyin": i.fee_tiyin,
        "net_tiyin": i.net_tiyin,
        "currency": i.currency,
        "status": i.status,
        "provider": i.provider,
        "provider_ref": i.provider_ref,
        "description": i.description,
        "customer_email": i.customer_email,
        "created_at": iso(i.created_at),
        "completed_at": iso(i.completed_at),
    }


def entry_dict(e: LedgerEntry) -> Dict[str, Any]:
    return {
        "id": e.id,
        "direction": e.direction,
        "amount_tiyin": e.amount_tiyin,
        "amount": e.amount_tiyin / 100,
        "balance_after_tiyin": e.balance_after,
        "currency": e.currency,
        "ref_type": e.ref_type,
        "ref_id": e.ref_id,
        "description": e.description,
        "created_at": iso(e.created_at),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — STRIPE CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

def stripe_configured() -> bool:
    return STRIPE_AVAILABLE and bool(STRIPE_SECRET_KEY)


if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
    _stripe.api_key = STRIPE_SECRET_KEY
    log.info("Stripe configured")
else:
    log.info("Stripe not configured (STRIPE_SECRET_KEY missing)")


def stripe_create_customer(email: str, name: str = "") -> Optional[str]:
    if not stripe_configured():
        return None
    try:
        customer = _stripe.Customer.create(email=email, name=name or email)
        return customer.id
    except Exception as e:
        log.error(f"Stripe customer creation failed: {e}")
        return None


def stripe_create_payment_intent(
    amount_tiyin: int,
    currency: str = "usd",
    customer_id: Optional[str] = None,
    description: str = "",
) -> Optional[Dict[str, Any]]:
    if not stripe_configured():
        return None
    try:
        params = {
            "amount": amount_tiyin,
            "currency": currency.lower(),
            "automatic_payment_methods": {"enabled": True},
            "description": description or "FoxPay payment",
        }
        if customer_id:
            params["customer"] = customer_id

        intent = _stripe.PaymentIntent.create(**params)
        return {
            "id": intent.id,
            "client_secret": intent.client_secret,
            "status": intent.status,
            "amount": intent.amount,
            "currency": intent.currency,
        }
    except Exception as e:
        log.error(f"Stripe PaymentIntent failed: {e}")
        raise HTTPException(400, f"Stripe error: {str(e)}")


def stripe_refund(payment_intent_id: str, amount: Optional[int] = None) -> bool:
    if not stripe_configured():
        return False
    try:
        params = {"payment_intent": payment_intent_id}
        if amount:
            params["amount"] = amount
        _stripe.Refund.create(**params)
        return True
    except Exception as e:
        log.error(f"Stripe refund failed: {e}")
        return False


def stripe_verify_webhook(payload: bytes, sig_header: str) -> Optional[Dict[str, Any]]:
    if not STRIPE_WEBHOOK_SECRET:
        try:
            return json.loads(payload)
        except Exception:
            return None
    try:
        event = _stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        return event
    except Exception as e:
        log.error(f"Stripe webhook verification failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — J.P. MORGAN CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

_jpm_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0.0}


def jpm_configured() -> bool:
    return bool(JPM_CLIENT_ID and JPM_CLIENT_SECRET and JPM_MERCHANT_ID)


async def jpm_get_token() -> Optional[str]:
    if not jpm_configured():
        return None
    now = time.time()
    if _jpm_token_cache["token"] and _jpm_token_cache["expires_at"] > now + 60:
        return _jpm_token_cache["token"]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{JPM_API_BASE}/oauth2/token",
                data={"grant_type": "client_credentials"},
                auth=(JPM_CLIENT_ID, JPM_CLIENT_SECRET),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()
            _jpm_token_cache["token"] = data["access_token"]
            _jpm_token_cache["expires_at"] = now + int(data.get("expires_in", 3600))
            return data["access_token"]
    except Exception as e:
        log.error(f"JPM token failed: {e}")
        return None


async def jpm_create_payment(
    amount_tiyin: int,
    currency: str = "USD",
    description: str = "",
    reference: str = "",
) -> Optional[Dict[str, Any]]:
    if not jpm_configured():
        return None
    token = await jpm_get_token()
    if not token:
        raise HTTPException(502, "JPM authentication failed")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{JPM_API_BASE}/payments/v1/payments",
                json={
                    "merchantId": JPM_MERCHANT_ID,
                    "amount": amount_tiyin / 100,
                    "currency": currency,
                    "description": description or "FoxPay",
                    "reference": reference,
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        log.error(f"JPM payment failed: {e.response.text}")
        raise HTTPException(400, f"JPM error: {e.response.text}")
    except Exception as e:
        log.error(f"JPM payment exception: {e}")
        raise HTTPException(502, f"JPM unavailable: {str(e)}")


async def jpm_get_payment(transaction_id: str) -> Optional[Dict[str, Any]]:
    if not jpm_configured():
        return None
    token = await jpm_get_token()
    if not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{JPM_API_BASE}/payments/v1/payments/{transaction_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        log.error(f"JPM get payment failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str
    password: str = Field(min_length=6)
    phone: Optional[str] = None
    company: Optional[str] = ""


class LoginIn(BaseModel):
    email: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class PasswordIn(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6)


class ProfileIn(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    language: Optional[str] = None


class TransferIn(BaseModel):
    to_email: str
    amount_tiyin: int = Field(gt=0)
    note: str = ""


class IntentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    description: str = ""
    customer_email: Optional[str] = None


class StripePaymentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    currency: str = "usd"
    description: str = ""


class JPMPaymentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    currency: str = "USD"
    description: str = ""


class KeyIn(BaseModel):
    label: str = "default"
    scopes: str = "read,write,p2p,collect"


class HookIn(BaseModel):
    url: str = Field(min_length=10)
    events: str = "*"


class FundIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    currency: str = "UZS"


class KYCIn(BaseModel):
    full_name: str
    passport_number: str
    birth_date: str
    address: str


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — APP & MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="FoxPay API",
    version="5.0.0",
    description=SITE_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=500)


@app.middleware("http")
async def add_headers(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    start = time.time()

    try:
        response = await call_next(request)
    except Exception as e:
        log.exception(f"Unhandled on {request.url.path}: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

    duration = (time.time() - start) * 1000

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Request-ID"] = request_id

    path = request.url.path
    if path.startswith("/api/") or path.startswith("/docs"):
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Cache-Control"] = "no-store"
    elif path == "/":
        response.headers["X-Robots-Tag"] = "index, follow, max-image-preview:large"
        response.headers["Link"] = f'<{SITE_URL}/>; rel="canonical"'
    elif path in ("/robots.txt", "/sitemap.xml"):
        response.headers["Cache-Control"] = "public, max-age=3600"

    if duration > 1500:
        log.warning(f"Slow {request.method} {path}: {duration:.0f}ms")

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — LANDING HTML
# ═══════════════════════════════════════════════════════════════════════════════

def build_landing_html() -> str:
    year = utcnow().year
    today = utcnow().strftime("%Y-%m-%d")

    faq = [
        ("FoxPay nima?", "Xalqaro to'lov platformasi. Stripe va J.P. Morgan integratsiyasi, P2P o'tkazmalar, multi-currency."),
        ("Qanday valyutalar?", "UZS, USD, EUR, GBP, RUB. Real vaqt kursi bilan konvertatsiya."),
        ("Komissiya qancha?", "P2P 1.5%. Stripe va JPM — provayder komissiyasi."),
        ("API bormi?", "REST API, webhooks. /docs da batafsil."),
        ("Xavfsizlik?", "JWT, HMAC webhooks, audit log, rate limiting."),
    ]

    faq_json = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}}
            for q, a in faq
        ],
    }
    org_json = {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": SITE_NAME,
        "url": SITE_URL,
        "description": SITE_DESCRIPTION,
        "email": CONTACT_EMAIL,
    }
    app_json = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": SITE_NAME,
        "applicationCategory": "FinanceApplication",
        "operatingSystem": "Web",
    }

    faq_html = "".join(
        f'<details class="faq-item"><summary class="faq-q">{html.escape(q)}</summary>'
        f'<div class="faq-a">{html.escape(a)}</div></details>'
        for q, a in faq
    )

    return f'''<!DOCTYPE html>
<html lang="uz" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_NAME} — Xalqaro to'lov platformasi</title>
<meta name="description" content="{SITE_DESCRIPTION}">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="theme-color" content="#FF6B00">
<link rel="canonical" href="{SITE_URL}/">
<meta property="og:type" content="website">
<meta property="og:title" content="{SITE_NAME}">
<meta property="og:description" content="{SITE_DESCRIPTION}">
<meta property="og:url" content="{SITE_URL}/">
<script type="application/ld+json">{json.dumps(org_json)}</script>
<script type="application/ld+json">{json.dumps(app_json)}</script>
<script type="application/ld+json">{json.dumps(faq_json)}</script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0B1120;color:#F8FAFC;line-height:1.5;font-size:15px}}
a{{color:#FF6B00;text-decoration:none}}
.container{{max-width:1100px;margin:0 auto;padding:0 24px}}
.header{{border-bottom:1px solid #1E293B;padding:18px 0;position:sticky;top:0;background:rgba(11,17,32,.9);backdrop-filter:blur(12px);z-index:100}}
.nav{{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}}
.logo{{font-weight:800;font-size:20px}}
.logo span{{color:#00F2FE}}
.nav-links{{display:flex;gap:24px;flex-wrap:wrap}}
.nav-links a{{color:#94A3B8;font-size:14px}}
.btn{{display:inline-block;padding:12px 24px;border-radius:10px;font-weight:600;font-size:14px;cursor:pointer;border:0}}
.btn-primary{{background:linear-gradient(135deg,#FF6B00,#E64A00);color:#fff}}
.btn-outline{{background:transparent;color:#F8FAFC;border:1px solid #1E293B}}
.hero{{padding:80px 0 100px;text-align:center}}
.hero h1{{font-size:56px;font-weight:900;margin-bottom:20px;letter-spacing:-.02em}}
.hero .grad{{background:linear-gradient(135deg,#FF6B00,#E64A00);-webkit-background-clip:text;background-clip:text;color:transparent}}
.hero .lead{{font-size:18px;color:#94A3B8;max-width:640px;margin:0 auto 32px;line-height:1.6}}
.section{{padding:60px 0}}
h2{{font-size:36px;font-weight:800;margin-bottom:16px;text-align:center}}
.section p{{text-align:center;color:#94A3B8;margin-bottom:40px}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}}
.card{{background:#0F172A;border:1px solid #1E293B;border-radius:14px;padding:24px}}
.card-icon{{font-size:32px;margin-bottom:12px}}
.card h3{{font-size:16px;font-weight:700;margin-bottom:8px}}
.card p{{color:#94A3B8;font-size:14px;text-align:left}}
.faq-list{{max-width:760px;margin:0 auto}}
.faq-item{{background:#0F172A;border:1px solid #1E293B;border-radius:14px;margin-bottom:12px;padding:0;overflow:hidden}}
.faq-q{{padding:18px 22px;cursor:pointer;font-weight:600;font-size:15px;list-style:none}}
.faq-q::-webkit-details-marker{{display:none}}
.faq-a{{padding:0 22px 18px;color:#94A3B8;font-size:14px;line-height:1.7}}
.footer{{border-top:1px solid #1E293B;padding:32px 0;text-align:center;color:#64748B;font-size:13px;margin-top:60px}}
@media(max-width:768px){{
.hero h1{{font-size:36px}}
.grid{{grid-template-columns:1fr}}
.nav-links{{display:none}}
}}
</style>
</head>
<body>
<header class="header">
<div class="container nav">
<a href="/" class="logo">FOX<span>PAY</span></a>
<nav class="nav-links">
<a href="#features">Imkoniyatlar</a>
<a href="#faq">FAQ</a>
<a href="/docs">API</a>
</nav>
<div>
<a href="/#/login" class="btn btn-outline" style="margin-right:8px">Kirish</a>
<a href="/#/register" class="btn btn-primary">Boshlash</a>
</div>
</div>
</header>

<main>
<section class="hero">
<div class="container">
<h1>Xalqaro to'lovlar <span class="grad">bir zumda</span>.</h1>
<p class="lead">Stripe va J.P. Morgan integratsiyasi. Multi-currency hamyon. P2P o'tkazmalar. Freelancerlar va biznes uchun.</p>
<div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
<a href="/#/register" class="btn btn-primary">Bepul boshlash →</a>
<a href="/docs" class="btn btn-outline">API docs</a>
</div>
</div>
</section>

<section class="section" id="features">
<div class="container">
<h2>Hammasi bitta joyda</h2>
<p>Xalqaro darajadagi to'lov infratuzilmasi</p>
<div class="grid">
<div class="card"><div class="card-icon">💳</div><h3>Stripe</h3><p>Visa, Mastercard, Amex. Xalqaro karta to'lovlari.</p></div>
<div class="card"><div class="card-icon">🏦</div><h3>J.P. Morgan</h3><p>Korporativ to'lovlar, SWIFT, yuqori limit.</p></div>
<div class="card"><div class="card-icon">🌍</div><h3>Multi-currency</h3><p>UZS, USD, EUR, GBP, RUB. Real vaqt kursi.</p></div>
<div class="card"><div class="card-icon">💸</div><h3>P2P</h3><p>Email orqali bir zumda. 1.5% komissiya.</p></div>
<div class="card"><div class="card-icon">🔐</div><h3>KYC</h3><p>Passport verifikatsiya. AML standartlari.</p></div>
<div class="card"><div class="card-icon">📊</div><h3>Analytics</h3><p>Real vaqt dashboard, hisobotlar, CSV eksport.</p></div>
</div>
</div>
</section>

<section class="section" id="faq">
<div class="container">
<h2>Ko'p beriladigan savollar</h2>
<div class="faq-list">{faq_html}</div>
</div>
</section>
</main>

<footer class="footer">
<div class="container">
© {year} {SITE_NAME} Inc. · {today}
</div>
</footer>
</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — SEO ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return (
        f"User-agent: *\n"
        f"Allow: /\n"
        f"Disallow: /api/\n"
        f"Disallow: /docs\n"
        f"Disallow: /redoc\n"
        f"\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )


@app.get("/sitemap.xml", response_class=FastResponse)
def sitemap():
    today = utcnow().strftime("%Y-%m-%d")
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f'<url><loc>{SITE_URL}/</loc><lastmod>{today}</lastmod>'
        f'<changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
        f'</urlset>'
    )
    return FastResponse(content=xml, media_type="application/xml")


@app.get("/google{token}.html", response_class=PlainTextResponse)
def google_verification(token: str):
    if not re.match(r"^[a-zA-Z0-9_-]{4,64}$", token):
        raise HTTPException(404)
    fname = f"google{token}.html"
    path = BASE_DIR / fname
    if path.exists():
        return PlainTextResponse(
            f"google-site-verification: {fname}",
            media_type="text/html",
        )
    return PlainTextResponse(
        f"google-site-verification: {fname}",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/manifest.webmanifest")
def manifest():
    return JSONResponse(
        {
            "name": SITE_NAME,
            "short_name": SITE_NAME,
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0B1120",
            "theme_color": "#FF6B00",
        },
        media_type="application/manifest+json",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 16 — HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    db_ok = False
    db_error = None
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_ok = True
    except Exception as e:
        db_error = str(e)
        log.error(f"DB health: {e}")

    return {
        "ok": True,
        "version": "5.0.0",
        "python": sys.version.split()[0],
        "db": DB_PATH,
        "db_ok": db_ok,
        "db_error": db_error,
        "dev": DEV_MODE,
        "stripe": stripe_configured(),
        "jpm": jpm_configured(),
    }


@app.get("/api/debug")
def debug():
    info = {
        "python": sys.version,
        "db": DB_PATH,
        "db_version": DB_VERSION,
        "render": RENDER_MODE,
        "stripe_configured": stripe_configured(),
        "jpm_configured": jpm_configured(),
    }
    try:
        db = SessionLocal()
        info["users"] = db.query(User).count()
        info["transfers"] = db.query(Transfer).count()
        info["intents"] = db.query(PaymentIntent).count()
        info["ledger"] = db.query(LedgerEntry).count()
        db.close()
        info["db_ok"] = True
    except Exception as e:
        info["db_error"] = str(e)
        info["db_ok"] = False
    return info


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 17 — AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"reg:{client_ip(request)}", 5, 300)
    email = validate_email(body.email)

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Email already registered")

    user = User(
        email=email,
        name=body.name.strip(),
        password_hash=hash_password(body.password),
        phone=(body.phone or "").strip() or None,
        company=(body.company or "").strip(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ensure_wallet(db, user.id, "UZS")

    create_audit(db, user.id, "user.register", request, f"email={email}")
    notify(db, user.id, "Xush kelibsiz!",
           "FoxPay'ga ro'yxatdan o'tdingiz. Balansni to'ldiring va to'lovni boshlang.",
           "success")

    log.info(f"Registered: {email} (id={user.id})")

    return {
        "token": make_token(user.id, "access"),
        "refresh_token": make_token(user.id, "refresh"),
        "user": user_dict(user),
    }


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"login:{client_ip(request)}", 10, 60)
    email = validate_email(body.email)
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Email or password incorrect")

    if not user.is_active:
        raise HTTPException(403, "Account disabled")

    create_audit(db, user.id, "user.login", request)

    return {
        "token": make_token(user.id, "access"),
        "refresh_token": make_token(user.id, "refresh"),
        "user": user_dict(user),
    }


@app.post("/api/auth/refresh")
def refresh(body: RefreshIn):
    uid = decode_token(body.refresh_token, "refresh")
    return {
        "token": make_token(uid, "access"),
        "refresh_token": make_token(uid, "refresh"),
    }


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.post("/api/auth/password")
def change_password(body: PasswordIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(400, "Current password incorrect")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 18 — WALLET ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/wallet")
def get_wallet(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    currency: str = "UZS",
):
    if currency not in SUPPORTED_CURRENCIES:
        raise HTTPException(400, f"Currency must be one of {SUPPORTED_CURRENCIES}")

    bal = get_balance(db, user.id, currency)
    ensure_wallet(db, user.id, currency)

    return {
        "currency": currency,
        "balance_tiyin": bal,
        "balance": bal / 100,
    }


@app.get("/api/wallet/all")
def get_all_wallets(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = []
    for cur in SUPPORTED_CURRENCIES:
        bal = get_balance(db, user.id, cur)
        if bal != 0:
            result.append({
                "currency": cur,
                "balance_tiyin": bal,
                "balance": bal / 100,
            })
    return result


@app.get("/api/wallet/ledger")
def get_ledger(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    currency: Optional[str] = None,
):
    q = db.query(LedgerEntry).filter(LedgerEntry.user_id == user.id)
    if currency:
        q = q.filter(LedgerEntry.currency == currency)
    rows = q.order_by(desc(LedgerEntry.created_at)).offset(offset).limit(limit).all()
    return [entry_dict(r) for r in rows]


@app.post("/api/dev/fund")
def dev_fund(
    body: FundIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not DEV_MODE:
        raise HTTPException(403, "Dev mode disabled")
    if body.currency not in SUPPORTED_CURRENCIES:
        raise HTTPException(400, "Unsupported currency")
    if body.amount_tiyin > 100_000_000_000:
        raise HTTPException(400, "Limit exceeded")

    post_ledger(
        db, user.id, "credit", body.amount_tiyin,
        "deposit", f"dev_{secrets.token_hex(4)}",
        "Dev fund", currency=body.currency,
    )
    db.commit()

    return {
        "ok": True,
        "amount_tiyin": body.amount_tiyin,
        "currency": body.currency,
        "balance": get_balance(db, user.id, body.currency),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 19 — P2P TRANSFERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/p2p/transfers")
def create_transfer(
    body: TransferIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"p2p:{user.id}", 30, 60)

    if body.amount_tiyin < MIN_TRANSFER_TIYIN:
        raise HTTPException(400, f"Minimum: {MIN_TRANSFER_TIYIN / 100}")
    if body.amount_tiyin > MAX_TRANSFER_TIYIN:
        raise HTTPException(400, "Amount too large")

    to_email = validate_email(body.to_email)
    recipient = db.query(User).filter(User.email == to_email).first()

    if not recipient:
        raise HTTPException(404, "Recipient not found")
    if recipient.id == user.id:
        raise HTTPException(400, "Cannot send to yourself")
    if not recipient.is_active:
        raise HTTPException(400, "Recipient disabled")

    fee = calc_fee(body.amount_tiyin)
    total = body.amount_tiyin + fee
    bal = get_balance(db, user.id, "UZS")

    if bal < total:
        raise HTTPException(
            400,
            f"Insufficient. Need {(total) / 100:.2f} UZS, have {(bal) / 100:.2f} UZS"
        )

    tid = f"tr_{secrets.token_hex(10)}"

    post_ledger(db, user.id, "debit", total, "p2p", tid,
                f"To {recipient.name}", currency="UZS")
    post_ledger(db, recipient.id, "credit", body.amount_tiyin, "p2p", tid,
                f"From {user.name}", currency="UZS")

    transfer = Transfer(
        transfer_id=tid,
        from_user_id=user.id,
        to_user_id=recipient.id,
        amount_tiyin=body.amount_tiyin,
        fee_tiyin=fee,
        currency="UZS",
        status="succeeded",
        note=body.note[:255],
        completed_at=utcnow(),
    )
    db.add(transfer)
    db.commit()

    background.add_task(
        dispatch_webhook, user.id, "transfer.succeeded",
        {"transfer_id": tid, "amount_tiyin": body.amount_tiyin},
    )
    notify(db, recipient.id, "Pul qabul qilindi",
           f"{user.name} sizga {body.amount_tiyin / 100:,.0f} UZS yubordi",
           "success")

    return {
        "transfer_id": tid,
        "amount_tiyin": body.amount_tiyin,
        "fee_tiyin": fee,
        "status": "succeeded",
        "created_at": iso(transfer.created_at),
    }


@app.get("/api/p2p/transfers")
def list_transfers(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows = db.query(Transfer).filter(
        or_(Transfer.from_user_id == user.id, Transfer.to_user_id == user.id)
    ).order_by(desc(Transfer.created_at)).offset(offset).limit(limit).all()
    return [transfer_dict(t) for t in rows]


@app.get("/api/p2p/transfers/{transfer_id}")
def get_transfer(
    transfer_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = db.query(Transfer).filter(Transfer.transfer_id == transfer_id).first()
    if not t:
        raise HTTPException(404, "Not found")
    if user.id not in (t.from_user_id, t.to_user_id):
        raise HTTPException(403, "Access denied")
    return transfer_dict(t)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 20 — PAYMENT INTENTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/pay/intents")
def create_intent(
    body: IntentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"intent:{user.id}", 30, 60)

    if body.amount_tiyin < MIN_TRANSFER_TIYIN:
        raise HTTPException(400, "Too small")

    fee = calc_fee(body.amount_tiyin)
    net = body.amount_tiyin - fee

    intent = PaymentIntent(
        intent_id=f"pi_{secrets.token_hex(10)}",
        user_id=user.id,
        amount_tiyin=body.amount_tiyin,
        fee_tiyin=fee,
        net_tiyin=net,
        status="requires_payment",
        description=body.description[:255],
        customer_email=body.customer_email,
    )
    db.add(intent)
    db.commit()
    db.refresh(intent)

    return intent_dict(intent)


@app.get("/api/pay/intents")
def list_intents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(PaymentIntent).filter(
        PaymentIntent.user_id == user.id
    ).order_by(desc(PaymentIntent.created_at)).limit(50).all()
    return [intent_dict(i) for i in rows]


@app.post("/api/pay/intents/{intent_id}/confirm")
def confirm_intent(
    intent_id: str,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    intent = db.query(PaymentIntent).filter(
        PaymentIntent.intent_id == intent_id,
        PaymentIntent.user_id == user.id,
    ).first()

    if not intent:
        raise HTTPException(404, "Not found")
    if intent.status == "succeeded":
        return {"intent_id": intent_id, "status": "succeeded"}

    post_ledger(db, user.id, "credit", intent.net_tiyin, "intent", intent_id,
                intent.description)

    intent.status = "succeeded"
    intent.completed_at = utcnow()
    db.commit()

    background.add_task(
        dispatch_webhook, user.id, "payment.succeeded",
        {"intent_id": intent_id, "net_tiyin": intent.net_tiyin},
    )

    return {
        "intent_id": intent_id,
        "status": "succeeded",
        "net_tiyin": intent.net_tiyin,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 21 — STRIPE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stripe/status")
def stripe_status():
    return {
        "available": STRIPE_AVAILABLE,
        "configured": stripe_configured(),
    }


@app.post("/api/stripe/create-payment")
def stripe_create_payment(
    body: StripePaymentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not stripe_configured():
        raise HTTPException(503, "Stripe not configured")

    rate_limit(f"stripe:{user.id}", 10, 60)

    customer = db.query(StripeCustomer).filter(
        StripeCustomer.user_id == user.id
    ).first()

    if not customer:
        cid = stripe_create_customer(user.email, user.name)
        if cid:
            customer = StripeCustomer(
                user_id=user.id,
                stripe_customer_id=cid,
            )
            db.add(customer)
            db.commit()

    result = stripe_create_payment_intent(
        amount_tiyin=body.amount_tiyin,
        currency=body.currency,
        customer_id=customer.stripe_customer_id if customer else None,
        description=body.description,
    )

    payment = StripePayment(
        user_id=user.id,
        payment_intent_id=result["id"],
        amount_tiyin=body.amount_tiyin,
        currency=body.currency,
        status="pending",
        description=body.description,
    )
    db.add(payment)
    db.commit()

    return {
        "client_secret": result["client_secret"],
        "payment_intent_id": result["id"],
        "amount": body.amount_tiyin / 100,
        "currency": body.currency,
    }


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    event = stripe_verify_webhook(payload, sig)
    if not event:
        raise HTTPException(400, "Invalid signature")

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    if event_type == "payment_intent.succeeded":
        pi_id = data.get("id")
        payment = db.query(StripePayment).filter(
            StripePayment.payment_intent_id == pi_id
        ).first()
        if payment:
            payment.status = "succeeded"
            payment.completed_at = utcnow()
            db.commit()

    elif event_type == "payment_intent.payment_failed":
        pi_id = data.get("id")
        payment = db.query(StripePayment).filter(
            StripePayment.payment_intent_id == pi_id
        ).first()
        if payment:
            payment.status = "failed"
            db.commit()

    return {"received": True}


@app.get("/api/stripe/payments")
def stripe_payments(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(StripePayment).filter(
        StripePayment.user_id == user.id
    ).order_by(desc(StripePayment.created_at)).limit(50).all()

    return [
        {
            "id": p.id,
            "payment_intent_id": p.payment_intent_id,
            "amount": p.amount_tiyin / 100,
            "currency": p.currency,
            "status": p.status,
            "created_at": iso(p.created_at),
        }
        for p in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 22 — JPMORGAN ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/jpm/status")
def jpm_status():
    return {
        "configured": jpm_configured(),
        "merchant_id": JPM_MERCHANT_ID[:8] + "..." if JPM_MERCHANT_ID else None,
    }


@app.post("/api/jpm/create-payment")
async def jpm_create(
    body: JPMPaymentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not jpm_configured():
        raise HTTPException(503, "J.P. Morgan not configured")

    rate_limit(f"jpm:{user.id}", 10, 60)

    result = await jpm_create_payment(
        amount_tiyin=body.amount_tiyin,
        currency=body.currency,
        description=body.description,
        reference=f"user_{user.id}",
    )

    payment = JPMPayment(
        user_id=user.id,
        transaction_id=result.get("transactionId", f"jpm_{secrets.token_hex(8)}"),
        amount_tiyin=body.amount_tiyin,
        currency=body.currency,
        status="pending",
        description=body.description,
    )
    db.add(payment)
    db.commit()

    return {
        "transaction_id": payment.transaction_id,
        "status": "pending",
        "amount": body.amount_tiyin / 100,
        "currency": body.currency,
    }


@app.get("/api/jpm/payments")
def jpm_payments(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(JPMPayment).filter(
        JPMPayment.user_id == user.id
    ).order_by(desc(JPMPayment.created_at)).limit(50).all()

    return [
        {
            "id": p.id,
            "transaction_id": p.transaction_id,
            "amount": p.amount_tiyin / 100,
            "currency": p.currency,
            "status": p.status,
            "created_at": iso(p.created_at),
        }
        for p in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 23 — API KEYS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/keys")
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.user_id == user.id).all()
    return [
        {
            "id": k.id,
            "prefix": k.prefix,
            "label": k.label,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "last_used_at": iso(k.last_used_at),
            "created_at": iso(k.created_at),
        }
        for k in rows
    ]


@app.post("/api/keys")
def create_key(body: KeyIn, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    rate_limit(f"key:{user.id}", 10, 60)

    full, prefix, kh = generate_api_key()
    k = ApiKey(
        user_id=user.id,
        prefix=prefix,
        key_hash=kh,
        label=body.label[:64],
        scopes=body.scopes[:200],
    )
    db.add(k)
    db.commit()
    db.refresh(k)

    return {
        "id": k.id,
        "prefix": k.prefix,
        "label": k.label,
        "scopes": k.scopes,
        "is_active": True,
        "full_key": full,
    }


@app.delete("/api/keys/{key_id}")
def revoke_key(key_id: int, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.user_id == user.id,
    ).first()
    if not k:
        raise HTTPException(404, "Not found")
    k.is_active = False
    db.commit()
    return {"ok": True}


@app.post("/api/keys/{key_id}/rotate")
def rotate_key(key_id: int, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.user_id == user.id,
    ).first()
    if not k:
        raise HTTPException(404, "Not found")

    full, prefix, kh = generate_api_key()
    k.prefix = prefix
    k.key_hash = kh
    k.is_active = True
    db.commit()

    return {"id": k.id, "prefix": k.prefix, "full_key": full}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 24 — WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/hooks")
def list_hooks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(WebhookEndpoint).filter(WebhookEndpoint.user_id == user.id).all()
    return [
        {
            "id": h.id,
            "url": h.url,
            "events": h.events,
            "is_active": h.is_active,
            "failure_count": h.failure_count,
            "created_at": iso(h.created_at),
        }
        for h in rows
    ]


@app.post("/api/hooks")
def create_hook(body: HookIn, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "Invalid URL")

    h = WebhookEndpoint(
        user_id=user.id,
        url=body.url,
        secret=f"whsec_{secrets.token_hex(20)}",
        events=body.events,
    )
    db.add(h)
    db.commit()
    db.refresh(h)

    return {"id": h.id, "url": h.url, "events": h.events}


@app.delete("/api/hooks/{hook_id}")
def delete_hook(hook_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    h = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.id == hook_id,
        WebhookEndpoint.user_id == user.id,
    ).first()
    if not h:
        raise HTTPException(404, "Not found")
    db.delete(h)
    db.commit()
    return {"ok": True}


def dispatch_webhook(user_id: int, event: str, data: Dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        hooks = db.query(WebhookEndpoint).filter(
            WebhookEndpoint.user_id == user_id,
            WebhookEndpoint.is_active == True,
        ).all()

        if not hooks:
            return

        payload = json.dumps({"event": event, "data": data}, separators=(",", ":"))
        ts = str(int(time.time()))

        for h in hooks:
            if h.events != "*" and event not in h.events.split(","):
                continue

            sig = hmac.new(
                h.secret.encode(),
                f"{ts}.{payload}".encode(),
                hashlib.sha256,
            ).hexdigest()

            try:
                httpx.post(h.url, content=payload, timeout=10, headers={
                    "Content-Type": "application/json",
                    "X-FoxPay-Signature": f"t={ts},v1={sig}",
                    "X-FoxPay-Event": event,
                })
                h.last_success_at = utcnow()
                h.failure_count = 0
            except Exception as e:
                h.failure_count = (h.failure_count or 0) + 1
                log.warning(f"Webhook failed {h.url}: {e}")

        db.commit()
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 25 — NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/notifications")
def list_notifications(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(30, ge=1, le=100),
):
    rows = db.query(Notification).filter(
        Notification.user_id == user.id
    ).order_by(desc(Notification.created_at)).limit(limit).all()

    unread = db.query(Notification).filter(
        Notification.user_id == user.id,
        Notification.is_read == False,
    ).count()

    return {
        "items": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "is_read": n.is_read,
                "link": n.link,
                "created_at": iso(n.created_at),
            }
            for n in rows
        ],
        "unread": unread,
    }


@app.post("/api/notifications/{nid}/read")
def mark_read(nid: int, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    n = db.query(Notification).filter(
        Notification.id == nid,
        Notification.user_id == user.id,
    ).first()
    if not n:
        raise HTTPException(404, "Not found")
    n.is_read = True
    db.commit()
    return {"ok": True}


@app.post("/api/notifications/read-all")
def mark_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Notification).filter(
        Notification.user_id == user.id,
        Notification.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 26 — ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/analytics/summary")
def analytics_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    balance = get_balance(db, user.id, "UZS")

    sent = db.query(Transfer).filter(
        Transfer.from_user_id == user.id,
        Transfer.status == "succeeded",
    ).all()
    received = db.query(Transfer).filter(
        Transfer.to_user_id == user.id,
        Transfer.status == "succeeded",
    ).all()

    total_sent = sum(t.amount_tiyin for t in sent)
    total_received = sum(t.amount_tiyin for t in received)
    total_fees = sum(t.fee_tiyin for t in sent)

    return {
        "balance_uzs": balance / 100,
        "balance_tiyin": balance,
        "total_sent_uzs": total_sent / 100,
        "total_received_uzs": total_received / 100,
        "total_fees_uzs": total_fees / 100,
        "transfers_count": len(sent) + len(received),
    }


@app.get("/api/analytics/daily")
def analytics_daily(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    days: int = Query(7, ge=1, le=90),
):
    now = utcnow()
    result = []

    for i in range(days - 1, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        rows = db.query(Transfer).filter(
            or_(Transfer.from_user_id == user.id, Transfer.to_user_id == user.id),
            Transfer.status == "succeeded",
            Transfer.created_at >= day_start,
            Transfer.created_at < day_end,
        ).all()

        volume = sum(t.amount_tiyin for t in rows)

        result.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "count": len(rows),
            "volume_uzs": volume / 100,
        })

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 27 — KYC
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/kyc/status")
def kyc_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    submission = db.query(KYCSubmission).filter(
        KYCSubmission.user_id == user.id
    ).order_by(desc(KYCSubmission.created_at)).first()

    return {
        "user_status": user.kyc_status,
        "submission": {
            "id": submission.id,
            "status": submission.status,
            "created_at": iso(submission.created_at),
            "rejection_reason": submission.rejection_reason,
        } if submission else None,
    }


@app.post("/api/kyc/submit")
def kyc_submit(body: KYCIn, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    if user.kyc_status == "verified":
        raise HTTPException(400, "Already verified")

    existing = db.query(KYCSubmission).filter(
        KYCSubmission.user_id == user.id,
        KYCSubmission.status == "pending",
    ).first()
    if existing:
        raise HTTPException(400, "Submission already pending")

    sub = KYCSubmission(
        user_id=user.id,
        full_name=body.full_name[:200],
        passport_number=body.passport_number[:32],
        birth_date=body.birth_date[:16],
        address=body.address[:500],
        status="pending",
    )
    db.add(sub)

    user.kyc_status = "pending"
    user.kyc_submitted_at = utcnow()
    db.commit()
    db.refresh(sub)

    notify(db, user.id, "KYC submitted",
           "Hujjatlar qabul qilindi. 24 soat ichida tekshiriladi.",
           "info")

    return {"submission_id": sub.id, "status": "pending"}


@app.get("/api/admin/kyc/pending")
def admin_kyc_pending(admin: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    rows = db.query(KYCSubmission).filter(
        KYCSubmission.status == "pending"
    ).order_by(KYCSubmission.created_at).all()

    result = []
    for r in rows:
        user = db.get(User, r.user_id)
        result.append({
            "id": r.id,
            "user_id": r.user_id,
            "user_name": user.name if user else "?",
            "user_email": user.email if user else "?",
            "full_name": r.full_name,
            "passport_number": r.passport_number,
            "birth_date": r.birth_date,
            "address": r.address,
            "created_at": iso(r.created_at),
        })
    return result


@app.post("/api/admin/kyc/{submission_id}/approve")
def admin_kyc_approve(submission_id: int, admin: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    sub = db.get(KYCSubmission, submission_id)
    if not sub:
        raise HTTPException(404, "Not found")
    if sub.status != "pending":
        raise HTTPException(400, "Already processed")

    sub.status = "approved"
    sub.reviewed_at = utcnow()
    sub.reviewed_by = admin.id

    user = db.get(User, sub.user_id)
    if user:
        user.kyc_status = "verified"
        user.kyc_verified_at = utcnow()

    db.commit()

    notify(db, sub.user_id, "KYC approved",
           "Shaxsingiz tasdiqlandi. Endi to'liq xizmatlardan foydalanishingiz mumkin.",
           "success")

    return {"ok": True, "status": "approved"}


@app.post("/api/admin/kyc/{submission_id}/reject")
def admin_kyc_reject(submission_id: int, reason: str = Query("Hujjatlar noto'g'ri"),
                     admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    sub = db.get(KYCSubmission, submission_id)
    if not sub:
        raise HTTPException(404, "Not found")
    if sub.status != "pending":
        raise HTTPException(400, "Already processed")

    sub.status = "rejected"
    sub.rejection_reason = reason[:500]
    sub.reviewed_at = utcnow()
    sub.reviewed_by = admin.id

    user = db.get(User, sub.user_id)
    if user:
        user.kyc_status = "rejected"

    db.commit()

    notify(db, sub.user_id, "KYC rejected",
           f"Sabab: {reason}",
           "error")

    return {"ok": True, "status": "rejected"}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 28 — SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/settings")
def get_settings(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.put("/api/settings")
def update_settings(body: ProfileIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if body.email and body.email.lower() != user.email:
        new_email = validate_email(body.email)
        clash = db.query(User).filter(User.email == new_email, User.id != user.id).first()
        if clash:
            raise HTTPException(400, "Email in use")
        user.email = new_email

    if body.name:
        user.name = body.name.strip()
    if body.phone is not None:
        user.phone = body.phone.strip() or None
    if body.company is not None:
        user.company = body.company.strip()
    if body.language and body.language in ("uz", "en", "ru", "zh", "fr", "it"):
        user.language = body.language

    db.commit()
    db.refresh(user)
    return user_dict(user)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 29 — ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/admin/users")
def admin_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(desc(User.created_at)).all()
    result = []
    for u in users:
        bal = get_balance(db, u.id, "UZS")
        result.append({**user_dict(u), "balance_uzs": bal / 100})
    return result


@app.post("/api/admin/users/{uid}/toggle")
def admin_toggle_user(uid: int, admin: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "Not found")
    if u.id == admin.id:
        raise HTTPException(400, "Cannot toggle yourself")
    u.is_active = not u.is_active
    db.commit()
    return {"ok": True, "is_active": u.is_active}


@app.get("/api/admin/stats")
def admin_stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users_count = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    transfers = db.query(Transfer).count()
    intents = db.query(PaymentIntent).count()

    total_ledger = db.query(func.sum(LedgerEntry.amount_tiyin)).scalar() or 0

    return {
        "users": users_count,
        "active_users": active_users,
        "transfers": transfers,
        "intents": intents,
        "ledger_total_tiyin": int(total_ledger),
        "stripe_configured": stripe_configured(),
        "jpm_configured": jpm_configured(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 30 — EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/export/transactions.csv")
def export_transactions(user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.user_id == user.id
    ).order_by(desc(LedgerEntry.created_at)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Currency", "Type", "Direction", "Amount", "Balance After", "Description"])

    for r in rows:
        writer.writerow([
            r.created_at.isoformat() if r.created_at else "",
            r.currency,
            r.ref_type,
            r.direction,
            f"{r.amount_tiyin / 100:.2f}",
            f"{r.balance_after / 100:.2f}",
            r.description,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=foxpay-{user.id}.csv"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 31 — CURRENCIES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/currencies")
def currencies():
    return {
        "supported": SUPPORTED_CURRENCIES,
        "default": "UZS",
    }


@app.get("/api/currencies/rates")
def get_rates(db: Session = Depends(get_db)):
    result = {}
    for f in SUPPORTED_CURRENCIES:
        result[f] = {}
        for t in SUPPORTED_CURRENCIES:
            if f != t:
                result[f][t] = get_rate(f, t, db)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 32 — INDEX & CATCH-ALL
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index():
    idx_path = BASE_DIR / "index.html"
    if idx_path.exists():
        return FileResponse(idx_path, media_type="text/html")
    return HTMLResponse(build_landing_html())


@app.get("/{path:path}", response_class=HTMLResponse)
def catch_all(path: str):
    if path.startswith(("api/", "docs", "redoc", "openapi.json")):
        raise HTTPException(404, "Not found")
    idx_path = BASE_DIR / "index.html"
    if idx_path.exists():
        return FileResponse(idx_path, media_type="text/html")
    return HTMLResponse(build_landing_html())


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 33 — ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"detail": "Endpoint not found"})
    idx = BASE_DIR / "index.html"
    if idx.exists():
        return FileResponse(idx)
    return HTMLResponse(build_landing_html())


@app.exception_handler(500)
async def server_error(request: Request, exc):
    log.exception(f"500 on {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal error"})


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 34 — STARTUP
# ═══════════════════════════════════════════════════════════════════════════════

def ensure_admin():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if not existing:
            admin = User(
                email=ADMIN_EMAIL,
                name=ADMIN_NAME,
                password_hash=hash_password(ADMIN_PASSWORD),
                is_admin=True,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            ensure_wallet(db, admin.id, "UZS")
            log.info(f"Admin created: {ADMIN_EMAIL}")
        elif not existing.is_admin:
            existing.is_admin = True
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
async def startup():
    ensure_admin()
    log.info("=" * 70)
    log.info(f"🦊 {SITE_NAME} v5.0.0 starting")
    log.info(f"   Python:  {sys.version.split()[0]}")
    log.info(f"   DB:      {DB_PATH}")
    log.info(f"   Port:    {PORT}")
    log.info(f"   Dev:     {DEV_MODE}")
    log.info(f"   Stripe:  {'✓' if stripe_configured() else '✗'}")
    log.info(f"   JPM:     {'✓' if jpm_configured() else '✗'}")
    log.info("=" * 70)

    try:
        db = SessionLocal()
        n = db.query(User).count()
        log.info(f"   Users: {n}")
        db.close()
    except Exception as e:
        log.error(f"   Startup check failed: {e}")


@app.on_event("shutdown")
async def shutdown():
    log.info("Shutting down")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 35 — ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True,
    )
