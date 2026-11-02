"""
═══════════════════════════════════════════════════════════════════════════
FOXPAY — Complete Production Backend v3.0.0
═══════════════════════════════════════════════════════════════════════════

Endpoints:
  Auth:        /api/auth/{register,login,refresh,logout,me,password}
  Wallet:      /api/wallet{,/ledger,/deposit,/withdraw}
  P2P:         /api/p2p/transfers{/:id,/cancel}
  Intents:     /api/pay/intents{/:id/confirm,/cancel}
  API Keys:    /api/keys{/:id/rotate}
  Webhooks:    /api/hooks{/:id/test}
  Merchants:   /api/merchants{/:id}
  Subscriptions: /api/subscriptions{/plans/:id/subscribe}
  Notifications: /api/notifications
  Analytics:   /api/analytics/{summary,daily,weekly,methods}
  Settings:    /api/settings{,/password}
  Admin:       /api/admin/{users,stats}
  Export:      /api/export/transactions.csv
  SEO:         /robots.txt, /sitemap.xml, /google*.html, /manifest.webmanifest
  Health:      /api/health, /api/debug, /api/stats

Render:
  Start: uvicorn main:app --host 0.0.0.0 --port $PORT
  
Environment:
  FOXPAY_SECRET  — JWT signing key
  FOXPAY_DB      — SQLite path (default /tmp/foxpay_v3.db on Render)
  FOXPAY_DEV     — "1" enables dev tools
  SITE_URL       — canonical URL
═══════════════════════════════════════════════════════════════════════════
"""

# ═══════════════════════════════════════════════════════════════════════
# 1. IMPORTS
# ═══════════════════════════════════════════════════════════════════════

import os
import re
import sys
import json
import time
import hmac
import csv
import io
import html
import uuid
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict

import jwt
from fastapi import (
    FastAPI, Depends, HTTPException, Header, Request, Response,
    status, Query, BackgroundTasks, Path as FPath,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    FileResponse, JSONResponse, PlainTextResponse, HTMLResponse,
    StreamingResponse, Response as FastResponse,
)
from pydantic import BaseModel, Field, EmailStr, field_validator
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    BigInteger, ForeignKey, Text, Index, Float, text, func, or_, and_, desc,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError


# ═══════════════════════════════════════════════════════════════════════
# 2. CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

DB_VERSION = "v3"  # bump when schema changes
BASE_DIR = Path(__file__).resolve().parent

SITE_URL = os.getenv("SITE_URL", "https://foxpay.uz")
SITE_NAME = "FoxPay"
SITE_TAGLINE = "To'lov bir zumda"
SITE_DESCRIPTION = (
    "O'zbekistonda onlayn to'lovlar, P2P o'tkazmalar va payment API. "
    "Freelancerlar va biznes uchun 1.5% komissiya. Bepul boshlash."
)
CONTACT_EMAIL = "hello@foxpay.uz"

PORT = int(os.getenv("PORT", "9988"))
HOST = os.getenv("HOST", "0.0.0.0")
SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
TOKEN_EXPIRE_DAYS = 7
REFRESH_EXPIRE_DAYS = 30
DEV_MODE = os.getenv("FOXPAY_DEV", "1") == "1"
RENDER_MODE = os.getenv("RENDER") is not None

FEE_RATE_BPS = 150  # 1.5% = 150 basis points
MIN_TRANSFER_TIYIN = 10000  # 100 UZS
MAX_TRANSFER_TIYIN = 100_000_000_000  # 1B UZS


# ═══════════════════════════════════════════════════════════════════════
# 3. LOGGING
# ═══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("foxpay")


# ═══════════════════════════════════════════════════════════════════════
# 4. DATABASE
# ═══════════════════════════════════════════════════════════════════════

def _resolve_db_path() -> str:
    """Find writable DB path. Uses versioned filename to avoid schema conflicts."""
    candidates = []

    if os.getenv("FOXPAY_DB"):
        candidates.append(os.getenv("FOXPAY_DB"))
    else:
        candidates.append(str(BASE_DIR / f"foxpay_{DB_VERSION}.db"))
        if RENDER_MODE:
            candidates.append(f"/tmp/foxpay_{DB_VERSION}.db")
        candidates.append(f"/tmp/foxpay_{DB_VERSION}.db")

    for path in candidates:
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            probe = p.parent / f".write_{secrets.token_hex(4)}"
            probe.write_text("x")
            probe.unlink()
            return path
        except Exception:
            continue
    return f"/tmp/foxpay_{DB_VERSION}.db"


DB_PATH = _resolve_db_path()
logger.info(f"Database: {DB_PATH}")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow() -> datetime:
    """Naive UTC datetime for DB storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialize datetime to ISO string with Z suffix."""
    return dt.isoformat() + "Z" if dt else None


def safe_int(v: Any, default: int = 0) -> int:
    """Safely convert to int."""
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════
# 5. MODELS
# ═══════════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False, default="")
    password_hash = Column(String(255), nullable=False, default="")
    phone = Column(String(32), index=True, nullable=True)
    company = Column(String(200), default="")
    role = Column(String(16), default="user")  # user | merchant | admin
    is_active = Column(Boolean, default=True, nullable=False)
    email_verified = Column(Boolean, default=False)
    language = Column(String(8), default="uz")
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    currency = Column(String(8), default="UZS", nullable=False)
    balance_tiyin = Column(BigInteger, default=0, nullable=False)
    frozen_tiyin = Column(BigInteger, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=False)
    direction = Column(String(8), nullable=False)  # credit | debit
    amount_tiyin = Column(BigInteger, nullable=False)
    balance_after = Column(BigInteger, default=0)
    ref_type = Column(String(32), default="", index=True)
    ref_id = Column(String(64), default="", index=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


Index("ix_ledger_user_created", LedgerEntry.user_id, LedgerEntry.created_at.desc())


class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    transfer_id = Column(String(32), unique=True, index=True, nullable=False)
    from_user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    to_user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    currency = Column(String(8), default="UZS")
    status = Column(String(16), default="succeeded", index=True)  # pending | succeeded | failed | cancelled
    note = Column(String(255), default="")
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)


Index("ix_transfer_from_created", Transfer.from_user_id, Transfer.created_at.desc())
Index("ix_transfer_to_created", Transfer.to_user_id, Transfer.created_at.desc())


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    intent_id = Column(String(32), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    net_tiyin = Column(BigInteger, default=0)
    currency = Column(String(8), default="UZS")
    status = Column(String(20), default="requires_payment", index=True)
    description = Column(String(255), default="")
    customer_email = Column(String(200), nullable=True)
    customer_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    prefix = Column(String(20), index=True, nullable=False)
    key_hash = Column(String(64), nullable=False)
    label = Column(String(64), default="default")
    scopes = Column(String(200), default="read,write,p2p,collect")
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    url = Column(String(500), nullable=False)
    secret = Column(String(100), nullable=False)
    events = Column(String(255), default="*")
    is_active = Column(Boolean, default=True)
    failure_count = Column(Integer, default=0)
    last_success_at = Column(DateTime, nullable=True)
    last_failure_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Merchant(Base):
    __tablename__ = "merchants"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    name = Column(String(120), nullable=False)
    category = Column(String(64), default="general")
    status = Column(String(16), default="active")
    volume_tiyin = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    plan_id = Column(String(32), nullable=False)
    plan_name = Column(String(64), default="")
    amount_tiyin = Column(BigInteger, default=0)
    status = Column(String(20), default="active")  # active | cancelled | expired
    started_at = Column(DateTime, default=utcnow, nullable=False)
    next_billing_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    title = Column(String(200), nullable=False)
    message = Column(Text, default="")
    type = Column(String(32), default="info")  # info | success | warning | error
    is_read = Column(Boolean, default=False, index=True)
    link = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=True)
    action = Column(String(64), index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


Base.metadata.create_all(bind=engine)
logger.info("Database tables created")


# ═══════════════════════════════════════════════════════════════════════
# 6. CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SUBSCRIPTION_PLANS = {
    "start": {
        "id": "start",
        "name": "Start",
        "amount_tiyin": 0,
        "fee_bps": 180,
        "features": ["Payment link", "Email support", "5 API calls/min"],
    },
    "business": {
        "id": "business",
        "name": "Business",
        "amount_tiyin": 4_900_000,  # 49,000 UZS
        "fee_bps": 150,
        "features": ["All Start", "REST API", "Webhooks", "Priority support", "100 API calls/min"],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise",
        "amount_tiyin": 49_000_000,  # 490,000 UZS
        "fee_bps": 100,
        "features": ["All Business", "SLA 99.99%", "Dedicated manager", "Unlimited API"],
    },
}

MERCHANT_CATEGORIES = [
    "general", "retail", "food", "books", "electronics",
    "tourism", "textile", "services", "digital", "other",
]

BOT_PATTERNS = [
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebookexternalhit", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "applebot", "semrushbot", "ahrefsbot",
]


# ═══════════════════════════════════════════════════════════════════════
# 7. SECURITY
# ═══════════════════════════════════════════════════════════════════════

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


def make_token(user_id: int, token_type: str = "access") -> str:
    days = TOKEN_EXPIRE_DAYS if token_type == "access" else REFRESH_EXPIRE_DAYS
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=days),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def decode_token(token: str, expected_type: str = "access") -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        if payload.get("type") != expected_type:
            raise HTTPException(401, "Invalid token type")
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    except (KeyError, ValueError):
        raise HTTPException(401, "Malformed token")


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization header")

    token = authorization[7:].strip()

    if token.startswith("fox_live_"):
        # API key auth
        prefix = token[:20]
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        api_key = db.query(ApiKey).filter(
            ApiKey.prefix == prefix,
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        ).first()
        if not api_key:
            raise HTTPException(401, "Invalid API key")
        api_key.last_used_at = utcnow()
        db.commit()
        user = db.get(User, api_key.user_id)
    else:
        user_id = decode_token(token, "access")
        user = db.get(User, user_id)

    if not user:
        raise HTTPException(401, "User not found")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def hash_api_key(full: str) -> str:
    return hashlib.sha256(full.encode()).hexdigest()


def generate_api_key() -> Tuple[str, str, str]:
    full = "fox_live_" + secrets.token_hex(24)
    return full, full[:20], hash_api_key(full)


# ═══════════════════════════════════════════════════════════════════════
# 8. RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════

_rate_store: Dict[str, List[float]] = defaultdict(list)


def rate_limit(key: str, limit: int, window: int = 60) -> None:
    now = time.time()
    hits = _rate_store[key]
    # Purge old
    _rate_store[key] = [t for t in hits if t > now - window]
    if len(_rate_store[key]) >= limit:
        raise HTTPException(429, "Too many requests. Try again later.")
    _rate_store[key].append(now)


def _cleanup_rate_store(max_age: int = 3600) -> None:
    cutoff = time.time() - max_age
    for k in list(_rate_store.keys()):
        _rate_store[k] = [t for t in _rate_store[k] if t > cutoff]
        if not _rate_store[k]:
            del _rate_store[k]


# ═══════════════════════════════════════════════════════════════════════
# 9. BOT DETECTION
# ═══════════════════════════════════════════════════════════════════════

def is_bot(request: Request) -> bool:
    ua = (request.headers.get("user-agent") or "").lower()
    if not ua:
        return False
    return any(bot in ua for bot in BOT_PATTERNS)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ═══════════════════════════════════════════════════════════════════════
# 10. UTILITIES
# ═══════════════════════════════════════════════════════════════════════

def get_balance(db: Session, user_id: int) -> int:
    """Compute balance from ledger (source of truth)."""
    result = db.query(
        func.coalesce(
            func.sum(
                func.case(
                    (LedgerEntry.direction == "credit", LedgerEntry.amount_tiyin),
                    else_=-LedgerEntry.amount_tiyin,
                )
            ),
            0,
        )
    ).filter(LedgerEntry.user_id == user_id).scalar()
    return int(result or 0)


def get_balance_simple(db: Session, user_id: int) -> int:
    """Simpler version - fetch all and sum in Python (fine for SQLite)."""
    rows = db.query(LedgerEntry.direction, LedgerEntry.amount_tiyin).filter(
        LedgerEntry.user_id == user_id
    ).all()
    credits = sum(r[1] for r in rows if r[0] == "credit")
    debits = sum(r[1] for r in rows if r[0] == "debit")
    return credits - debits


def ensure_wallet(db: Session, user_id: int) -> Wallet:
    w = db.query(Wallet).filter(Wallet.user_id == user_id).first()
    if not w:
        w = Wallet(user_id=user_id, balance_tiyin=0, currency="UZS")
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
) -> LedgerEntry:
    if direction not in ("credit", "debit"):
        raise ValueError("Invalid direction")
    if amount <= 0:
        raise ValueError("Amount must be positive")

    ensure_wallet(db, user_id)

    # Compute new balance
    current = get_balance_simple(db, user_id)
    new_balance = current + (amount if direction == "credit" else -amount)

    entry = LedgerEntry(
        user_id=user_id,
        direction=direction,
        amount_tiyin=amount,
        balance_after=new_balance,
        ref_type=ref_type,
        ref_id=ref_id,
        description=description,
    )
    db.add(entry)

    wallet = db.query(Wallet).filter(Wallet.user_id == user_id).first()
    if wallet:
        wallet.balance_tiyin = new_balance

    return entry


def calc_fee(amount: int, rate_bps: int = FEE_RATE_BPS) -> int:
    return amount * rate_bps // 10_000


def create_audit(
    db: Session,
    user_id: Optional[int],
    action: str,
    request: Optional[Request] = None,
    details: str = "",
) -> None:
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
        logger.warning(f"Audit log failed: {e}")


def create_notification(
    db: Session,
    user_id: int,
    title: str,
    message: str = "",
    type: str = "info",
    link: Optional[str] = None,
) -> None:
    try:
        db.add(Notification(
            user_id=user_id,
            title=title[:200],
            message=message,
            type=type,
            link=link,
        ))
        db.commit()
    except Exception as e:
        logger.warning(f"Notification failed: {e}")


def user_dict(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "phone": user.phone,
        "company": user.company,
        "role": user.role,
        "language": user.language,
        "created_at": iso(user.created_at),
    }


def wallet_dict(db: Session, user: User) -> Dict[str, Any]:
    bal = get_balance_simple(db, user.id)
    w = ensure_wallet(db, user.id)
    return {
        "currency": w.currency,
        "balance_tiyin": bal,
        "balance_uzs": bal / 100,
        "frozen_tiyin": w.frozen_tiyin or 0,
    }


def transfer_dict(t: Transfer) -> Dict[str, Any]:
    return {
        "id": t.transfer_id,
        "from_user_id": t.from_user_id,
        "to_user_id": t.to_user_id,
        "amount_tiyin": t.amount_tiyin,
        "amount_uzs": t.amount_tiyin / 100,
        "fee_tiyin": t.fee_tiyin,
        "fee_uzs": t.fee_tiyin / 100,
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
        "amount_uzs": i.amount_tiyin / 100,
        "fee_tiyin": i.fee_tiyin,
        "net_tiyin": i.net_tiyin,
        "currency": i.currency,
        "status": i.status,
        "description": i.description,
        "customer_email": i.customer_email,
        "customer_name": i.customer_name,
        "created_at": iso(i.created_at),
        "completed_at": iso(i.completed_at),
    }


# ═══════════════════════════════════════════════════════════════════════
# 11. APP & MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="FoxPay API",
    version="3.0.0",
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
        logger.exception(f"Unhandled error on {request.url.path}: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

    duration = (time.time() - start) * 1000

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Request-ID"] = request_id

    # SEO headers
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/docs") or path.startswith("/redoc"):
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
    elif path == "/":
        response.headers["X-Robots-Tag"] = "index, follow, max-image-preview:large"
        response.headers["Link"] = f'<{SITE_URL}/>; rel="canonical"'

    # Cache headers
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif path in ("/robots.txt", "/sitemap.xml"):
        response.headers["Cache-Control"] = "public, max-age=3600"

    # Log slow requests
    if duration > 1000:
        logger.warning(f"Slow request: {request.method} {path} took {duration:.0f}ms")

    return response


# ═══════════════════════════════════════════════════════════════════════
# 12. LANDING PAGE (inline HTML for SEO)
# ═══════════════════════════════════════════════════════════════════════

def build_landing_html() -> str:
    """Generate SEO-optimized landing page."""
    today = utcnow().strftime("%Y-%m-%d")
    year = utcnow().year

    faq_items = [
        ("FoxPay nima?", "FoxPay — O'zbekiston uchun onlayn to'lov platformasi. Freelancerlar, kichik biznes va merchantlar uchun P2P o'tkazmalar, payment API va webhooks."),
        ("Komissiya qancha?", "Start rejasida 1.8%, Business rejasida 1.5%, Enterprise uchun individual komissiya. Oylik to'lov yo'q — faqat muvaffaqiyatli tranzaksiyadan komissiya olinadi."),
        ("Qaysi kartalar qo'llab-quvvatlanadi?", "Uzcard, Humo, xalqaro Visa va Mastercard. Shuningdek Payme, Click va bank o'tkazmalari."),
        ("Pul qancha vaqtda tushadi?", "P2P o'tkazmalar real vaqtda (bir zumda). Merchant to'lovlari 1 ish kuni ichida bank kartasiga tushadi."),
        ("API bormi?", "Ha, REST API, webhook va tayyor SDK. 15 daqiqada integratsiya qilish mumkin. Batafsil /docs da."),
        ("Xavfsizlik qanday?", "Double-entry ledger, PCI DSS standartlari, 2FA, HMAC-signed webhooks va har bir tranzaksiya uchun to'liq audit log."),
    ]

    faq_json = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": q,
                "acceptedAnswer": {"@type": "Answer", "text": a},
            }
            for q, a in faq_items
        ],
    }

    org_json = {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": SITE_NAME,
        "url": SITE_URL,
        "logo": f"{SITE_URL}/logo.png",
        "description": SITE_DESCRIPTION,
        "email": CONTACT_EMAIL,
        "address": {
            "@type": "PostalAddress",
            "addressLocality": "Tashkent",
            "addressCountry": "UZ",
        },
    }

    website_json = {
        "@context": "https://schema.org",
        "@type": "WebSite",
        "url": SITE_URL,
        "name": SITE_NAME,
        "inLanguage": "uz",
    }

    app_json = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": SITE_NAME,
        "applicationCategory": "FinanceApplication",
        "operatingSystem": "Web",
        "url": SITE_URL,
        "offers": {
            "@type": "Offer",
            "price": "0",
            "priceCurrency": "UZS",
            "description": "Bepul boshlash. Faqat muvaffaqiyatli tranzaksiyadan 1.5% komissiya.",
        },
    }

    faq_html = "".join(
        f'<details class="faq-item">'
        f'<summary class="faq-q">{html.escape(q)}</summary>'
        f'<div class="faq-a">{html.escape(a)}</div>'
        f'</details>'
        for q, a in faq_items
    )

    plans_html = ""
    for plan_id, plan in SUBSCRIPTION_PLANS.items():
        featured = ' class="price-card featured"' if plan_id == "business" else ' class="price-card"'
        badge = '<div class="price-badge">Ommabop</div>' if plan_id == "business" else ''
        fee_pct = plan["fee_bps"] / 100
        amount = plan["amount_tiyin"] / 100
        price_display = "Bepul" if amount == 0 else f"{amount:,.0f} UZS/oy"
        features_html = "".join(f"<li>{html.escape(f)}</li>" for f in plan["features"])
        btn_class = "btn btn-primary" if plan_id == "business" else "btn btn-outline"

        plans_html += f"""
<div{featured}>
{badge}
<div class="price-name">{html.escape(plan['name'])}</div>
<div class="price-amount">{fee_pct}%<span> / tx</span></div>
<div class="price-desc">{price_display}</div>
<ul class="price-list">{features_html}</ul>
<a href="/#/register" class="{btn_class}" style="width:100%;text-align:center">Boshlash</a>
</div>"""

    return f'''<!DOCTYPE html>
<html lang="uz" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_NAME} — O'zbekistonda onlayn to'lovlar, P2P o'tkazmalar va API</title>
<meta name="description" content="{SITE_DESCRIPTION}">
<meta name="keywords" content="FoxPay, to'lov tizimi, onlayn to'lov, P2P o'tkazma, payment API, Uzcard, Humo, Payme, Click, fintech O'zbekiston">
<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">
<meta name="author" content="{SITE_NAME}">
<meta name="theme-color" content="#FF6B00">
<meta name="language" content="Uzbek">
<meta name="geo.region" content="UZ">
<meta name="geo.placename" content="Tashkent">
<link rel="canonical" href="{SITE_URL}/">
<link rel="alternate" hreflang="uz" href="{SITE_URL}/">
<link rel="alternate" hreflang="x-default" href="{SITE_URL}/">
<meta property="og:type" content="website">
<meta property="og:site_name" content="{SITE_NAME}">
<meta property="og:locale" content="uz_UZ">
<meta property="og:title" content="{SITE_NAME} — {SITE_TAGLINE}">
<meta property="og:description" content="{SITE_DESCRIPTION}">
<meta property="og:url" content="{SITE_URL}/">
<meta property="og:image" content="{SITE_URL}/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{SITE_NAME} — {SITE_TAGLINE}">
<meta name="twitter:description" content="{SITE_DESCRIPTION}">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='20' fill='%230B1120'/%3E%3Cpath d='M30 30l20 20 20-20v30a20 20 0 0 1-40 0V30z' fill='%23FF6B00'/%3E%3C/svg%3E">
<script type="application/ld+json">{json.dumps(org_json)}</script>
<script type="application/ld+json">{json.dumps(website_json)}</script>
<script type="application/ld+json">{json.dumps(app_json)}</script>
<script type="application/ld+json">{json.dumps(faq_json)}</script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0B1120;color:#F8FAFC;line-height:1.5;font-size:15px;-webkit-font-smoothing:antialiased}}
a{{color:#FF6B00;text-decoration:none}}
h1,h2,h3{{line-height:1.2;letter-spacing:-.02em}}
.container{{max-width:1100px;margin:0 auto;padding:0 24px}}
.header{{border-bottom:1px solid #1E293B;padding:18px 0;position:sticky;top:0;background:rgba(11,17,32,.9);backdrop-filter:blur(12px);z-index:100}}
.nav{{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}}
.logo{{font-weight:800;font-size:20px;letter-spacing:-.02em}}
.logo span{{color:#00F2FE}}
.nav-links{{display:flex;gap:24px;flex-wrap:wrap}}
.nav-links a{{color:#94A3B8;font-size:14px;font-weight:500}}
.nav-links a:hover{{color:#F8FAFC}}
.btn{{display:inline-block;padding:12px 24px;border-radius:10px;font-weight:600;font-size:14px;transition:.15s;cursor:pointer;border:0;text-align:center}}
.btn-primary{{background:linear-gradient(135deg,#FF6B00,#E64A00);color:#fff;box-shadow:0 4px 14px rgba(255,107,0,.3)}}
.btn-primary:hover{{box-shadow:0 6px 24px rgba(255,107,0,.45)}}
.btn-outline{{background:transparent;color:#F8FAFC;border:1px solid #1E293B}}
.btn-outline:hover{{background:rgba(255,255,255,.04)}}
.hero{{padding:80px 0 100px}}
.hero-grid{{display:grid;grid-template-columns:1.1fr .9fr;gap:60px;align-items:center}}
.eyebrow{{display:inline-block;padding:6px 14px;border-radius:99px;background:rgba(255,107,0,.1);color:#FF6B00;font-size:12px;font-weight:600;margin-bottom:24px;border:1px solid rgba(255,107,0,.2)}}
h1{{font-size:54px;font-weight:900;margin-bottom:22px}}
h1 .grad{{background:linear-gradient(135deg,#FF6B00,#E64A00);-webkit-background-clip:text;background-clip:text;color:transparent}}
.lead{{font-size:17px;color:#94A3B8;margin-bottom:32px;max-width:540px;line-height:1.65}}
.cta-group{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:40px}}
.stats{{display:flex;gap:40px;flex-wrap:wrap}}
.stat-num{{font-size:26px;font-weight:800}}
.stat-lbl{{font-size:12px;color:#94A3B8;margin-top:4px}}
.hero-card{{background:#0F172A;border:1px solid #1E293B;border-radius:18px;padding:26px;box-shadow:0 20px 60px rgba(0,0,0,.4)}}
.hero-card-label{{font-size:12px;color:#94A3B8;margin-bottom:6px}}
.hero-card-amt{{font-size:34px;font-weight:800;letter-spacing:-.02em}}
.section{{padding:80px 0}}
.section-head{{text-align:center;max-width:640px;margin:0 auto 48px}}
.eyebrow-sm{{font-size:12px;font-weight:700;color:#FF6B00;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}}
h2{{font-size:42px;font-weight:800;margin-bottom:16px}}
.section-head p{{font-size:17px;color:#94A3B8}}
.grid-3{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}}
.card{{background:#0F172A;border:1px solid #1E293B;border-radius:14px;padding:26px;transition:.2s}}
.card:hover{{transform:translateY(-3px);box-shadow:0 20px 60px rgba(0,0,0,.4);border-color:#FF6B00}}
.card-icon{{font-size:24px;margin-bottom:16px}}
.card h3{{font-size:16px;font-weight:700;margin-bottom:10px}}
.card p{{font-size:14px;color:#94A3B8;line-height:1.65}}
.price-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}}
.price-card{{background:#0F172A;border:1px solid #1E293B;border-radius:14px;padding:30px;position:relative}}
.price-card.featured{{border:2px solid #FF6B00;box-shadow:0 20px 60px rgba(255,107,0,.2)}}
.price-badge{{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,#FF6B00,#E64A00);color:#fff;padding:4px 16px;border-radius:99px;font-size:11px;font-weight:700}}
.price-name{{font-size:13px;font-weight:600;color:#94A3B8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}}
.price-amount{{font-size:34px;font-weight:800;margin-bottom:8px}}
.price-amount span{{font-size:14px;color:#94A3B8;font-weight:500}}
.price-desc{{font-size:13px;color:#94A3B8;margin-bottom:22px;min-height:40px}}
.price-list{{list-style:none;margin-bottom:24px}}
.price-list li{{font-size:14px;color:#94A3B8;padding:8px 0;padding-left:24px;position:relative}}
.price-list li::before{{content:'✓';color:#10B981;font-weight:700;position:absolute;left:0}}
.faq-list{{max-width:760px;margin:0 auto}}
.faq-item{{background:#0F172A;border:1px solid #1E293B;border-radius:14px;margin-bottom:12px;overflow:hidden}}
.faq-q{{padding:18px 22px;cursor:pointer;font-size:15px;font-weight:600;list-style:none;display:flex;justify-content:space-between}}
.faq-q::-webkit-details-marker{{display:none}}
.faq-q::after{{content:'+';color:#94A3B8;font-size:22px;font-weight:400}}
.faq-item[open] .faq-q::after{{transform:rotate(45deg)}}
.faq-a{{padding:0 22px 20px;font-size:14px;color:#94A3B8;line-height:1.7}}
.cta-box{{background:linear-gradient(135deg,#FF6B00,#E64A00);border-radius:18px;padding:60px 40px;text-align:center;color:#fff;box-shadow:0 24px 70px rgba(255,107,0,.3)}}
.cta-box h2{{font-size:38px;margin-bottom:16px}}
.cta-box p{{font-size:16px;opacity:.92;margin-bottom:28px;max-width:520px;margin-left:auto;margin-right:auto}}
.cta-box .btn{{background:#fff;color:#E64A00}}
.footer{{border-top:1px solid #1E293B;padding:60px 0 32px;margin-top:80px}}
.footer-grid{{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:40px;margin-bottom:40px}}
.footer-col h4{{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px}}
.footer-col a,.footer-col p{{display:block;font-size:13px;color:#94A3B8;padding:5px 0;transition:.15s}}
.footer-col a:hover{{color:#F8FAFC}}
.footer-bottom{{padding-top:24px;border-top:1px solid #1E293B;font-size:12px;color:#94A3B8;display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px}}
@media(max-width:768px){{
h1{{font-size:34px}}
h2{{font-size:26px}}
.hero-grid,.grid-3,.price-grid{{grid-template-columns:1fr}}
.hero-card{{display:none}}
.stats{{gap:20px}}
.footer-grid{{grid-template-columns:1fr 1fr}}
}}
</style>
</head>
<body>

<header class="header">
<div class="container nav">
<a href="/" class="logo">FOX<span>PAY</span></a>
<nav class="nav-links" aria-label="Asosiy navigatsiya">
<a href="#features">Imkoniyatlar</a>
<a href="#pricing">Narxlar</a>
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
<div class="container hero-grid">
<div>
<span class="eyebrow">⚡ O'zbekistonda #1 to'lovlar platformasi</span>
<h1>To'lovni <span class="grad">bir zumda</span> qabul qiling.</h1>
<p class="lead">FoxPay — freelancerlar, onlayn do'konlar va kichik biznes uchun tez, ishonchli va arzon to'lov infratuzilmasi. P2P o'tkazmalar, REST API va webhooks. Atigi 1.5% komissiya.</p>
<div class="cta-group">
<a href="/#/register" class="btn btn-primary">Bepul boshlash →</a>
<a href="#features" class="btn btn-outline">Batafsil</a>
</div>
<div class="stats">
<div><div class="stat-num">12,400+</div><div class="stat-lbl">Faol merchant</div></div>
<div><div class="stat-num">₣ 4.2 mlrd</div><div class="stat-lbl">Oylik aylanma</div></div>
<div><div class="stat-num">99.98%</div><div class="stat-lbl">Uptime SLA</div></div>
</div>
</div>
<aside class="hero-card" aria-label="Bugungi tushum">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
<div><div class="hero-card-label">Bugungi tushum</div><div class="hero-card-amt">₣ 8,240,000</div></div>
<span style="background:rgba(16,185,129,.12);color:#10B981;padding:4px 10px;border-radius:99px;font-size:11px;font-weight:700">+18.2%</span>
</div>
<div style="display:flex;align-items:flex-end;gap:6px;height:120px">
<div style="flex:1;background:rgba(255,107,0,.3);border-radius:4px;height:40%"></div>
<div style="flex:1;background:rgba(255,107,0,.4);border-radius:4px;height:55%"></div>
<div style="flex:1;background:rgba(255,107,0,.5);border-radius:4px;height:48%"></div>
<div style="flex:1;background:rgba(255,107,0,.6);border-radius:4px;height:70%"></div>
<div style="flex:1;background:rgba(255,107,0,.75);border-radius:4px;height:85%"></div>
<div style="flex:1;background:#FF6B00;border-radius:4px;height:100%"></div>
</div>
</aside>
</div>
</section>

<section class="section" id="features">
<div class="container">
<div class="section-head">
<div class="eyebrow-sm">Imkoniyatlar</div>
<h2>Hammasi bitta joyda</h2>
<p>To'lov qabul qilishdan API integratsiyagacha — biznesingiz uchun zarur bo'lgan barcha vositalar</p>
</div>
<div class="grid-3">
<article class="card"><div class="card-icon">⚡</div><h3>Tez to'lov</h3><p>Uzcard, Humo, Payme, Click — barchasi bir tugmada. O'rtacha tranzaksiya vaqti 1.2 soniya.</p></article>
<article class="card"><div class="card-icon">🛡️</div><h3>Xavfsiz</h3><p>Double-entry ledger, PCI DSS standartlari, 2FA va har bir tranzaksiya uchun to'liq audit log.</p></article>
<article class="card"><div class="card-icon">💻</div><h3>Oson integratsiya</h3><p>REST API, webhook va tayyor SDK. 15 daqiqada to'lov qabul qilishni boshlang.</p></article>
<article class="card"><div class="card-icon">💸</div><h3>P2P o'tkazma</h3><p>Telefon yoki email orqali bir zumda pul o'tkazing. Komissiya faqat 1.5%.</p></article>
<article class="card"><div class="card-icon">📊</div><h3>Analitika</h3><p>Real vaqtdagi dashboard, KPI ko'rsatkichlar va avtomatik hisobotlar.</p></article>
<article class="card"><div class="card-icon">🌍</div><h3>Xalqaro</h3><p>SWIFT va SEPA tarmoqlari orqali 40+ valyutada pul qabul qiling va yuboring.</p></article>
</div>
</div>
</section>

<section class="section" id="pricing">
<div class="container">
<div class="section-head">
<div class="eyebrow-sm">Narxlar</div>
<h2>Halol va shaffof narxlar</h2>
<p>Yashirin to'lovlar yo'q. Faqat muvaffaqiyatli tranzaksiyadan komissiya</p>
</div>
<div class="price-grid">{plans_html}
</div>
</div>
</section>

<section class="section" id="faq">
<div class="container">
<div class="section-head">
<div class="eyebrow-sm">FAQ</div>
<h2>Ko'p beriladigan savollar</h2>
</div>
<div class="faq-list">{faq_html}</div>
</div>
</section>

<section class="section">
<div class="container">
<div class="cta-box">
<h2>Bugun birinchi to'lovni qabul qiling</h2>
<p>Ro'yxatdan o'tish bepul. Karta talab qilinmaydi. 5 daqiqada boshlang.</p>
<a href="/#/register" class="btn">Bepul boshlash →</a>
</div>
</div>
</section>

</main>

<footer class="footer">
<div class="container">
<div class="footer-grid">
<div class="footer-col">
<div class="logo" style="margin-bottom:12px">FOX<span>PAY</span></div>
<p style="max-width:280px">{SITE_DESCRIPTION}</p>
</div>
<div class="footer-col">
<h4>Mahsulot</h4>
<a href="#features">Imkoniyatlar</a>
<a href="#pricing">Narxlar</a>
<a href="/docs">API Docs</a>
<a href="/#/register">Ro'yxatdan o'tish</a>
</div>
<div class="footer-col">
<h4>Kompaniya</h4>
<a href="#faq">FAQ</a>
<a href="mailto:{CONTACT_EMAIL}">Bog'lanish</a>
</div>
<div class="footer-col">
<h4>Huquqiy</h4>
<a href="/privacy">Maxfiylik</a>
<a href="/terms">Shartlar</a>
<a href="/security">Xavfsizlik</a>
</div>
</div>
<div class="footer-bottom">
<span>© {year} {SITE_NAME} Inc. Barcha huquqlar himoyalangan.</span>
<span>Toshkent, O'zbekiston · {today}</span>
</div>
</div>
</footer>

</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════════
# 13. STATIC / SEO ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return f"""User-agent: *
Allow: /
Disallow: /api/
Disallow: /docs
Disallow: /redoc
Disallow: /openapi.json

User-agent: Googlebot
Allow: /
Disallow: /api/

User-agent: Bingbot
Allow: /
Disallow: /api/

Sitemap: {SITE_URL}/sitemap.xml
"""


@app.get("/sitemap.xml", response_class=FastResponse)
def sitemap_xml():
    today = utcnow().strftime("%Y-%m-%d")
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url>
    <loc>{SITE_URL}/</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
</url>
<url>
    <loc>{SITE_URL}/#features</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
</url>
<url>
    <loc>{SITE_URL}/#pricing</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
</url>
<url>
    <loc>{SITE_URL}/#faq</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
</url>
<url>
    <loc>{SITE_URL}/docs</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
</url>
</urlset>'''
    return FastResponse(content=xml, media_type="application/xml")


@app.get("/google{token}.html", response_class=PlainTextResponse)
def google_verification(token: str):
    """Google Search Console verification. Handles any google*.html path."""
    if not re.match(r"^[a-zA-Z0-9_-]{4,64}$", token):
        raise HTTPException(404, "Not found")

    fname = f"google{token}.html"

    # Real file check first
    path = BASE_DIR / fname
    if path.exists():
        return PlainTextResponse(
            f"google-site-verification: {fname}",
            media_type="text/html",
        )

    logger.info(f"Google verification (dynamic): {fname}")
    return PlainTextResponse(
        f"google-site-verification: {fname}",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/manifest.webmanifest")
def manifest():
    return JSONResponse(
        {
            "name": f"{SITE_NAME} — Payment Platform",
            "short_name": SITE_NAME,
            "description": SITE_DESCRIPTION,
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0B1120",
            "theme_color": "#FF6B00",
            "lang": "uz",
        },
        media_type="application/manifest+json",
    )


@app.get("/favicon.ico")
def favicon():
    """Redirect to inline SVG favicon."""
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="20" fill="#0B1120"/><path d="M30 30l20 20 20-20v30a20 20 0 0 1-40 0V30z" fill="#FF6B00"/></svg>'
    return FastResponse(content=svg, media_type="image/svg+xml")


# ═══════════════════════════════════════════════════════════════════════
# 14. HEALTH & DEBUG
# ═══════════════════════════════════════════════════════════════════════

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
        logger.error(f"Health DB error: {e}")

    return {
        "ok": True,
        "service": "foxpay",
        "version": "3.0.0",
        "python": sys.version.split()[0],
        "db": DB_PATH,
        "db_ok": db_ok,
        "db_error": db_error,
        "dev_mode": DEV_MODE,
        "site_url": SITE_URL,
        "time": iso(utcnow()),
    }


@app.get("/api/debug")
def debug():
    """Extended diagnostics."""
    info: Dict[str, Any] = {
        "python": sys.version,
        "db_path": DB_PATH,
        "db_version": DB_VERSION,
        "render": RENDER_MODE,
        "dev": DEV_MODE,
    }

    try:
        import pydantic
        info["pydantic"] = pydantic.VERSION
    except Exception as e:
        info["pydantic_error"] = str(e)

    try:
        import jwt as j
        info["pyjwt"] = j.__version__
    except Exception as e:
        info["pyjwt_error"] = str(e)

    try:
        db = SessionLocal()
        info["users"] = db.query(User).count()
        info["transfers"] = db.query(Transfer).count()
        info["intents"] = db.query(PaymentIntent).count()
        info["db_ok"] = True
        db.close()
    except Exception as e:
        info["db_error"] = str(e)
        info["db_ok"] = False

    return info


@app.get("/api/stats")
def public_stats(db: Session = Depends(get_db)):
    try:
        users = db.query(User).count()
        transfers = db.query(Transfer).count()
        volume = db.query(func.sum(Transfer.amount_tiyin)).scalar() or 0
        return {
            "users": users,
            "transfers": transfers,
            "volume_tiyin": int(volume),
            "volume_uzs": int(volume) / 100,
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {"users": 0, "transfers": 0, "volume_tiyin": 0, "volume_uzs": 0}


# ═══════════════════════════════════════════════════════════════════════
# 15. SCHEMAS
# ═══════════════════════════════════════════════════════════════════════

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=6, max_length=128)
    phone: Optional[str] = None
    company: Optional[str] = ""


class LoginIn(BaseModel):
    email: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class PasswordChangeIn(BaseModel):
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
    customer_name: Optional[str] = None


class KeyIn(BaseModel):
    label: str = "default"
    scopes: str = "read,write,p2p,collect"


class HookIn(BaseModel):
    url: str = Field(min_length=10)
    events: str = "*"


class MerchantIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = "general"


class SubscribeIn(BaseModel):
    plan_id: str


class FundIn(BaseModel):
    amount_tiyin: int = Field(gt=0)


class WithdrawIn(BaseModel):
    amount_tiyin: int = Field(gt=0)


# ═══════════════════════════════════════════════════════════════════════
# 16. AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def register(
    body: RegisterIn,
    request: Request,
    db: Session = Depends(get_db),
):
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

    ensure_wallet(db, user.id)

    create_audit(db, user.id, "user.register", request, f"email={email}")
    create_notification(
        db,
        user.id,
        "Xush kelibsiz!",
        "FoxPay'ga ro'yxatdan o'tdingiz. Balansni to'ldiring va birinchi to'lovni qabul qiling.",
        "success",
    )

    logger.info(f"Registered: {email} (id={user.id})")

    return {
        "token": make_token(user.id, "access"),
        "refresh_token": make_token(user.id, "refresh"),
        "user": user_dict(user),
    }


@app.post("/api/auth/login")
def login(
    body: LoginIn,
    request: Request,
    db: Session = Depends(get_db),
):
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
def refresh_token(body: RefreshIn):
    user_id = decode_token(body.refresh_token, "refresh")
    return {
        "token": make_token(user_id, "access"),
        "refresh_token": make_token(user_id, "refresh"),
    }


@app.post("/api/auth/logout")
def logout(user: User = Depends(get_current_user)):
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.post("/api/auth/password")
def change_password(
    body: PasswordChangeIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(400, "Current password incorrect")

    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════
# 17. WALLET ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/wallet")
def get_wallet(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return wallet_dict(db, user)


@app.get("/api/wallet/ledger")
def get_ledger(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.user_id == user.id
    ).order_by(LedgerEntry.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": r.id,
            "direction": r.direction,
            "amount_tiyin": r.amount_tiyin,
            "balance_after": r.balance_after,
            "ref_type": r.ref_type,
            "ref_id": r.ref_id,
            "description": r.description,
            "created_at": iso(r.created_at),
        }
        for r in rows
    ]


@app.post("/api/dev/fund")
def dev_fund(
    body: FundIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not DEV_MODE:
        raise HTTPException(403, "Dev mode disabled")
    if body.amount_tiyin > 1_000_000_000:
        raise HTTPException(400, "Dev fund limit: 10,000,000 UZS")

    post_ledger(db, user.id, "credit", body.amount_tiyin, "deposit", f"dev_{secrets.token_hex(4)}")
    db.commit()

    return {"ok": True, "amount_tiyin": body.amount_tiyin, "balance": get_balance_simple(db, user.id)}


@app.post("/api/wallet/withdraw")
def withdraw(
    body: WithdrawIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    bal = get_balance_simple(db, user.id)
    if bal < body.amount_tiyin:
        raise HTTPException(400, "Insufficient balance")

    post_ledger(db, user.id, "debit", body.amount_tiyin, "withdraw", f"wd_{secrets.token_hex(4)}")
    db.commit()

    return {"ok": True, "amount_tiyin": body.amount_tiyin, "balance": get_balance_simple(db, user.id)}


# ═══════════════════════════════════════════════════════════════════════
# 18. P2P TRANSFERS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/p2p/transfers")
def create_transfer(
    body: TransferIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"p2p:{user.id}", 30, 60)

    if body.amount_tiyin < MIN_TRANSFER_TIYIN:
        raise HTTPException(400, f"Minimum amount: {MIN_TRANSFER_TIYIN / 100:.0f} UZS")
    if body.amount_tiyin > MAX_TRANSFER_TIYIN:
        raise HTTPException(400, "Amount too large")

    to_email = validate_email(body.to_email)
    recipient = db.query(User).filter(User.email == to_email).first()

    if not recipient:
        raise HTTPException(404, "Recipient not found")
    if recipient.id == user.id:
        raise HTTPException(400, "Cannot send to yourself")

    fee = calc_fee(body.amount_tiyin)
    total = body.amount_tiyin + fee

    bal = get_balance_simple(db, user.id)
    if bal < total:
        raise HTTPException(400, f"Insufficient balance. Need {total/100:.0f} UZS, have {bal/100:.0f} UZS")

    tid = f"tr_{secrets.token_hex(10)}"

    post_ledger(db, user.id, "debit", total, "p2p", tid, body.note or f"Transfer to {to_email}")
    post_ledger(db, recipient.id, "credit", body.amount_tiyin, "p2p", tid, body.note or f"Transfer from {user.email}")

    transfer = Transfer(
        transfer_id=tid,
        from_user_id=user.id,
        to_user_id=recipient.id,
        amount_tiyin=body.amount_tiyin,
        fee_tiyin=fee,
        status="succeeded",
        note=body.note[:255],
        completed_at=utcnow(),
    )
    db.add(transfer)
    db.commit()

    background.add_task(
        dispatch_webhook,
        user.id,
        "transfer.succeeded",
        {"transfer_id": tid, "amount_tiyin": body.amount_tiyin, "fee_tiyin": fee, "to_email": to_email},
    )

    create_notification(
        db,
        recipient.id,
        "Pul qabul qilindi",
        f"{user.name} sizga {body.amount_tiyin / 100:,.0f} UZS yubordi.",
        "success",
    )

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
    status_filter: Optional[str] = Query(None, alias="status"),
):
    q = db.query(Transfer).filter(
        or_(Transfer.from_user_id == user.id, Transfer.to_user_id == user.id)
    )
    if status_filter:
        q = q.filter(Transfer.status == status_filter)

    rows = q.order_by(Transfer.created_at.desc()).offset(offset).limit(limit).all()
    return [transfer_dict(t) for t in rows]


@app.get("/api/p2p/transfers/{transfer_id}")
def get_transfer(
    transfer_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    t = db.query(Transfer).filter(Transfer.transfer_id == transfer_id).first()
    if not t:
        raise HTTPException(404, "Transfer not found")
    if user.id not in (t.from_user_id, t.to_user_id):
        raise HTTPException(403, "Access denied")
    return transfer_dict(t)


# ═══════════════════════════════════════════════════════════════════════
# 19. PAYMENT INTENTS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/pay/intents")
def create_intent(
    body: IntentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"intent:{user.id}", 30, 60)

    if body.amount_tiyin < MIN_TRANSFER_TIYIN:
        raise HTTPException(400, f"Minimum: {MIN_TRANSFER_TIYIN / 100:.0f} UZS")

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
        customer_name=body.customer_name,
    )
    db.add(intent)
    db.commit()
    db.refresh(intent)

    return intent_dict(intent)


@app.get("/api/pay/intents")
def list_intents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
):
    rows = db.query(PaymentIntent).filter(
        PaymentIntent.user_id == user.id
    ).order_by(PaymentIntent.created_at.desc()).limit(limit).all()
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
        raise HTTPException(404, "Intent not found")
    if intent.status == "succeeded":
        return {"intent_id": intent.intent_id, "status": "succeeded", "already": True}
    if intent.status != "requires_payment":
        raise HTTPException(400, f"Cannot confirm intent with status {intent.status}")

    post_ledger(db, user.id, "credit", intent.net_tiyin, "intent", intent.intent_id, intent.description)

    intent.status = "succeeded"
    intent.completed_at = utcnow()
    db.commit()

    background.add_task(
        dispatch_webhook,
        user.id,
        "payment.succeeded",
        {"intent_id": intent.intent_id, "net_tiyin": intent.net_tiyin},
    )

    return {
        "intent_id": intent.intent_id,
        "status": "succeeded",
        "net_tiyin": intent.net_tiyin,
    }


@app.post("/api/pay/intents/{intent_id}/cancel")
def cancel_intent(
    intent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    intent = db.query(PaymentIntent).filter(
        PaymentIntent.intent_id == intent_id,
        PaymentIntent.user_id == user.id,
    ).first()
    if not intent:
        raise HTTPException(404, "Intent not found")
    if intent.status not in ("requires_payment", "pending"):
        raise HTTPException(400, "Cannot cancel")

    intent.status = "cancelled"
    intent.cancelled_at = utcnow()
    db.commit()
    return {"intent_id": intent.intent_id, "status": "cancelled"}


# ═══════════════════════════════════════════════════════════════════════
# 20. API KEYS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/keys")
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc()).all()
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
def create_key(
    body: KeyIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"key:{user.id}", 10, 60)

    full, prefix, key_hash = generate_api_key()
    k = ApiKey(
        user_id=user.id,
        prefix=prefix,
        key_hash=key_hash,
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
        "created_at": iso(k.created_at),
    }


@app.delete("/api/keys/{key_id}")
def revoke_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    k = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user.id).first()
    if not k:
        raise HTTPException(404, "Key not found")
    k.is_active = False
    db.commit()
    return {"ok": True}


@app.post("/api/keys/{key_id}/rotate")
def rotate_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    k = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user.id).first()
    if not k:
        raise HTTPException(404, "Key not found")

    full, prefix, key_hash = generate_api_key()
    k.prefix = prefix
    k.key_hash = key_hash
    k.is_active = True
    db.commit()
    return {"id": k.id, "prefix": k.prefix, "full_key": full}


# ═══════════════════════════════════════════════════════════════════════
# 21. WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

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
            "last_success_at": iso(h.last_success_at),
            "last_failure_at": iso(h.last_failure_at),
            "created_at": iso(h.created_at),
        }
        for h in rows
    ]


@app.post("/api/hooks")
def create_hook(
    body: HookIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

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
def delete_hook(
    hook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    h = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.id == hook_id,
        WebhookEndpoint.user_id == user.id,
    ).first()
    if not h:
        raise HTTPException(404, "Hook not found")
    db.delete(h)
    db.commit()
    return {"ok": True}


@app.post("/api/hooks/{hook_id}/test")
def test_hook(
    hook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    h = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.id == hook_id,
        WebhookEndpoint.user_id == user.id,
    ).first()
    if not h:
        raise HTTPException(404, "Hook not found")

    try:
        import httpx
        payload = json.dumps({"event": "test.ping", "data": {"timestamp": iso(utcnow())}})
        ts = str(int(time.time()))
        sig = hmac.new(
            h.secret.encode(),
            f"{ts}.{payload}".encode(),
            hashlib.sha256,
        ).hexdigest()

        resp = httpx.post(
            h.url,
            content=payload,
            timeout=10,
            headers={
                "Content-Type": "application/json",
                "X-FoxPay-Signature": f"t={ts},v1={sig}",
                "X-FoxPay-Event": "test.ping",
            },
        )
        return {"ok": True, "status": resp.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def dispatch_webhook(user_id: int, event: str, data: Dict[str, Any]) -> None:
    """Send webhook to user's endpoints (background task)."""
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed, webhooks disabled")
        return

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
                resp = httpx.post(
                    h.url,
                    content=payload,
                    timeout=10,
                    headers={
                        "Content-Type": "application/json",
                        "X-FoxPay-Signature": f"t={ts},v1={sig}",
                        "X-FoxPay-Event": event,
                    },
                )
                if 200 <= resp.status_code < 300:
                    h.last_success_at = utcnow()
                    h.failure_count = 0
                else:
                    h.last_failure_at = utcnow()
                    h.failure_count = (h.failure_count or 0) + 1
            except Exception as e:
                h.last_failure_at = utcnow()
                h.failure_count = (h.failure_count or 0) + 1
                logger.warning(f"Webhook failed {h.url}: {e}")

        db.commit()
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════
# 22. MERCHANTS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/merchants")
def list_merchants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Merchant).filter(Merchant.user_id == user.id).all()
    return [
        {
            "id": m.id,
            "name": m.name,
            "category": m.category,
            "status": m.status,
            "volume_tiyin": m.volume_tiyin,
            "created_at": iso(m.created_at),
        }
        for m in rows
    ]


@app.post("/api/merchants")
def create_merchant(
    body: MerchantIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.category not in MERCHANT_CATEGORIES:
        raise HTTPException(400, f"Category must be one of: {', '.join(MERCHANT_CATEGORIES)}")

    m = Merchant(
        user_id=user.id,
        name=body.name.strip(),
        category=body.category,
        status="active",
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "name": m.name, "category": m.category, "status": m.status}


# ═══════════════════════════════════════════════════════════════════════
# 23. SUBSCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/subscriptions/plans")
def list_plans():
    return list(SUBSCRIPTION_PLANS.values())


@app.get("/api/subscriptions")
def list_subscriptions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(Subscription).filter(Subscription.user_id == user.id).order_by(Subscription.created_at.desc()).all()
    return [
        {
            "id": s.id,
            "plan_id": s.plan_id,
            "plan_name": s.plan_name,
            "amount_tiyin": s.amount_tiyin,
            "status": s.status,
            "started_at": iso(s.started_at),
            "next_billing_at": iso(s.next_billing_at),
            "cancelled_at": iso(s.cancelled_at),
        }
        for s in rows
    ]


@app.post("/api/subscriptions/subscribe")
def subscribe(
    body: SubscribeIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plan = SUBSCRIPTION_PLANS.get(body.plan_id)
    if not plan:
        raise HTTPException(404, "Plan not found")

    # Cancel existing active
    db.query(Subscription).filter(
        Subscription.user_id == user.id,
        Subscription.status == "active",
    ).update({"status": "cancelled", "cancelled_at": utcnow()})

    sub = Subscription(
        user_id=user.id,
        plan_id=plan["id"],
        plan_name=plan["name"],
        amount_tiyin=plan["amount_tiyin"],
        status="active",
        next_billing_at=utcnow() + timedelta(days=30),
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return {"id": sub.id, "plan_id": sub.plan_id, "status": sub.status}


# ═══════════════════════════════════════════════════════════════════════
# 24. NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/notifications")
def list_notifications(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(30, ge=1, le=100),
):
    rows = db.query(Notification).filter(
        Notification.user_id == user.id
    ).order_by(Notification.created_at.desc()).limit(limit).all()

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


@app.post("/api/notifications/{notif_id}/read")
def mark_read(
    notif_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    n = db.query(Notification).filter(
        Notification.id == notif_id,
        Notification.user_id == user.id,
    ).first()
    if not n:
        raise HTTPException(404, "Not found")
    n.is_read = True
    db.commit()
    return {"ok": True}


@app.post("/api/notifications/read-all")
def mark_all_read(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.query(Notification).filter(
        Notification.user_id == user.id,
        Notification.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════
# 25. ANALYTICS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/analytics/summary")
def analytics_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    bal = get_balance_simple(db, user.id)
    sent = db.query(Transfer).filter(Transfer.from_user_id == user.id, Transfer.status == "succeeded").all()
    received = db.query(Transfer).filter(Transfer.to_user_id == user.id, Transfer.status == "succeeded").all()
    intents = db.query(PaymentIntent).filter(PaymentIntent.user_id == user.id).all()

    total_sent = sum(t.amount_tiyin for t in sent)
    total_fees = sum(t.fee_tiyin for t in sent)
    total_received = sum(t.amount_tiyin for t in received)
    succeeded_intents = [i for i in intents if i.status == "succeeded"]
    pending_intents = [i for i in intents if i.status == "requires_payment"]

    return {
        "balance_tiyin": bal,
        "balance_uzs": bal / 100,
        "total_sent_tiyin": total_sent,
        "total_received_tiyin": total_received,
        "total_fees_tiyin": total_fees,
        "transfer_count": len(sent) + len(received),
        "intent_count": len(intents),
        "intents_succeeded": len(succeeded_intents),
        "intents_pending": len(pending_intents),
    }


@app.get("/api/analytics/daily")
def analytics_daily(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    days: int = Query(7, ge=1, le=90),
):
    now = utcnow()
    results = []
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
        results.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "count": len(rows),
            "volume_tiyin": volume,
            "volume_uzs": volume / 100,
        })

    return results


@app.get("/api/analytics/methods")
def analytics_methods(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Payment methods distribution (stub for now)."""
    total = db.query(Transfer).filter(
        or_(Transfer.from_user_id == user.id, Transfer.to_user_id == user.id)
    ).count()

    if total == 0:
        return []

    return [
        {"method": "P2P", "count": total, "percentage": 100},
    ]


# ═══════════════════════════════════════════════════════════════════════
# 26. SETTINGS
# ═══════════════════════════════════════════════════════════════════════

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
        new_email = validate_email(body.email)
        clash = db.query(User).filter(User.email == new_email, User.id != user.id).first()
        if clash:
            raise HTTPException(400, "Email already in use")
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


# ═══════════════════════════════════════════════════════════════════════
# 27. ADMIN
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/admin/users")
def admin_list_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows = db.query(User).order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    return [user_dict(u) for u in rows]


@app.get("/api/admin/stats")
def admin_stats(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return {
        "users": db.query(User).count(),
        "wallets": db.query(Wallet).count(),
        "transfers": db.query(Transfer).count(),
        "intents": db.query(PaymentIntent).count(),
        "api_keys": db.query(ApiKey).count(),
        "webhooks": db.query(WebhookEndpoint).count(),
        "merchants": db.query(Merchant).count(),
        "subscriptions": db.query(Subscription).count(),
    }


# ═══════════════════════════════════════════════════════════════════════
# 28. EXPORT
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/export/transactions.csv")
def export_transactions_csv(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(Transfer).filter(
        or_(Transfer.from_user_id == user.id, Transfer.to_user_id == user.id)
    ).order_by(Transfer.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "From", "To", "Amount (UZS)", "Fee (UZS)", "Status", "Note", "Date"])

    for t in rows:
        writer.writerow([
            t.transfer_id,
            t.from_user_id,
            t.to_user_id,
            f"{t.amount_tiyin / 100:.2f}",
            f"{t.fee_tiyin / 100:.2f}",
            t.status,
            t.note or "",
            iso(t.created_at) or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=foxpay-transactions-{user.id}.csv"},
    )


# ═══════════════════════════════════════════════════════════════════════
# 29. INDEX & CATCH-ALL
# ═══════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index():
    idx_path = BASE_DIR / "index.html"
    if idx_path.exists():
        return FileResponse(idx_path, media_type="text/html")
    return HTMLResponse(build_landing_html())


@app.get("/{path:path}", response_class=HTMLResponse)
def catch_all(path: str):
    """SPA fallback — serves index.html for all non-API routes."""
    if path.startswith("api/") or path in ("docs", "redoc", "openapi.json"):
        raise HTTPException(404, "Not found")

    idx_path = BASE_DIR / "index.html"
    if idx_path.exists():
        return FileResponse(idx_path, media_type="text/html")
    return HTMLResponse(build_landing_html())


# ═══════════════════════════════════════════════════════════════════════
# 30. ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"detail": "Endpoint not found"})
    idx_path = BASE_DIR / "index.html"
    if idx_path.exists():
        return FileResponse(idx_path)
    return HTMLResponse(build_landing_html())


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.exception(f"500 on {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ═══════════════════════════════════════════════════════════════════════
# 31. STARTUP & SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    logger.info("=" * 70)
    logger.info(f"🦊 FoxPay API v3.0.0 starting")
    logger.info(f"   Python:    {sys.version.split()[0]}")
    logger.info(f"   DB:        {DB_PATH}")
    logger.info(f"   DB version: {DB_VERSION}")
    logger.info(f"   Port:      {PORT}")
    logger.info(f"   Dev:       {DEV_MODE}")
    logger.info(f"   Render:    {RENDER_MODE}")
    logger.info(f"   Site URL:  {SITE_URL}")
    logger.info("=" * 70)

    # Verify schema
    try:
        db = SessionLocal()
        result = db.execute(text("SELECT COUNT(*) FROM users")).scalar()
        logger.info(f"   DB schema OK (users table, {result} rows)")
        db.close()
    except Exception as e:
        logger.error(f"   DB schema check FAILED: {e}")


@app.on_event("shutdown")
async def shutdown():
    logger.info("FoxPay API shutting down")


# ═══════════════════════════════════════════════════════════════════════
# 32. ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True,
    )
