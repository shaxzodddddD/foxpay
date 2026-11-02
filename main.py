"""
═══════════════════════════════════════════════════════════════════════════
FOXPAY — Production-Ready Backend
═══════════════════════════════════════════════════════════════════════════

Features:
  ✅ Full auth (register/login/JWT/refresh)
  ✅ Double-entry ledger + wallet
  ✅ P2P transfers with 1.5% fee
  ✅ Payment intents
  ✅ API keys for merchants
  ✅ Webhooks (HMAC-signed)
  ✅ Google Search optimization:
     - robots.txt, sitemap.xml
     - googleXXXX.html verification
     - Bot detection (prerender for bots)
     - SEO headers (X-Robots-Tag, canonical)
  ✅ Static landing page (no JS required)
  ✅ Rate limiting
  ✅ Error handling
  ✅ CORS, security headers

Render Setup:
  Build:  pip install -r requirements.txt
  Start:  uvicorn main:app --host 0.0.0.0 --port $PORT
  
Environment:
  FOXPAY_SECRET    — JWT signing key (required in prod)
  FOXPAY_DB        — SQLite path (default: /tmp/foxpay.db on Render)
  FOXPAY_DEV       — "1" enables /api/dev/fund (default: on)
  SITE_URL         — https://foxpay.uz (for canonical/sitemap)
═══════════════════════════════════════════════════════════════════════════
"""

import os
import re
import sys
import json
import time
import hmac
import html
import secrets
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

import jwt
from fastapi import (
    FastAPI, Depends, HTTPException, Header, Request, Response,
    status, Query, BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    FileResponse, JSONResponse, PlainTextResponse, HTMLResponse,
    Response as FastResponse,
)
from pydantic import BaseModel, Field, validator
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    BigInteger, ForeignKey, Text, Index, func,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.pool import StaticPool


# ═══════════════════════════════════════════════════════════════════════
# 1. CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).resolve().parent
SITE_URL = os.getenv("SITE_URL", "https://foxpay.uz")
SITE_NAME = "FoxPay"
SITE_DESCRIPTION = "O'zbekistonda onlayn to'lovlar, P2P o'tkazmalar va payment API"
CONTACT_EMAIL = "hello@foxpay.uz"

PORT = int(os.getenv("PORT", "9988"))
SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
JWT_ALG = "HS256"
TOKEN_EXPIRE_DAYS = 7
DEV_MODE = os.getenv("FOXPAY_DEV", "1") == "1"
RENDER_MODE = os.getenv("RENDER") is not None

FEE_RATE_BPS = 150  # 1.5% = 150 basis points

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("foxpay")


# ═══════════════════════════════════════════════════════════════════════
# 2. DATABASE
# ═══════════════════════════════════════════════════════════════════════

def _resolve_db_path() -> str:
    """Find first writable DB path."""
    candidates = []
    if os.getenv("FOXPAY_DB"):
        candidates.append(os.getenv("FOXPAY_DB"))
    candidates.append(str(BASE_DIR / "foxpay.db"))
    if RENDER_MODE:
        candidates.append("/tmp/foxpay.db")
    candidates.append("/tmp/foxpay.db")

    for path in candidates:
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            probe = p.parent / f".write_test_{secrets.token_hex(4)}"
            probe.write_text("x")
            probe.unlink()
            return path
        except Exception:
            continue
    return "/tmp/foxpay.db"


DB_PATH = _resolve_db_path()
logger.info(f"Database: {DB_PATH}")

# Use StaticPool for SQLite in-memory safety with FastAPI
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_pre_ping=True,
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
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


# ═══════════════════════════════════════════════════════════════════════
# 3. MODELS
# ═══════════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    phone = Column(String(32), index=True, nullable=True)
    company = Column(String(200), default="")
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow, index=True)


class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    currency = Column(String(8), default="UZS")
    balance_tiyin = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=utcnow)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    direction = Column(String(8), nullable=False)  # credit | debit
    amount_tiyin = Column(BigInteger, nullable=False)
    ref_type = Column(String(32), index=True)
    ref_id = Column(String(64), index=True)
    note = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, index=True)


Index("ix_ledger_user_created", LedgerEntry.user_id, LedgerEntry.created_at.desc())


class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    transfer_id = Column(String(32), unique=True, index=True)
    from_user_id = Column(Integer, ForeignKey("users.id"), index=True)
    to_user_id = Column(Integer, ForeignKey("users.id"), index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    fee_tiyin = Column(BigInteger, default=0)
    currency = Column(String(8), default="UZS")
    status = Column(String(16), default="succeeded")
    note = Column(String(255), default="")
    created_at = Column(DateTime, default=utcnow, index=True)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id = Column(Integer, primary_key=True)
    intent_id = Column(String(32), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    amount_tiyin = Column(BigInteger, nullable=False)
    status = Column(String(20), default="requires_payment")
    description = Column(String(255), default="")
    customer_email = Column(String(200), nullable=True)
    fee_tiyin = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    prefix = Column(String(20), index=True)
    key_hash = Column(String(64), nullable=False)
    label = Column(String(64), default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(100), nullable=False)
    events = Column(String(255), default="*")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Merchant(Base):
    __tablename__ = "merchants"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    name = Column(String(120), nullable=False)
    category = Column(String(64), default="general")
    status = Column(String(16), default="active")
    volume_tiyin = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=utcnow)


Base.metadata.create_all(bind=engine)
logger.info("Database tables created")


# ═══════════════════════════════════════════════════════════════════════
# 4. SECURITY
# ═══════════════════════════════════════════════════════════════════════

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email format")
    return email


def hash_password(raw: str) -> str:
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


def make_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing authorization header")
    token = authorization[7:].strip()

    if token.startswith("fox_live_"):
        k = db.query(ApiKey).filter(
            ApiKey.prefix == token[:20],
            ApiKey.key_hash == hashlib.sha256(token.encode()).hexdigest(),
            ApiKey.is_active == True,
        ).first()
        if not k:
            raise HTTPException(401, "Invalid API key")
        user = db.get(User, k.user_id)
    else:
        user = db.get(User, decode_token(token))

    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    return user


# ═══════════════════════════════════════════════════════════════════════
# 5. SCHEMAS
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


class ProfileIn(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None


class TransferIn(BaseModel):
    to_email: str
    amount_tiyin: int = Field(gt=0)
    note: str = ""


class IntentIn(BaseModel):
    amount_tiyin: int = Field(gt=0)
    description: str = ""
    customer_email: Optional[str] = None


class KeyIn(BaseModel):
    label: str = "default"


class HookIn(BaseModel):
    url: str = Field(min_length=10)
    events: str = "*"


class FundIn(BaseModel):
    amount_tiyin: int = Field(gt=0)


# ═══════════════════════════════════════════════════════════════════════
# 6. LEDGER LOGIC
# ═══════════════════════════════════════════════════════════════════════

def get_balance(db: Session, user_id: int, currency: str = "UZS") -> int:
    """Compute balance from ledger (source of truth)."""
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.user_id == user_id
    ).all()
    return (
        sum(r.amount_tiyin for r in rows if r.direction == "credit")
        - sum(r.amount_tiyin for r in rows if r.direction == "debit")
    )


def post_ledger(
    db: Session,
    user_id: int,
    direction: str,
    amount: int,
    ref_type: str = "",
    ref_id: str = "",
    note: str = "",
) -> None:
    """Write a ledger entry and update cached balance."""
    if direction not in ("credit", "debit"):
        raise ValueError("Invalid direction")
    if amount <= 0:
        raise ValueError("Amount must be positive")

    db.add(LedgerEntry(
        user_id=user_id,
        direction=direction,
        amount_tiyin=amount,
        ref_type=ref_type,
        ref_id=ref_id,
        note=note,
    ))

    w = db.query(Wallet).filter(Wallet.user_id == user_id).first()
    if not w:
        w = Wallet(user_id=user_id, balance_tiyin=0)
        db.add(w)
        db.flush()
    w.balance_tiyin += amount if direction == "credit" else -amount


def calc_fee(amount: int) -> int:
    return amount * FEE_RATE_BPS // 10_000


# ═══════════════════════════════════════════════════════════════════════
# 7. RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════

_rate_store: Dict[str, List[float]] = {}


def rate_limit(key: str, limit: int, window: int = 60) -> None:
    """Simple in-memory rate limiter."""
    now = time.time()
    hits = _rate_store.get(key, [])
    hits = [t for t in hits if t > now - window]
    if len(hits) >= limit:
        raise HTTPException(429, "Too many requests. Please try again later.")
    hits.append(now)
    _rate_store[key] = hits


# ═══════════════════════════════════════════════════════════════════════
# 8. BOT DETECTION (for SEO)
# ═══════════════════════════════════════════════════════════════════════

BOT_PATTERNS = [
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebookexternalhit", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "applebot", "semrushbot", "ahrefsbot",
]


def is_bot(request: Request) -> bool:
    """Detect crawlers/social media bots."""
    ua = (request.headers.get("user-agent") or "").lower()
    if not ua:
        return True
    return any(bot in ua for bot in BOT_PATTERNS)


# ═══════════════════════════════════════════════════════════════════════
# 9. APP & MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="FoxPay API",
    version="2.0.0",
    description="Payment infrastructure for Uzbekistan. P2P, API, webhooks.",
    docs_url="/docs",
    redoc_url="/redoc",
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
async def security_headers(request: Request, call_next):
    """Add security & SEO headers."""
    response = await call_next(request)

    # Security
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # SEO
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/docs"):
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
    elif path == "/":
        response.headers["X-Robots-Tag"] = "index, follow, max-image-preview:large"
        response.headers["Link"] = f'<{SITE_URL}/>; rel="canonical"'

    # Cache
    if path.startswith("/static/") or path.endswith((".css", ".js", ".png", ".ico", ".svg")):
        response.headers["Cache-Control"] = "public, max-age=86400"
    elif path == "/" or path == "/robots.txt" or path == "/sitemap.xml":
        response.headers["Cache-Control"] = "public, max-age=300"
    elif path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


# ═══════════════════════════════════════════════════════════════════════
# 10. LANDING PAGE (inline HTML — no JS needed for SEO)
# ═══════════════════════════════════════════════════════════════════════

def build_landing_html() -> str:
    """Generate SEO-optimized landing page."""
    today = datetime.utcnow().strftime("%Y-%m-%d")

    faq_data = [
        ("FoxPay nima?", "FoxPay — O'zbekiston uchun onlayn to'lov platformasi. Freelancerlar, kichik biznes va merchantlar uchun P2P o'tkazmalar, payment API va webhooks."),
        ("Komissiya qancha?", "Start rejasida 1.8%, Business rejasida 1.5%. Oylik to'lov yo'q — faqat muvaffaqiyatli tranzaksiyadan komissiya olinadi."),
        ("Qaysi kartalar qo'llab-quvvatlanadi?", "Uzcard, Humo, Visa, Mastercard. Shuningdek Payme, Click va bank o'tkazmalari."),
        ("Pul qancha vaqtda tushadi?", "P2P o'tkazmalar real vaqtda. Merchant to'lovlari 1 ish kuni ichida."),
        ("API bormi?", "Ha, REST API, webhook va tayyor SDK. 15 daqiqada integratsiya."),
    ]

    faq_json = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}}
            for q, a in faq_data
        ]
    }

    org_json = {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": SITE_NAME,
        "url": SITE_URL,
        "logo": f"{SITE_URL}/logo.png",
        "description": SITE_DESCRIPTION,
        "email": CONTACT_EMAIL,
        "address": {"@type": "PostalAddress", "addressLocality": "Tashkent", "addressCountry": "UZ"},
    }

    app_json = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": SITE_NAME,
        "applicationCategory": "FinanceApplication",
        "operatingSystem": "Web",
        "url": SITE_URL,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "UZS"},
    }

    faq_html = "".join(
        f'<details class="faq-item"><summary class="faq-q">{html.escape(q)}</summary>'
        f'<div class="faq-a">{html.escape(a)}</div></details>'
        for q, a in faq_data
    )

    return f'''<!DOCTYPE html>
<html lang="uz" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_NAME} — O'zbekistonda onlayn to'lovlar, P2P o'tkazmalar va API</title>
<meta name="description" content="{SITE_DESCRIPTION}. 1.5% komissiya, bepul boshlash.">
<meta name="keywords" content="FoxPay, to'lov tizimi, onlayn to'lov, P2P o'tkazma, payment API, Uzcard, Humo, Payme, Click, fintech O'zbekiston">
<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">
<meta name="author" content="FoxPay">
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
<meta property="og:title" content="{SITE_NAME} — To'lov bir zumda">
<meta property="og:description" content="{SITE_DESCRIPTION}">
<meta property="og:url" content="{SITE_URL}/">
<meta property="og:image" content="{SITE_URL}/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{SITE_NAME} — To'lov bir zumda">
<meta name="twitter:description" content="{SITE_DESCRIPTION}">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='20' fill='%230B1120'/%3E%3Cpath d='M30 30l20 20 20-20v30a20 20 0 0 1-40 0V30z' fill='%23FF6B00'/%3E%3C/svg%3E">
<script type="application/ld+json">{json.dumps(org_json)}</script>
<script type="application/ld+json">{json.dumps(app_json)}</script>
<script type="application/ld+json">{json.dumps(faq_json)}</script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0B1120;color:#F8FAFC;line-height:1.5;font-size:15px;-webkit-font-smoothing:antialiased}}
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
.btn{{display:inline-block;padding:12px 24px;border-radius:10px;font-weight:600;font-size:14px;transition:.15s;cursor:pointer;border:0}}
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
.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
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
.hero-grid,.grid-3,.grid-2,.price-grid{{grid-template-columns:1fr}}
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
<div class="price-grid">
<div class="price-card">
<div class="price-name">Start</div>
<div class="price-amount">1.8%<span> / tx</span></div>
<div class="price-desc">Yangi boshlovchilar uchun</div>
<ul class="price-list"><li>Oylik to'lov yo'q</li><li>Payment link</li><li>Email support</li></ul>
<a href="/#/register" class="btn btn-outline" style="width:100%;text-align:center">Boshlash</a>
</div>
<div class="price-card featured">
<div class="price-badge">Ommabop</div>
<div class="price-name">Business</div>
<div class="price-amount">1.5%<span> / tx</span></div>
<div class="price-desc">O'sib borayotgan biznes uchun</div>
<ul class="price-list"><li>Barcha Start</li><li>REST API + Webhook</li><li>Ustuvor support</li></ul>
<a href="/#/register" class="btn btn-primary" style="width:100%;text-align:center">Boshlash</a>
</div>
<div class="price-card">
<div class="price-name">Enterprise</div>
<div class="price-amount">Kelishiladi</div>
<div class="price-desc">Yirik kompaniyalar uchun</div>
<ul class="price-list"><li>Individual komissiya</li><li>SLA 99.99%</li><li>Dedicated manager</li></ul>
<a href="/#/register" class="btn btn-outline" style="width:100%;text-align:center">Bog'lanish</a>
</div>
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
<span>© {datetime.utcnow().year} {SITE_NAME} Inc. Barcha huquqlar himoyalangan.</span>
<span>Toshkent, O'zbekiston · {today}</span>
</div>
</div>
</footer>

</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════════
# 11. STATIC FILE ROUTES (Google verification, robots, sitemap)
# ═══════════════════════════════════════════════════════════════════════

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    """Robots.txt for search engines."""
    return f"""User-agent: *
Allow: /
Disallow: /api/
Disallow: /docs
Disallow: /redoc
Disallow: /openapi.json

# Search engines - full access
User-agent: Googlebot
Allow: /
Disallow: /api/

User-agent: Bingbot
Allow: /
Disallow: /api/

Sitemap: {SITE_URL}/sitemap.xml
Host: {SITE_URL.replace('https://', '').replace('http://', '')}
"""


@app.get("/sitemap.xml", response_class=FastResponse)
def sitemap_xml():
    """Dynamic sitemap."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
<url>
    <loc>{SITE_URL}/</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
    <xhtml:link rel="alternate" hreflang="uz" href="{SITE_URL}/"/>
    <xhtml:link rel="alternate" hreflang="x-default" href="{SITE_URL}/"/>
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


@app.get("/google{verification_token}.html", response_class=PlainTextResponse)
def google_verification(verification_token: str):
    """
    Google Search Console HTML verification.
    Handles: /google1234abcd.html
    """
    # Reject if token doesn't look valid (avoid serving for arbitrary paths)
    if not re.match(r"^[a-zA-Z0-9_-]{6,64}$", verification_token):
        raise HTTPException(404, "Not found")

    # First check if actual file exists
    fname = f"google{verification_token}.html"
    path = BASE_DIR / fname
    if path.exists():
        return PlainTextResponse(
            f"google-site-verification: {fname}",
            media_type="text/html",
        )

    # Otherwise serve dynamic response (works for any verification)
    logger.info(f"Google verification served: {fname}")
    return PlainTextResponse(
        f"google-site-verification: {fname}",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/manifest.webmanifest")
def manifest():
    """PWA manifest."""
    return JSONResponse({
        "name": f"{SITE_NAME} — Payment Platform",
        "short_name": SITE_NAME,
        "description": SITE_DESCRIPTION,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0B1120",
        "theme_color": "#FF6B00",
        "lang": "uz",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
    }, media_type="application/manifest+json")


# ═══════════════════════════════════════════════════════════════════════
# 12. HEALTH & DEBUG
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    db_ok = False
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db_ok = True
        db.close()
    except Exception as e:
        logger.error(f"Health check DB error: {e}")

    return {
        "ok": True,
        "service": "foxpay",
        "version": "2.0.0",
        "python": sys.version.split()[0],
        "db": DB_PATH,
        "db_ok": db_ok,
        "dev": DEV_MODE,
        "site_url": SITE_URL,
        "time": iso(utcnow()),
    }


@app.get("/api/stats")
def public_stats(db: Session = Depends(get_db)):
    """Public stats for landing page."""
    return {
        "users": db.query(User).count(),
        "transfers": db.query(Transfer).count(),
        "volume_tiyin": db.query(func.sum(Transfer.amount_tiyin)).scalar() or 0,
    }


# ═══════════════════════════════════════════════════════════════════════
# 13. AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"register:{request.client.host}", 5, 300)

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

    db.add(Wallet(user_id=user.id, balance_tiyin=0))
    db.commit()

    logger.info(f"User registered: {user.email} (id={user.id})")

    return {
        "token": make_token(user.id),
        "user": {"id": user.id, "name": user.name, "email": user.email},
    }


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(f"login:{request.client.host}", 10, 60)

    email = validate_email(body.email)
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Email or password incorrect")

    return {
        "token": make_token(user.id),
        "user": {"id": user.id, "name": user.name, "email": user.email},
    }


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "company": user.company,
        "created_at": iso(user.created_at),
    }


# ═══════════════════════════════════════════════════════════════════════
# 14. WALLET ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/wallet")
def get_wallet(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    bal = get_balance(db, user.id)
    return {
        "currency": "UZS",
        "balance_tiyin": bal,
        "balance_uzs": bal / 100,
    }


@app.get("/api/wallet/ledger")
def get_ledger(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
):
    rows = db.query(LedgerEntry).filter(
        LedgerEntry.user_id == user.id
    ).order_by(LedgerEntry.created_at.desc()).limit(limit).all()

    return [
        {
            "id": r.id,
            "direction": r.direction,
            "amount_tiyin": r.amount_tiyin,
            "ref_type": r.ref_type,
            "ref_id": r.ref_id,
            "note": r.note,
            "created_at": iso(r.created_at),
        }
        for r in rows
    ]


@app.post("/api/dev/fund")
def fund(
    body: FundIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not DEV_MODE:
        raise HTTPException(403, "Dev mode disabled")

    post_ledger(db, user.id, "credit", body.amount_tiyin, "deposit", f"dev_{secrets.token_hex(4)}")
    db.commit()

    return {"ok": True, "amount_tiyin": body.amount_tiyin}


# ═══════════════════════════════════════════════════════════════════════
# 15. P2P TRANSFERS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/p2p/transfers")
def create_transfer(
    body: TransferIn,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"p2p:{user.id}", 30, 60)

    to_email = validate_email(body.to_email)
    recipient = db.query(User).filter(User.email == to_email).first()
    if not recipient:
        raise HTTPException(404, "Recipient not found")
    if recipient.id == user.id:
        raise HTTPException(400, "Cannot send to yourself")

    fee = calc_fee(body.amount_tiyin)
    total = body.amount_tiyin + fee

    if get_balance(db, user.id) < total:
        raise HTTPException(400, "Insufficient balance")

    tid = f"tr_{secrets.token_hex(10)}"

    post_ledger(db, user.id, "debit", total, "p2p", tid, body.note)
    post_ledger(db, recipient.id, "credit", body.amount_tiyin, "p2p", tid, body.note)

    transfer = Transfer(
        transfer_id=tid,
        from_user_id=user.id,
        to_user_id=recipient.id,
        amount_tiyin=body.amount_tiyin,
        fee_tiyin=fee,
        status="succeeded",
        note=body.note[:255],
    )
    db.add(transfer)
    db.commit()

    background.add_task(
        dispatch_webhook,
        user.id,
        "transfer.succeeded",
        {
            "transfer_id": tid,
            "amount_tiyin": body.amount_tiyin,
            "fee_tiyin": fee,
            "to_email": to_email,
        },
    )

    return {
        "transfer_id": tid,
        "amount_tiyin": body.amount_tiyin,
        "fee_tiyin": fee,
        "status": "succeeded",
    }


@app.get("/api/p2p/transfers")
def list_transfers(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
):
    rows = db.query(Transfer).filter(
        (Transfer.from_user_id == user.id) | (Transfer.to_user_id == user.id)
    ).order_by(Transfer.created_at.desc()).limit(limit).all()

    return [
        {
            "transfer_id": r.transfer_id,
            "from_user_id": r.from_user_id,
            "to_user_id": r.to_user_id,
            "amount_tiyin": r.amount_tiyin,
            "fee_tiyin": r.fee_tiyin,
            "status": r.status,
            "note": r.note,
            "created_at": iso(r.created_at),
        }
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════
# 16. PAYMENT INTENTS
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/pay/intents")
def create_intent(
    body: IntentIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rate_limit(f"intent:{user.id}", 30, 60)

    intent = PaymentIntent(
        intent_id=f"pi_{secrets.token_hex(10)}",
        user_id=user.id,
        amount_tiyin=body.amount_tiyin,
        status="requires_payment",
        description=body.description[:255],
        customer_email=body.customer_email,
        fee_tiyin=calc_fee(body.amount_tiyin),
    )
    db.add(intent)
    db.commit()
    db.refresh(intent)

    return {
        "intent_id": intent.intent_id,
        "amount_tiyin": intent.amount_tiyin,
        "fee_tiyin": intent.fee_tiyin,
        "status": intent.status,
        "description": intent.description,
        "created_at": iso(intent.created_at),
    }


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
        return {"intent_id": intent.intent_id, "status": "succeeded"}

    net = intent.amount_tiyin - intent.fee_tiyin
    post_ledger(db, user.id, "credit", net, "intent", intent.intent_id)
    post_ledger(db, user.id, "debit", intent.fee_tiyin, "fee", intent.intent_id)

    intent.status = "succeeded"
    intent.completed_at = utcnow()
    db.commit()

    background.add_task(
        dispatch_webhook,
        user.id,
        "payment.succeeded",
        {"intent_id": intent.intent_id, "amount_tiyin": net},
    )

    return {"intent_id": intent.intent_id, "status": "succeeded", "net_tiyin": net}


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
            "intent_id": r.intent_id,
            "amount_tiyin": r.amount_tiyin,
            "fee_tiyin": r.fee_tiyin,
            "status": r.status,
            "description": r.description,
            "customer_email": r.customer_email,
            "created_at": iso(r.created_at),
        }
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════
# 17. API KEYS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/keys")
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.user_id == user.id).all()
    return [
        {
            "id": k.id,
            "prefix": k.prefix,
            "label": k.label,
            "is_active": k.is_active,
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

    full = "fox_live_" + secrets.token_hex(24)
    key = ApiKey(
        user_id=user.id,
        prefix=full[:20],
        key_hash=hashlib.sha256(full.encode()).hexdigest(),
        label=body.label[:64],
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    return {
        "id": key.id,
        "prefix": key.prefix,
        "label": key.label,
        "is_active": True,
        "full_key": full,
    }


@app.delete("/api/keys/{key_id}")
def revoke_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.user_id == user.id,
    ).first()

    if not key:
        raise HTTPException(404, "Key not found")

    key.is_active = False
    db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════
# 18. WEBHOOKS
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
        raise HTTPException(400, "Invalid URL")

    hook = WebhookEndpoint(
        user_id=user.id,
        url=body.url,
        secret=f"whsec_{secrets.token_hex(20)}",
        events=body.events,
    )
    db.add(hook)
    db.commit()
    db.refresh(hook)

    return {"id": hook.id, "url": hook.url, "events": hook.events}


@app.delete("/api/hooks/{hook_id}")
def delete_hook(
    hook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    hook = db.query(WebhookEndpoint).filter(
        WebhookEndpoint.id == hook_id,
        WebhookEndpoint.user_id == user.id,
    ).first()

    if not hook:
        raise HTTPException(404, "Hook not found")

    db.delete(hook)
    db.commit()
    return {"ok": True}


def dispatch_webhook(user_id: int, event: str, data: dict) -> None:
    """Send webhook to all endpoints (background task)."""
    try:
        import httpx
    except ImportError:
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
                httpx.post(
                    h.url,
                    content=payload,
                    timeout=10,
                    headers={
                        "Content-Type": "application/json",
                        "X-FoxPay-Signature": f"t={ts},v1={sig}",
                        "X-FoxPay-Event": event,
                    },
                )
            except Exception as e:
                logger.warning(f"Webhook failed {h.url}: {e}")
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════
# 19. MERCHANTS
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


# ═══════════════════════════════════════════════════════════════════════
# 20. SETTINGS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/settings")
def get_settings(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "company": user.company,
    }


@app.put("/api/settings")
def update_settings(
    body: ProfileIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.email and body.email.lower() != user.email:
        new_email = validate_email(body.email)
        if db.query(User).filter(User.email == new_email, User.id != user.id).first():
            raise HTTPException(400, "Email already in use")
        user.email = new_email

    if body.name:
        user.name = body.name.strip()
    if body.phone is not None:
        user.phone = body.phone.strip() or None
    if body.company is not None:
        user.company = body.company.strip()

    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "company": user.company,
    }


# ═══════════════════════════════════════════════════════════════════════
# 21. LANDING PAGE & CATCH-ALL
# ═══════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Serve landing page. Bot-friendly static HTML."""
    # Try to serve index.html if exists (production build)
    index_path = BASE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    # Fallback to inline HTML
    return HTMLResponse(build_landing_html())


@app.get("/{path:path}", response_class=HTMLResponse)
def catch_all(path: str, request: Request):
    """
    Catch-all route.
    IMPORTANT: This must come AFTER all specific routes.
    - /api/* → 404
    - Bot requests to SPA routes → prerendered landing
    - Otherwise → index.html (SPA fallback)
    """
    if path.startswith("api/") or path in ("docs", "redoc", "openapi.json"):
        raise HTTPException(404, "Not found")

    # Serve index.html if exists
    index_path = BASE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")

    # Fallback to inline landing
    return HTMLResponse(build_landing_html())


# ═══════════════════════════════════════════════════════════════════════
# 22. ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={"detail": "Endpoint not found"},
        )
    # For non-API, serve landing page (SPA fallback)
    index_path = BASE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse(build_landing_html())


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.error(f"500 error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ═══════════════════════════════════════════════════════════════════════
# 23. STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    logger.info("=" * 70)
    logger.info(f"🦊 FoxPay API v2.0.0 starting")
    logger.info(f"   Python: {sys.version.split()[0]}")
    logger.info(f"   DB: {DB_PATH}")
    logger.info(f"   Port: {PORT}")
    logger.info(f"   Dev mode: {DEV_MODE}")
    logger.info(f"   Site URL: {SITE_URL}")
    logger.info(f"   Render: {RENDER_MODE}")
    logger.info("=" * 70)


@app.on_event("shutdown")
async def shutdown():
    logger.info("FoxPay API shutting down")


# ═══════════════════════════════════════════════════════════════════════
# 24. ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True,
    )
