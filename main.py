"""
FoxPay Backend — main.py
Stack: FastAPI + SQLAlchemy + SQLite + JWT + Passlib
Port: 9988
Run:  python main.py
Docs: http://localhost:9988/docs
"""

import os
import secrets
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from jose import jwt, JWTError
from passlib.context import CryptContext


# ============================================================
# CONFIG
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "foxpay.db"
SECRET_KEY = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 7
PORT = 9988
HOST = "0.0.0.0"

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


# ============================================================
# DATABASE
# ============================================================
engine = create_engine(
    f"sqlite:///{DB_FILE}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    email = Column(String(200), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    company = Column(String(200), default="")
    api_key = Column(String(100), unique=True, index=True)
    joined_at = Column(DateTime, default=utcnow)


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    tx_id = Column(String(32), unique=True, index=True)
    user_id = Column(Integer, index=True)
    customer = Column(String(120))
    email = Column(String(200))
    amount = Column(Float, default=0)
    fee = Column(Float, default=0)
    method = Column(String(32))
    status = Column(String(16), default="pending")
    date = Column(DateTime, default=utcnow)


class Invoice(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True)
    inv_id = Column(String(32), unique=True)
    user_id = Column(Integer, index=True)
    customer = Column(String(120))
    email = Column(String(200))
    amount = Column(Float, default=0)
    status = Column(String(16), default="draft")
    issue_date = Column(DateTime, default=utcnow)
    due_date = Column(DateTime)
    note = Column(Text, default="")


class PaymentLink(Base):
    __tablename__ = "links"
    id = Column(Integer, primary_key=True)
    link_id = Column(String(32), unique=True)
    user_id = Column(Integer, index=True)
    title = Column(String(120))
    amount = Column(Float, default=0)
    slug = Column(String(40), unique=True)
    clicks = Column(Integer, default=0)
    payments = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Merchant(Base):
    __tablename__ = "merchants"
    id = Column(Integer, primary_key=True)
    merchant_id = Column(String(32), unique=True)
    user_id = Column(Integer, index=True)
    name = Column(String(120))
    category = Column(String(64))
    status = Column(String(16), default="active")
    volume = Column(Float, default=0)
    joined = Column(DateTime, default=utcnow)


Base.metadata.create_all(bind=engine)


# ============================================================
# AUTH UTILS
# ============================================================
pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(raw: str) -> str:
    return pwd_ctx.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return pwd_ctx.verify(raw, hashed)
    except Exception:
        return False


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def new_api_key() -> str:
    return "fox_live_" + secrets.token_hex(24)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    token = auth[7:].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


# ============================================================
# SCHEMAS
# ============================================================
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    company: Optional[str] = ""


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class InvoiceIn(BaseModel):
    customer: str = Field(min_length=1)
    email: EmailStr
    amount: float = Field(gt=0)
    due_date: Optional[str] = None
    note: Optional[str] = ""


class LinkIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    amount: float = Field(gt=0)


class ProfileIn(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    company: Optional[str] = None


# ============================================================
# SERIALIZERS
# ============================================================
def user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "name": u.name,
        "email": u.email,
        "company": u.company,
        "apiKey": u.api_key,
        "joinedAt": iso(u.joined_at),
    }


def tx_dict(t: Transaction) -> dict:
    return {
        "id": t.tx_id,
        "customer": t.customer,
        "email": t.email,
        "amount": t.amount,
        "fee": t.fee,
        "method": t.method,
        "status": t.status,
        "date": iso(t.date),
    }


def inv_dict(i: Invoice) -> dict:
    return {
        "id": i.inv_id,
        "customer": i.customer,
        "email": i.email,
        "amount": i.amount,
        "status": i.status,
        "issueDate": iso(i.issue_date),
        "dueDate": iso(i.due_date),
        "note": i.note,
    }


def link_dict(l: PaymentLink) -> dict:
    return {
        "id": l.link_id,
        "title": l.title,
        "amount": l.amount,
        "slug": l.slug,
        "clicks": l.clicks,
        "payments": l.payments,
        "active": l.active,
        "createdAt": iso(l.created_at),
    }


def merchant_dict(m: Merchant) -> dict:
    return {
        "id": m.merchant_id,
        "name": m.name,
        "category": m.category,
        "status": m.status,
        "volume": m.volume,
        "joined": iso(m.joined),
    }


# ============================================================
# SEED
# ============================================================
def seed_for_user(db: Session, user: User):
    """Demo ma'lumotlarni yangi user uchun yaratish."""
    names = [
        "Aziz Karimov", "Malika Yusupova", "Jasur Toshmatov", "Dilnoza Aliyeva",
        "Bekzod Rahimov", "Nilufar Sattorova", "Sardor Ismoilov", "Gulnora Nazarova",
        "Farhod Yuldashev", "Zilola Kholmatova",
    ]
    methods = ["Uzcard", "Humo", "Payme", "Click", "Bank o'tkazma"]
    statuses = ["success"] * 4 + ["pending", "failed", "refunded"]
    now = utcnow()

    for i in range(48):
        name = random.choice(names)
        amount = random.randint(5, 500) * 1000
        db.add(Transaction(
            tx_id=f"TX-{100000 + i + user.id * 1000}",
            user_id=user.id,
            customer=name,
            email=name.lower().replace(" ", ".") + "@mail.uz",
            amount=amount,
            fee=round(amount * 0.015),
            method=random.choice(methods),
            status=random.choice(statuses),
            date=now - timedelta(days=random.randint(0, 30), seconds=random.randint(0, 86400)),
        ))

    for i in range(14):
        db.add(Invoice(
            inv_id=f"INV-{2000 + i + user.id * 100}",
            user_id=user.id,
            customer=random.choice(names),
            email=f"client{i}@company.uz",
            amount=random.randint(100, 3000) * 1000,
            status=random.choice(["paid", "sent", "draft", "overdue"]),
            issue_date=now - timedelta(days=random.randint(0, 20)),
            due_date=now + timedelta(days=random.randint(1, 30)),
            note="Xizmatlar uchun to'lov",
        ))

    titles = ["Konsultatsiya", "Dizayn xizmati", "Kurs to'lovi", "Mahsulot #1",
              "Mahsulot #2", "Landing page", "Logo dizayn", "Konsalting soat"]
    for i, t in enumerate(titles):
        db.add(PaymentLink(
            link_id=f"PL-{3000 + i + user.id * 100}",
            user_id=user.id,
            title=t,
            amount=random.randint(50, 800) * 1000,
            slug=f"fox-{secrets.token_hex(3)}",
            clicks=random.randint(10, 500),
            payments=random.randint(0, 40),
            active=random.random() > 0.2,
            created_at=now - timedelta(days=random.randint(0, 40)),
        ))

    shops = ["Chorsu Market", "Silk Road Coffee", "Tashkent Books",
             "Navoi Tech", "Samarkand Tour", "Bukhara Textile"]
    cats = ["Retail", "Food", "Books", "Electronics", "Tourism", "Textile"]
    for i, s in enumerate(shops):
        db.add(Merchant(
            merchant_id=f"M-{400 + i + user.id * 10}",
            user_id=user.id,
            name=s,
            category=cats[i],
            status="pending" if i % 4 == 3 else "active",
            volume=random.randint(10, 500) * 1_000_000,
            joined=now - timedelta(days=random.randint(30, 500)),
        ))

    db.commit()


def ensure_demo_user(db: Session):
    demo = db.query(User).filter(User.email == "demo@foxpay.uz").first()
    if demo:
        return
    demo = User(
        name="Aziz Karimov",
        email="demo@foxpay.uz",
        password_hash=hash_password("demo123"),
        company="FoxPay Demo",
        api_key=new_api_key(),
        joined_at=utcnow(),
    )
    db.add(demo)
    db.commit()
    db.refresh(demo)
    seed_for_user(db, demo)


# ============================================================
# APP
# ============================================================
app = FastAPI(
    title="FoxPay API",
    description="FoxPay to'lov platformasi uchun backend",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    db = SessionLocal()
    try:
        ensure_demo_user(db)
    finally:
        db.close()
    print(f"\n  FoxPay API  →  http://localhost:{PORT}")
    print(f"  Docs        →  http://localhost:{PORT}/docs")
    print(f"  Demo login  →  demo@foxpay.uz / demo123\n")


# ---------- Health ----------
@app.get("/api/health")
def health():
    return {"ok": True, "service": "foxpay", "port": PORT, "time": iso(utcnow())}


# ---------- Auth ----------
@app.post("/api/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    exists = db.query(User).filter(User.email == body.email.lower()).first()
    if exists:
        raise HTTPException(400, "Bu email allaqachon ro'yxatdan o'tgan")
    user = User(
        name=body.name.strip(),
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        company=(body.company or "").strip(),
        api_key=new_api_key(),
        joined_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    seed_for_user(db, user)
    return {"token": create_token(user.id), "user": user_dict(user)}


@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Email yoki parol noto'g'ri")
    return {"token": create_token(user.id), "user": user_dict(user)}


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"user": user_dict(user)}


# ---------- Bootstrap (barcha ma'lumot bir so'rovda) ----------
@app.get("/api/bootstrap")
def bootstrap(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    txs = db.query(Transaction).filter(Transaction.user_id == user.id).order_by(Transaction.date.desc()).all()
    invs = db.query(Invoice).filter(Invoice.user_id == user.id).order_by(Invoice.issue_date.desc()).all()
    links = db.query(PaymentLink).filter(PaymentLink.user_id == user.id).order_by(PaymentLink.created_at.desc()).all()
    mers = db.query(Merchant).filter(Merchant.user_id == user.id).order_by(Merchant.joined.desc()).all()
    return {
        "user": user_dict(user),
        "transactions": [tx_dict(t) for t in txs],
        "invoices": [inv_dict(i) for i in invs],
        "links": [link_dict(l) for l in links],
        "merchants": [merchant_dict(m) for m in mers],
    }


# ---------- Dashboard ----------
@app.get("/api/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    txs = db.query(Transaction).filter(Transaction.user_id == user.id).all()
    success = [t for t in txs if t.status == "success"]
    total_volume = sum(t.amount for t in success)
    total_fees = sum(t.fee for t in success)
    pending = len([t for t in txs if t.status == "pending"])
    success_rate = round(len(success) / len(txs) * 100) if txs else 0

    # Oxirgi 12 hafta bo'yicha guruh
    buckets = [0.0] * 12
    now = utcnow()
    for t in success:
        delta_days = (now - t.date).days
        week = delta_days // 7
        if 0 <= week < 12:
            buckets[11 - week] += t.amount

    methods = {}
    for t in txs:
        methods[t.method] = methods.get(t.method, 0) + 1

    return {
        "totalVolume": total_volume,
        "totalFees": total_fees,
        "pending": pending,
        "successRate": success_rate,
        "revenueSeries": buckets,
        "methodDistribution": methods,
        "recentTransactions": [tx_dict(t) for t in
            sorted(txs, key=lambda x: x.date, reverse=True)[:6]],
    }


# ---------- Transactions ----------
@app.get("/api/transactions")
def list_transactions(
    q: Optional[str] = Query(None),
    status: Optional[str] = Query(None, alias="status"),
    method: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per: int = Query(10, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Transaction).filter(Transaction.user_id == user.id)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (Transaction.customer.ilike(like)) |
            (Transaction.tx_id.ilike(like)) |
            (Transaction.email.ilike(like))
        )
    if status and status != "all":
        query = query.filter(Transaction.status == status)
    if method and method != "all":
        query = query.filter(Transaction.method == method)

    total = query.count()
    items = query.order_by(Transaction.date.desc()).offset((page - 1) * per).limit(per).all()
    return {
        "items": [tx_dict(t) for t in items],
        "total": total,
        "page": page,
        "per": per,
        "pages": max(1, (total + per - 1) // per),
    }


@app.get("/api/transactions/{tx_id}")
def get_transaction(tx_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Transaction).filter(Transaction.tx_id == tx_id, Transaction.user_id == user.id).first()
    if not t:
        raise HTTPException(404, "Tranzaksiya topilmadi")
    return tx_dict(t)


# ---------- Invoices ----------
@app.get("/api/invoices")
def list_invoices(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(Invoice).filter(Invoice.user_id == user.id).order_by(Invoice.issue_date.desc()).all()
    return {"items": [inv_dict(i) for i in items], "total": len(items)}


@app.post("/api/invoices", status_code=201)
def create_invoice(body: InvoiceIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    due = utcnow() + timedelta(days=14)
    if body.due_date:
        try:
            due = datetime.fromisoformat(body.due_date)
        except ValueError:
            raise HTTPException(400, "due_date noto'g'ri formatda")
    inv = Invoice(
        inv_id=f"INV-{2000 + user.id * 100 + int(utcnow().timestamp()) % 10000}",
        user_id=user.id,
        customer=body.customer,
        email=body.email,
        amount=body.amount,
        status="sent",
        issue_date=utcnow(),
        due_date=due,
        note=body.note or "",
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv_dict(inv)


@app.delete("/api/invoices/{inv_id}", status_code=204)
def delete_invoice(inv_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    inv = db.query(Invoice).filter(Invoice.inv_id == inv_id, Invoice.user_id == user.id).first()
    if not inv:
        raise HTTPException(404, "Invoice topilmadi")
    db.delete(inv)
    db.commit()


# ---------- Payment Links ----------
@app.get("/api/links")
def list_links(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(PaymentLink).filter(PaymentLink.user_id == user.id).order_by(PaymentLink.created_at.desc()).all()
    return {"items": [link_dict(l) for l in items], "total": len(items)}


@app.post("/api/links", status_code=201)
def create_link(body: LinkIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    slug = "fox-" + secrets.token_hex(3)
    while db.query(PaymentLink).filter(PaymentLink.slug == slug).first():
        slug = "fox-" + secrets.token_hex(3)
    link = PaymentLink(
        link_id=f"PL-{3000 + user.id * 100 + int(utcnow().timestamp()) % 10000}",
        user_id=user.id,
        title=body.title,
        amount=body.amount,
        slug=slug,
        active=True,
        created_at=utcnow(),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link_dict(link)


@app.patch("/api/links/{link_id}/toggle")
def toggle_link(link_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    link = db.query(PaymentLink).filter(PaymentLink.link_id == link_id, PaymentLink.user_id == user.id).first()
    if not link:
        raise HTTPException(404, "Link topilmadi")
    link.active = not link.active
    db.commit()
    db.refresh(link)
    return link_dict(link)


@app.delete("/api/links/{link_id}", status_code=204)
def delete_link(link_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    link = db.query(PaymentLink).filter(PaymentLink.link_id == link_id, PaymentLink.user_id == user.id).first()
    if not link:
        raise HTTPException(404, "Link topilmadi")
    db.delete(link)
    db.commit()


# ---------- Merchants ----------
@app.get("/api/merchants")
def list_merchants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(Merchant).filter(Merchant.user_id == user.id).order_by(Merchant.joined.desc()).all()
    return {"items": [merchant_dict(m) for m in items], "total": len(items)}


# ---------- Settings ----------
@app.get("/api/settings")
def get_settings(user: User = Depends(get_current_user)):
    return user_dict(user)


@app.put("/api/settings")
def update_settings(body: ProfileIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if body.email and body.email.lower() != user.email:
        clash = db.query(User).filter(User.email == body.email.lower(), User.id != user.id).first()
        if clash:
            raise HTTPException(400, "Bu email band")
        user.email = body.email.lower()
    if body.name:
        user.name = body.name.strip()
    if body.company is not None:
        user.company = body.company.strip()
    db.commit()
    db.refresh(user)
    return user_dict(user)


@app.post("/api/settings/regenerate-key")
def regen_api_key(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.api_key = new_api_key()
    db.commit()
    db.refresh(user)
    return {"apiKey": user.api_key}


# ============================================================
# SERVE FRONTEND
# ============================================================
INDEX_HTML = BASE_DIR / "index.html"


@app.get("/")
def serve_index():
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML)
    return JSONResponse(
        {"message": "FoxPay API ishlamoqda. index.html topilmadi."},
        status_code=200,
    )


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    # API yo'llarini ushlamaymiz
    if full_path.startswith("api/"):
        raise HTTPException(404, "API endpoint topilmadi")
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML)
    raise HTTPException(404, "Fayl topilmadi")


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print(f"\n🦊  FoxPay backend ishga tushmoqda → http://localhost:{PORT}\n")
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=True,
        log_level="info",
    )