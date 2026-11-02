"""
FoxPay — lightweight backend with Google verification support.
Render: uvicorn main:app --host 0.0.0.0 --port $PORT
"""
import os, secrets, hashlib, hmac
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, BigInteger, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, declarative_base

# ═══════ CONFIG ═══════
BASE = Path(__file__).parent
PORT = int(os.getenv("PORT", "9988"))
SECRET = os.getenv("FOXPAY_SECRET") or secrets.token_urlsafe(48)
DB_PATH = os.getenv("FOXPAY_DB") or ("/tmp/foxpay.db" if os.getenv("RENDER") else str(BASE / "foxpay.db"))

# ═══════ DB ═══════
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def utcnow(): return datetime.utcnow()

# ═══════ MODELS ═══════
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utcnow)

class Ledger(Base):
    __tablename__ = "ledger"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    direction = Column(String(8))
    amount_tiyin = Column(BigInteger)
    ref_type = Column(String(32), default="")
    ref_id = Column(String(64), default="")
    created_at = Column(DateTime, default=utcnow)

class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    transfer_id = Column(String(32), unique=True)
    from_user_id = Column(Integer, index=True)
    to_user_id = Column(Integer, index=True)
    amount_tiyin = Column(BigInteger)
    fee_tiyin = Column(BigInteger, default=0)
    status = Column(String(16), default="succeeded")
    created_at = Column(DateTime, default=utcnow)

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    prefix = Column(String(20))
    key_hash = Column(String(64))
    label = Column(String(64), default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

Base.metadata.create_all(bind=engine)

# ═══════ SECURITY ═══════
def hash_pw(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100_000)
    return f"{salt.hex()}${dk.hex()}"

def verify_pw(pw, stored):
    try:
        salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 100_000)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except: return False

def make_token(uid):
    return jwt.encode({"sub": str(uid), "exp": datetime.utcnow() + timedelta(days=7)}, SECRET, algorithm="HS256")

def get_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    try:
        payload = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
        if not user: raise HTTPException(401, "User not found")
        return user
    except HTTPException: raise
    except: raise HTTPException(401, "Invalid token")

def balance(db, uid):
    rows = db.query(Ledger).filter(Ledger.user_id == uid).all()
    return sum(r.amount_tiyin for r in rows if r.direction == "credit") - \
           sum(r.amount_tiyin for r in rows if r.direction == "debit")

def post_ledger(db, uid, direction, amount, ref_type="", ref_id=""):
    db.add(Ledger(user_id=uid, direction=direction, amount_tiyin=amount, ref_type=ref_type, ref_id=ref_id))

# ═══════ SCHEMAS ═══════
class RegisterIn(BaseModel):
    name: str = Field(min_length=2)
    email: str
    password: str = Field(min_length=6)

class LoginIn(BaseModel):
    email: str
    password: str

class TransferIn(BaseModel):
    to_email: str
    amount_tiyin: int = Field(gt=0)
    note: str = ""

class FundIn(BaseModel):
    amount_tiyin: int = Field(gt=0)

# ═══════ APP ═══════
app = FastAPI(title="FoxPay API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ═══════════════════════════════════════════════════════════
# GOOGLE VERIFICATION — catch-all'dan OLDIN turishi SHART
# ═══════════════════════════════════════════════════════════
@app.get("/google{filename}.html")
def google_verify(filename: str):
    """Google Search Console HTML verification file."""
    path = BASE / f"google{filename}.html"
    if path.exists():
        return PlainTextResponse(
            f"google-site-verification: google{filename}.html",
            media_type="text/html"
        )
    raise HTTPException(404, "Not found")

# Alternative: any file starting with "google" and ending with ".html" in root
@app.get("/{fname}")
def serve_root_file(fname: str):
    """Serve google*.html, robots.txt, sitemap.xml, manifest.webmanifest."""
    if fname.startswith("google") and fname.endswith(".html"):
        return PlainTextResponse(f"google-site-verification: {fname}", media_type="text/html")
    if fname == "robots.txt":
        f = BASE / "robots.txt"
        if f.exists(): return FileResponse(f, media_type="text/plain")
        return PlainTextResponse("User-agent: *\nAllow: /\n\nSitemap: https://foxpay.uz/sitemap.xml")
    if fname == "sitemap.xml":
        f = BASE / "sitemap.xml"
        if f.exists(): return FileResponse(f, media_type="application/xml")
        return PlainTextResponse('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://foxpay.uz/</loc><priority>1.0</priority></url></urlset>', media_type="application/xml")
    if fname == "manifest.webmanifest":
        f = BASE / "manifest.webmanifest"
        if f.exists(): return FileResponse(f, media_type="application/manifest+json")
        raise HTTPException(404)
    raise HTTPException(404)

# ═══════ HEALTH ═══════
@app.get("/api/health")
def health():
    return {"ok": True, "python": __import__("sys").version.split()[0], "db": DB_PATH}

# ═══════ AUTH ═══════
@app.post("/api/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if "@" not in email: raise HTTPException(400, "Invalid email")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Email already registered")
    u = User(email=email, name=body.name.strip(), password_hash=hash_pw(body.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"token": make_token(u.id), "user": {"id": u.id, "name": u.name, "email": u.email}}

@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if not u or not verify_pw(body.password, u.password_hash):
        raise HTTPException(401, "Email or password incorrect")
    return {"token": make_token(u.id), "user": {"id": u.id, "name": u.name, "email": u.email}}

@app.get("/api/auth/me")
def me(u: User = Depends(get_user)):
    return {"id": u.id, "name": u.name, "email": u.email}

# ═══════ WALLET ═══════
@app.get("/api/wallet")
def get_wallet(u: User = Depends(get_user), db: Session = Depends(get_db)):
    b = balance(db, u.id)
    return {"balance_tiyin": b, "balance_uzs": b / 100}

@app.get("/api/wallet/ledger")
def get_ledger(u: User = Depends(get_user), db: Session = Depends(get_db)):
    rows = db.query(Ledger).filter(Ledger.user_id == u.id).order_by(Ledger.created_at.desc()).limit(50).all()
    return [{"direction": r.direction, "amount_tiyin": r.amount_tiyin,
             "ref_type": r.ref_type, "created_at": r.created_at.isoformat() + "Z"} for r in rows]

@app.post("/api/dev/fund")
def fund(body: FundIn, u: User = Depends(get_user), db: Session = Depends(get_db)):
    if os.getenv("FOXPAY_DEV", "1") != "1":
        raise HTTPException(403, "Dev mode disabled")
    post_ledger(db, u.id, "credit", body.amount_tiyin, "deposit", "dev_" + secrets.token_hex(4))
    db.commit()
    return {"ok": True, "amount_tiyin": body.amount_tiyin}

# ═══════ P2P ═══════
@app.post("/api/p2p/transfers")
def transfer(body: TransferIn, u: User = Depends(get_user), db: Session = Depends(get_db)):
    recipient = db.query(User).filter(User.email == body.to_email.strip().lower()).first()
    if not recipient: raise HTTPException(404, "Recipient not found")
    if recipient.id == u.id: raise HTTPException(400, "Cannot send to yourself")
    fee = body.amount_tiyin * 150 // 10000
    total = body.amount_tiyin + fee
    if balance(db, u.id) < total:
        raise HTTPException(400, f"Insufficient balance. Need {total/100:.2f}, have {balance(db, u.id)/100:.2f}")
    tid = "tr_" + secrets.token_hex(8)
    post_ledger(db, u.id, "debit", total, "p2p", tid)
    post_ledger(db, recipient.id, "credit", body.amount_tiyin, "p2p", tid)
    db.add(Transfer(transfer_id=tid, from_user_id=u.id, to_user_id=recipient.id,
                    amount_tiyin=body.amount_tiyin, fee_tiyin=fee, status="succeeded"))
    db.commit()
    return {"transfer_id": tid, "amount_tiyin": body.amount_tiyin, "fee_tiyin": fee, "status": "succeeded"}

@app.get("/api/p2p/transfers")
def list_transfers(u: User = Depends(get_user), db: Session = Depends(get_db)):
    rows = db.query(Transfer).filter(
        (Transfer.from_user_id == u.id) | (Transfer.to_user_id == u.id)
    ).order_by(Transfer.created_at.desc()).limit(50).all()
    return [{"transfer_id": r.transfer_id, "from_user_id": r.from_user_id,
             "to_user_id": r.to_user_id, "amount_tiyin": r.amount_tiyin,
             "fee_tiyin": r.fee_tiyin, "status": r.status,
             "created_at": r.created_at.isoformat() + "Z"} for r in rows]

# ═══════ API KEYS ═══════
@app.get("/api/keys")
def list_keys(u: User = Depends(get_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.user_id == u.id).all()
    return [{"id": k.id, "prefix": k.prefix, "label": k.label, "is_active": k.is_active} for k in rows]

@app.post("/api/keys")
def create_key(u: User = Depends(get_user), db: Session = Depends(get_db)):
    full = "fox_live_" + secrets.token_hex(24)
    k = ApiKey(user_id=u.id, prefix=full[:20], key_hash=hashlib.sha256(full.encode()).hexdigest())
    db.add(k); db.commit(); db.refresh(k)
    return {"id": k.id, "prefix": k.prefix, "label": k.label, "is_active": True, "full_key": full}

@app.delete("/api/keys/{kid}")
def revoke_key(kid: int, u: User = Depends(get_user), db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(ApiKey.id == kid, ApiKey.user_id == u.id).first()
    if not k: raise HTTPException(404, "Not found")
    k.is_active = False; db.commit()
    return {"ok": True}

# ═══════ INDEX (catch-all — ENG OXIRIDA) ═══════
@app.get("/")
def index():
    f = BASE / "index.html"
    if f.exists(): return FileResponse(f)
    return JSONResponse({"message": "FoxPay API", "docs": "/docs"})

@app.get("/{path:path}")
def catch_all(path: str):
    if path.startswith("api/"): raise HTTPException(404, "API endpoint not found")
    f = BASE / "index.html"
    if f.exists(): return FileResponse(f)
    raise HTTPException(404)

# ═══════ ENTRYPOINT ═══════
if __name__ == "__main__":
    import uvicorn
    print(f"\n🦊 FoxPay → http://localhost:{PORT}")
    print(f"   DB: {DB_PATH}\n")
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
