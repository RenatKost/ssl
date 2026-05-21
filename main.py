"""
TGPars License Server
Minimal FastAPI service for managing license keys.
Deploy on Railway (free tier) or any VPS.

Plans: trial | starter | pro | enterprise
"""
from __future__ import annotations

import hashlib
import hashlib as _hashlib_pay
import hmac as _hmac_mod
import hmac as _hmac_pay
import json as _json
import os as _os
from pathlib import Path as _Path
import json
import logging
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import uuid as _uuid
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("license-server")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./licenses.db")
ADMIN_TOKEN  = os.environ.get("ADMIN_TOKEN", "changeme-admin-secret")
HMAC_SECRET  = os.environ.get("HMAC_SECRET", "").encode()

# ── Payment / email config ────────────────────────────────────────────────────
RESEND_API_KEY            = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL                = os.environ.get("FROM_EMAIL", "noreply@traffic-os.com")
WEBSITE_URL               = os.environ.get("WEBSITE_URL", "https://traffic-os.com")
STRIPE_SECRET_KEY         = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET     = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
NOWPAYMENTS_API_KEY    = os.environ.get("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET", "")

# Stripe Price IDs — set in Railway env vars after creating products in Stripe Dashboard
STRIPE_PRICES: dict[str, str] = {
    # New plans (Phase 1)
    "telegram_monthly":   os.environ.get("STRIPE_PRICE_TG_MONTHLY", ""),
    "telegram_halfyear":  os.environ.get("STRIPE_PRICE_TG_HALFYEAR", ""),
    # Legacy plans kept for existing customers
    "starter_monthly":    os.environ.get("STRIPE_PRICE_STARTER_MONTHLY", ""),
    "starter_yearly":     os.environ.get("STRIPE_PRICE_STARTER_YEARLY", ""),
    "pro_monthly":        os.environ.get("STRIPE_PRICE_PRO_MONTHLY", ""),
    "pro_yearly":         os.environ.get("STRIPE_PRICE_PRO_YEARLY", ""),
    "enterprise_monthly": os.environ.get("STRIPE_PRICE_ENT_MONTHLY", ""),
    "enterprise_yearly":  os.environ.get("STRIPE_PRICE_ENT_YEARLY", ""),
}

PLAN_PERIODS: dict[str, int] = {"monthly": 30, "halfyear": 182, "yearly": 365}

_PLAN_PRICES_USD: dict[str, float] = {
    "telegram_monthly":  9.99, "telegram_halfyear": 49.99,
    "starter_monthly": 19,  "starter_yearly": 149,
    "pro_monthly":     39,  "pro_yearly":     299,
    "enterprise_monthly": 99, "enterprise_yearly": 799,
}


def _sign_response(valid: bool, plan: str, expires_at, server_time: str) -> str:
    """Sign the key fields of a valid response so the client can detect tampering."""
    if not HMAC_SECRET:
        return ""
    payload = f"{valid}|{plan or ''}|{expires_at or ''}|{server_time}".encode()
    return _hmac_mod.new(HMAC_SECRET, payload, hashlib.sha256).hexdigest()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    plan = Column(String(32), nullable=False, default="starter")  # trial|telegram_monthly|telegram_halfyear|starter|pro|enterprise
    # JSON array of up to max_machines machine_id strings
    machine_ids = Column(Text, nullable=False, default="[]")
    max_machines = Column(Integer, nullable=False, default=2)
    expires_at = Column(DateTime, nullable=True)       # NULL = never expires
    trial_days = Column(Integer, nullable=True)        # legacy: only for old trial plan
    activated_at = Column(DateTime, nullable=True)     # first activation timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.utcnow())
    notes = Column(Text, nullable=True)
    # JSON dict: {machine_id: {components: {...}, last_seen: "ISO"}}
    hwid_data = Column(Text, nullable=False, default="{}")


class TrialMachine(Base):
    __tablename__ = "trial_machines"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.utcnow())


class Payment(Base):
    __tablename__ = "payments"

    id           = Column(Integer, primary_key=True)
    order_id     = Column(String(64), unique=True, index=True, nullable=False)
    method       = Column(String(16), nullable=False)   # stripe | nowpayments
    plan         = Column(String(32), nullable=False)
    period       = Column(String(16), nullable=False)
    email        = Column(String(255), nullable=False)
    amount_usd   = Column(Float, nullable=False)
    currency     = Column(String(16), nullable=True)    # card | USDT | BTC | …
    external_id  = Column(String(128), nullable=True)   # Stripe session_id | NP invoice_id
    status       = Column(String(16), nullable=False, default="pending")
    license_key  = Column(String(64), nullable=True)
    created_at   = Column(DateTime, nullable=False, default=lambda: datetime.utcnow())
    completed_at = Column(DateTime, nullable=True)


Base.metadata.create_all(bind=engine)


def _ensure_columns() -> None:
    """Add columns introduced after initial deploy (safe to run every startup)."""
    with engine.connect() as conn:
        for col_sql in ["hwid_data TEXT DEFAULT '{}'"]:
            col_name = col_sql.split()[0]
            try:
                conn.execute(text(f"ALTER TABLE licenses ADD COLUMN {col_sql}"))
                conn.commit()
            except Exception:
                pass  # column already exists


_ensure_columns()


# ---------- Feature flags per plan ----------

PLAN_FEATURES: dict[str, dict] = {
    # Active plans
    "trial": {
        "max_accounts": 5,
        "max_messages_day": 100,
        "instagram": False,
        "twitter": False,
        "video": False,
    },
    "telegram_monthly": {
        "max_accounts": -1,
        "max_messages_day": -1,
        "instagram": True,
        "twitter": True,
        "video": True,
    },
    "telegram_halfyear": {
        "max_accounts": -1,
        "max_messages_day": -1,
        "instagram": True,
        "twitter": True,
        "video": True,
    },
    # Legacy plans kept for existing customers
    "starter": {
        "max_accounts": 50,
        "max_messages_day": 1500,
        "instagram": False,
        "twitter": False,
        "video": False,
    },
    "pro": {
        "max_accounts": 200,
        "max_messages_day": -1,
        "instagram": True,
        "twitter": False,
        "video": True,
    },
    "enterprise": {
        "max_accounts": -1,
        "max_messages_day": -1,
        "instagram": True,
        "twitter": True,
        "video": True,
    },
}


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _require_admin(x_admin_token: str = Header(...)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def _generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    segments = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(segments)


# ---------- Pydantic models ----------

# Minimum client version allowed to validate (Phase 7 — version locking)
# Bump this to block clients older than a given version.
MIN_VERSION = "1.0.0"


def _version_gte(a: str, b: str) -> bool:
    """Return True if version a >= b."""
    try:
        return tuple(int(x) for x in a.split(".")) >= tuple(int(x) for x in b.split("."))
    except Exception:
        return True


def _hwid_match_score(stored: dict, incoming: dict) -> int:
    """Count matching non-empty component hashes. Max 5 (mac/hostname/machine_guid/disk/cpu)."""
    score = 0
    for key in ("mac", "hostname", "machine_guid", "disk", "cpu"):
        sv, iv = stored.get(key, ""), incoming.get(key, "")
        if sv and iv and sv == iv:
            score += 1
    return score


class ValidateRequest(BaseModel):
    key: str
    machine_id: str
    version: str = ""
    hwid_components: Optional[dict] = None


class ActivateRequest(BaseModel):
    key: str
    machine_id: str
    hwid_components: Optional[dict] = None


class DeactivateRequest(BaseModel):
    key: str
    machine_id: str


class TransferRequest(BaseModel):
    key: str
    old_machine_id: str
    new_machine_id: str
    hwid_components: Optional[dict] = None


class GenerateRequest(BaseModel):
    plan: str = "starter"
    expires_days: Optional[int] = None   # None = never expires
    max_machines: int = 2
    notes: Optional[str] = None


# ---------- App ----------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="TGPars License Server", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/validate")
@limiter.limit("60/minute")
def validate(request: Request, req: ValidateRequest = Body(...), db: Session = Depends(_get_db)):
    """Called by TGPars app on startup and every 30 min."""
    now = datetime.utcnow()
    server_time = now.isoformat()

    if req.version and not _version_gte(req.version, MIN_VERSION):
        return {"valid": False, "reason": "version_too_old", "min_version": MIN_VERSION, "server_time": server_time}

    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        return {"valid": False, "reason": "key_not_found", "server_time": server_time}

    machines: list[str] = json.loads(lic.machine_ids)
    hwid_data: dict = json.loads(lic.hwid_data or "{}")

    machine_allowed = False
    if not machines:
        return {"valid": False, "reason": "not_activated", "server_time": server_time}

    if req.machine_id in machines:
        machine_allowed = True
    elif req.hwid_components:
        for mid, mdata in list(hwid_data.items()):
            stored_comp = mdata.get("components", {})
            if _hwid_match_score(stored_comp, req.hwid_components) >= 2:
                log.info("Fuzzy HWID match: old=%s new=%s", mid, req.machine_id)
                machines[machines.index(mid)] = req.machine_id
                entry = hwid_data.pop(mid)
                entry["components"] = req.hwid_components
                entry["last_seen"] = server_time
                hwid_data[req.machine_id] = entry
                lic.machine_ids = json.dumps(machines)
                lic.hwid_data = json.dumps(hwid_data)
                db.commit()
                machine_allowed = True
                break

    if not machine_allowed:
        return {"valid": False, "reason": "machine_not_registered", "server_time": server_time}

    entry = hwid_data.setdefault(req.machine_id, {})
    entry["last_seen"] = server_time
    if req.hwid_components:
        entry["components"] = req.hwid_components
    lic.hwid_data = json.dumps(hwid_data)
    db.commit()

    expires_at = lic.expires_at
    if lic.plan == "trial" and lic.trial_days:
        expires_at = (lic.activated_at + timedelta(days=lic.trial_days)) if lic.activated_at else None

    if expires_at and now > expires_at:
        return {"valid": False, "reason": "expired", "server_time": server_time}

    features = PLAN_FEATURES.get(lic.plan, PLAN_FEATURES["starter"])
    days_left = max(0, (expires_at - now).days) if expires_at else None

    expires_at_str = expires_at.isoformat() if expires_at else None
    return {
        "valid": True,
        "plan": lic.plan,
        "features": features,
        "expires_at": expires_at_str,
        "days_left": days_left,
        "server_time": server_time,
        "__sig": _sign_response(True, lic.plan, expires_at_str, server_time),
    }


@app.post("/activate")
@limiter.limit("5/minute")
def activate(request: Request, req: ActivateRequest = Body(...), db: Session = Depends(_get_db)):
    """Bind machine_id to license key. Returns error if machine limit reached."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")

    now = datetime.utcnow()
    server_time = now.isoformat()
    machines: list[str] = json.loads(lic.machine_ids)
    hwid_data: dict = json.loads(lic.hwid_data or "{}")

    if req.machine_id not in machines:
        if len(machines) >= lic.max_machines:
            raise HTTPException(
                status_code=403,
                detail=f"Machine limit reached ({lic.max_machines}). Deactivate another machine first.",
            )
        machines.append(req.machine_id)
        lic.machine_ids = json.dumps(machines)
        if not lic.activated_at:
            lic.activated_at = now

    hwid_data[req.machine_id] = {
        "components": req.hwid_components or {},
        "last_seen": server_time,
    }
    lic.hwid_data = json.dumps(hwid_data)
    db.commit()

    expires_at = lic.expires_at
    if lic.plan == "trial" and lic.trial_days and lic.activated_at:
        expires_at = lic.activated_at + timedelta(days=lic.trial_days)

    features = PLAN_FEATURES.get(lic.plan, PLAN_FEATURES["starter"])
    days_left = max(0, (expires_at - now).days) if expires_at else None
    expires_at_str = expires_at.isoformat() if expires_at else None

    return {
        "valid": True,
        "plan": lic.plan,
        "features": features,
        "expires_at": expires_at_str,
        "days_left": days_left,
        "server_time": server_time,
        "__sig": _sign_response(True, lic.plan, expires_at_str, server_time),
    }


class TrialRequest(BaseModel):
    machine_id: str
    hwid_components: Optional[dict] = None


@app.post("/trial")
@limiter.limit("3/minute")
def create_trial(request: Request, req: TrialRequest = Body(...), db: Session = Depends(_get_db)):
    """Create a 24-hour trial key. One per machine_id."""
    if db.query(TrialMachine).filter(TrialMachine.machine_id == req.machine_id).first():
        raise HTTPException(status_code=409, detail="trial_already_used")

    now = datetime.utcnow()
    key = _generate_key()
    expires_at = now + timedelta(hours=24)

    lic = License(
        key=key,
        plan="trial",
        machine_ids=json.dumps([req.machine_id]),
        max_machines=1,
        expires_at=expires_at,
        activated_at=now,
        notes=f"trial:{req.machine_id}",
    )
    if req.hwid_components:
        lic.hwid_data = json.dumps({
            req.machine_id: {"components": req.hwid_components, "last_seen": now.isoformat()}
        })
    db.add(lic)
    db.add(TrialMachine(machine_id=req.machine_id))
    db.commit()
    db.refresh(lic)

    server_time = now.isoformat()
    expires_at_str = expires_at.isoformat()
    features = PLAN_FEATURES.get("trial", {})
    return {
        "key": key,
        "valid": True,
        "plan": "trial",
        "features": features,
        "expires_at": expires_at_str,
        "hours_left": 24,
        "days_left": 0,
        "server_time": server_time,
        "__sig": _sign_response(True, "trial", expires_at_str, server_time),
    }


@app.post("/transfer")
def transfer_machine(req: TransferRequest, db: Session = Depends(_get_db)):
    """Self-service machine transfer. Old machine slot is freed and replaced by new one."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")

    machines: list[str] = json.loads(lic.machine_ids)
    hwid_data: dict = json.loads(lic.hwid_data or "{}")

    if req.old_machine_id not in machines:
        raise HTTPException(status_code=404, detail="old_machine_not_registered")

    machines[machines.index(req.old_machine_id)] = req.new_machine_id
    old_entry = hwid_data.pop(req.old_machine_id, {})
    old_entry["components"] = req.hwid_components or {}
    old_entry["last_seen"] = datetime.utcnow().isoformat()
    hwid_data[req.new_machine_id] = old_entry
    lic.machine_ids = json.dumps(machines)
    lic.hwid_data = json.dumps(hwid_data)
    db.commit()
    return {"ok": True, "machine_id": req.new_machine_id}


@app.post("/deactivate")
def deactivate(req: DeactivateRequest, db: Session = Depends(_get_db)):
    """Free up a machine slot (e.g. when migrating to new VPS)."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")

    machines: list[str] = json.loads(lic.machine_ids)
    hwid_data: dict = json.loads(lic.hwid_data or "{}")
    if req.machine_id in machines:
        machines.remove(req.machine_id)
        hwid_data.pop(req.machine_id, None)
        lic.machine_ids = json.dumps(machines)
        lic.hwid_data = json.dumps(hwid_data)
        db.commit()

    return {"ok": True, "machines_left": len(machines)}


# ---------- Admin endpoints ----------

@app.get("/admin/licenses", dependencies=[Depends(_require_admin)])
def list_licenses(db: Session = Depends(_get_db)):
    licenses = db.query(License).order_by(License.created_at.desc()).all()
    result = []
    for lic in licenses:
        machines = json.loads(lic.machine_ids)
        now = datetime.utcnow()
        expires_at = lic.expires_at
        if lic.plan == "trial" and lic.trial_days and lic.activated_at:
            expires_at = lic.activated_at + timedelta(days=lic.trial_days)
        result.append({
            "id": lic.id,
            "key": lic.key,
            "plan": lic.plan,
            "machines": machines,
            "max_machines": lic.max_machines,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "activated_at": lic.activated_at.isoformat() if lic.activated_at else None,
            "created_at": lic.created_at.isoformat(),
            "notes": lic.notes,
            "active": not (expires_at and now > expires_at),
            "last_seen": {
                mid: mdata.get("last_seen")
                for mid, mdata in json.loads(lic.hwid_data or "{}").items()
            },
        })
    return result


@app.post("/admin/generate", dependencies=[Depends(_require_admin)])
def generate_license(req: GenerateRequest, db: Session = Depends(_get_db)):
    if req.plan not in PLAN_FEATURES:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {req.plan}")

    key = _generate_key()
    expires_at = None
    if req.expires_days:
        expires_at = datetime.utcnow() + timedelta(days=req.expires_days)

    trial_days = 7 if req.plan == "trial" else None

    lic = License(
        key=key,
        plan=req.plan,
        machine_ids="[]",
        max_machines=req.max_machines,
        expires_at=expires_at,
        trial_days=trial_days,
        notes=req.notes,
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)

    return {
        "key": key,
        "plan": lic.plan,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "max_machines": lic.max_machines,
    }


@app.delete("/admin/licenses/{key}", dependencies=[Depends(_require_admin)])
def delete_license(key: str, db: Session = Depends(_get_db)):
    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="not_found")
    db.delete(lic)
    db.commit()
    return {"ok": True}


@app.get("/admin/payments", dependencies=[Depends(_require_admin)])
def list_payments(db: Session = Depends(_get_db)):
    payments = db.query(Payment).order_by(Payment.created_at.desc()).limit(200).all()
    return [
        {
            "id": p.id,
            "order_id": p.order_id,
            "method": p.method,
            "plan": p.plan,
            "period": p.period,
            "email": p.email,
            "amount_usd": p.amount_usd,
            "currency": p.currency,
            "external_id": p.external_id,
            "status": p.status,
            "license_key": p.license_key,
            "created_at": p.created_at.isoformat(),
            "completed_at": p.completed_at.isoformat() if p.completed_at else None,
        }
        for p in payments
    ]


# ── Email helper ──────────────────────────────────────────────────────────────

async def _send_license_email(email: str, key: str, plan: str, expires_at) -> bool:
    if not RESEND_API_KEY:
        log.warning("RESEND_API_KEY not set — skipping email to %s", email)
        return False
    expires_str = expires_at.strftime("%d %B %Y") if expires_at else "Never"
    cabinet_url  = f"{WEBSITE_URL}/cabinet?key={key}"
    download_url = _MANIFEST["download_url"]
    body_html = f"""
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a2e">
  <h2 style="margin-bottom:4px">Your TrafficOS License 🎉</h2>
  <p style="color:#6b7280">Thank you for your purchase!</p>
  <div style="background:#f4f4f8;border-radius:10px;padding:20px 24px;margin:20px 0;
              font-size:24px;font-weight:700;letter-spacing:3px;text-align:center;
              color:#4f46e5">{key}</div>
  <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
    <tr><td style="padding:6px 0;color:#6b7280">Plan</td>
        <td style="padding:6px 0;font-weight:600">{plan.title()}</td></tr>
    <tr><td style="padding:6px 0;color:#6b7280">Valid until</td>
        <td style="padding:6px 0;font-weight:600">{expires_str}</td></tr>
  </table>
  <a href="{download_url}"
     style="display:inline-block;background:#4f46e5;color:#fff;padding:12px 24px;
            border-radius:8px;text-decoration:none;font-weight:600;margin-right:10px">
    ⬇ Download TrafficOS
  </a>
  <a href="{cabinet_url}"
     style="display:inline-block;background:#f4f4f8;color:#1a1a2e;padding:12px 24px;
            border-radius:8px;text-decoration:none;font-weight:600">
    My Cabinet
  </a>
  <p style="margin-top:24px;color:#9ca3af;font-size:12px">
    Keep this email — your key is the only way to manage your license.<br>
    Enter it in TrafficOS: Settings → License → Activate.
  </p>
</div>"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={
                    "from": FROM_EMAIL,
                    "to": [email],
                    "subject": f"Your TrafficOS {plan.title()} License Key",
                    "html": body_html,
                },
            )
        if resp.status_code in (200, 201):
            log.info("License email sent to %s (plan=%s)", email, plan)
            return True
        log.warning("Resend error %s: %s", resp.status_code, resp.text)
        return False
    except Exception as exc:
        log.warning("Email send failed: %s", exc)
        return False


def _create_license_for_payment(db: Session, plan: str, period: str, email: str) -> tuple:
    plan_key = f"{plan}_{period}" if period else plan
    days = PLAN_PERIODS.get(period, 30)
    key = _generate_key()
    expires_at = datetime.utcnow() + timedelta(days=days)
    lic = License(
        key=key, plan=plan_key, machine_ids="[]", max_machines=2,
        expires_at=expires_at, notes=f"payment:{email}",
    )
    db.add(lic)
    db.commit()
    return key, expires_at


# ── Cabinet (public) ──────────────────────────────────────────────────────────

@app.get("/cabinet/{key}")
def cabinet(key: str, db: Session = Depends(_get_db)):
    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")
    now = datetime.utcnow()
    expires_at = lic.expires_at
    if lic.plan == "trial" and lic.trial_days and lic.activated_at:
        expires_at = lic.activated_at + timedelta(days=lic.trial_days)
    machines: list[str] = json.loads(lic.machine_ids)
    days_left = max(0, (expires_at - now).days) if expires_at else None
    active = not (expires_at and now > expires_at)
    return {
        "key": key,
        "plan": lic.plan,
        "features": PLAN_FEATURES.get(lic.plan, {}),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "active": active,
        "machines_used": len(machines),
        "max_machines": lic.max_machines,
        "download_url": _MANIFEST["download_url"],
        "latest_version": _MANIFEST["version"],
    }


# ── Stripe ────────────────────────────────────────────────────────────────────

class StripeSessionRequest(BaseModel):
    plan: str
    period: str
    email: str


@app.post("/payment/stripe/create-session")
async def stripe_create_session(req: StripeSessionRequest):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    import stripe as _stripe
    _stripe.api_key = STRIPE_SECRET_KEY
    price_key = f"{req.plan}_{req.period}"
    price_id = STRIPE_PRICES.get(price_key)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Unknown plan/period: {price_key}")
    session = _stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="payment",
        customer_email=req.email,
        metadata={"plan": req.plan, "period": req.period, "email": req.email},
        success_url=f"{WEBSITE_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{WEBSITE_URL}/pricing",
    )
    return {"checkout_url": session.url}


@app.post("/payment/stripe/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(_get_db)):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Stripe webhook secret not configured")
    import stripe as _stripe
    import asyncio
    _stripe.api_key = STRIPE_SECRET_KEY
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = _stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if event["type"] == "checkout.session.completed":
        sess_obj = event["data"]["object"]
        meta     = sess_obj.get("metadata", {})
        email    = meta.get("email", "")
        plan     = meta.get("plan", "starter")
        period   = meta.get("period", "monthly")
        key, expires_at = _create_license_for_payment(db, plan, period, email)
        pmt = Payment(
            order_id=str(_uuid.uuid4()),
            method="stripe", plan=plan, period=period, email=email,
            amount_usd=_PLAN_PRICES_USD.get(f"{plan}_{period}", 0),
            currency="card", external_id=sess_obj.get("id", ""),
            status="paid", license_key=key, completed_at=datetime.utcnow(),
        )
        db.add(pmt)
        db.commit()
        log.info("Stripe payment OK: plan=%s email=%s key=%s", plan, email, key)
        asyncio.create_task(_send_license_email(email, key, plan, expires_at))
    return {"ok": True}


# ── NOWPayments ───────────────────────────────────────────────────────────────

_NOWPAYMENTS_CURRENCY_MAP: dict[str, str] = {
    "USDT": "usdttrc20",
    "BTC":  "btc",
    "ETH":  "eth",
    "LTC":  "ltc",
    "TON":  "ton",
}


class NowpaymentsInvoiceRequest(BaseModel):
    plan: str
    period: str
    email: str
    currency: str = "USDT"


@app.post("/payment/nowpayments/create-invoice")
async def nowpayments_create_invoice(req: NowpaymentsInvoiceRequest, db: Session = Depends(_get_db)):
    if not NOWPAYMENTS_API_KEY:
        raise HTTPException(status_code=503, detail="NOWPayments not configured")
    price_key = f"{req.plan}_{req.period}"
    amount = _PLAN_PRICES_USD.get(price_key)
    if not amount:
        raise HTTPException(status_code=400, detail=f"Unknown plan/period: {price_key}")

    order_id = str(_uuid.uuid4())
    pmt = Payment(
        order_id=order_id, method="nowpayments",
        plan=req.plan, period=req.period, email=req.email,
        amount_usd=amount, currency=req.currency, status="pending",
    )
    db.add(pmt)
    db.commit()

    license_server_url = os.environ.get("LICENSE_SERVER_URL", "https://web-production-8c6356.up.railway.app")
    pay_currency = _NOWPAYMENTS_CURRENCY_MAP.get(req.currency.upper(), "usdttrc20")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            "https://api.nowpayments.io/v1/invoice",
            headers={"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"},
            json={
                "price_amount": amount,
                "price_currency": "usd",
                "pay_currency": pay_currency,
                "order_id": order_id,
                "order_description": f"TrafficOS {req.plan.title()} ({req.period})",
                "ipn_callback_url": f"{license_server_url}/payment/nowpayments/webhook",
                "success_url": f"{WEBSITE_URL}/success?email={req.email}",
                "cancel_url": f"{WEBSITE_URL}/pricing",
            },
        )
    if resp.status_code not in (200, 201):
        log.warning("NOWPayments error %s: %s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail="NOWPayments error")
    data = resp.json()
    invoice_id = str(data.get("id", ""))
    pmt.external_id = invoice_id
    db.commit()
    return {"invoice_url": data.get("invoice_url", ""), "invoice_id": invoice_id}


@app.post("/payment/nowpayments/webhook")
async def nowpayments_webhook(request: Request, db: Session = Depends(_get_db)):
    import asyncio
    payload = await request.body()
    if NOWPAYMENTS_IPN_SECRET:
        sig = request.headers.get("x-nowpayments-sig", "")
        body_data = json.loads(payload)
        sorted_payload = json.dumps(body_data, sort_keys=True, separators=(",", ":"))
        expected = _hmac_pay.new(
            NOWPAYMENTS_IPN_SECRET.encode(), sorted_payload.encode(), _hashlib_pay.sha512
        ).hexdigest()
        if not _hmac_pay.compare_digest(sig.lower(), expected.lower()):
            raise HTTPException(status_code=400, detail="Invalid signature")

    body = json.loads(payload)
    payment_status = body.get("payment_status", "")
    order_id = str(body.get("order_id", ""))
    if payment_status not in ("finished", "confirmed"):
        return {"ok": True}

    pmt = db.query(Payment).filter(Payment.order_id == order_id).first()
    if not pmt:
        log.warning("NOWPayments webhook: no payment for order_id=%s", order_id)
        return {"ok": True}
    if pmt.status == "paid":
        return {"ok": True}

    key, expires_at = _create_license_for_payment(db, pmt.plan, pmt.period, pmt.email)
    pmt.status = "paid"
    pmt.license_key = key
    pmt.completed_at = datetime.utcnow()
    db.commit()
    log.info("NOWPayments OK: plan=%s email=%s key=%s", pmt.plan, pmt.email, key)
    asyncio.create_task(_send_license_email(pmt.email, key, pmt.plan, expires_at))
    return {"ok": True}


@app.get("/payment/nowpayments/status/{invoice_id}")
async def nowpayments_status(invoice_id: str, db: Session = Depends(_get_db)):
    pmt = db.query(Payment).filter(Payment.external_id == invoice_id).first()
    if not pmt:
        return {"paid": False, "status": "not_found"}
    return {"paid": pmt.status == "paid", "status": pmt.status}


# ── Auto-update endpoints ─────────────────────────────────────────────────────

# Update these values on every release
# Railway may not expose it reliably; hardcoding is simpler and always correct).
_MANIFEST = {
    "version": "1.5.5",
    "download_url": "https://github.com/RenatKost/ss/releases/download/v1.5.5/TrafficOS_Setup_v1.5.5.exe",
    "notes": "Фикс Stories/Реакций: воркфлоу-узлы теперь реально просматривают и реагируют на истории. Фикс рассылки (не уходит в Избранное). Авто-сохранение видео в выбранную папку. Экспорт аккаунтов (Session/JSON/CSV). ETA-прогресс в узлах воркфлоу.",
}


def _version_gt(a: str, b: str) -> bool:
    """Return True if version a is strictly greater than b."""
    try:
        return tuple(int(x) for x in a.split(".")) > tuple(int(x) for x in b.split("."))
    except Exception:
        return False


@app.get("/api/update/manifest")
def get_update_manifest():
    """Serve the update manifest."""
    return _MANIFEST


@app.get("/api/update/check")
def check_update(current_version: str = "1.0.0"):
    """Compare current_version with manifest version."""
    latest = _MANIFEST["version"]
    available = _version_gt(latest, current_version)
    return {
        "available": available,
        "latest_version": latest,
        "current_version": current_version,
        "download_url": _MANIFEST["download_url"] if available else "",
        "notes": _MANIFEST["notes"] if available else "",
    }

