"""
TGPars License Server
Minimal FastAPI service for managing license keys.
Deploy on Railway (free tier) or any VPS.

Plans: trial | starter | pro | enterprise
"""
from __future__ import annotations

import hashlib
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

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("license-server")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./licenses.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "changeme-admin-secret")

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
    plan = Column(String(32), nullable=False, default="starter")  # trial|starter|pro|enterprise
    # JSON array of up to max_machines machine_id strings
    machine_ids = Column(Text, nullable=False, default="[]")
    max_machines = Column(Integer, nullable=False, default=2)
    expires_at = Column(DateTime, nullable=True)       # NULL = never expires
    trial_days = Column(Integer, nullable=True)        # only for trial plan
    activated_at = Column(DateTime, nullable=True)     # first activation timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.utcnow())
    notes = Column(Text, nullable=True)


Base.metadata.create_all(bind=engine)


# ---------- Feature flags per plan ----------

PLAN_FEATURES: dict[str, dict] = {
    "trial": {
        "max_accounts": 50,
        "max_messages_day": 1500,
        "instagram": False,
        "twitter": False,
        "video": False,
    },
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

class ValidateRequest(BaseModel):
    key: str
    machine_id: str
    version: str = ""


class ActivateRequest(BaseModel):
    key: str
    machine_id: str


class DeactivateRequest(BaseModel):
    key: str
    machine_id: str


class GenerateRequest(BaseModel):
    plan: str = "starter"
    expires_days: Optional[int] = None   # None = never expires
    max_machines: int = 2
    notes: Optional[str] = None


# ---------- App ----------

app = FastAPI(title="TGPars License Server", version="1.0.0")

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
def validate(req: ValidateRequest, db: Session = Depends(_get_db)):
    """Called by TGPars app on startup and every 30 min."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        return {"valid": False, "reason": "key_not_found"}

    machines = json.loads(lic.machine_ids)

    # Check machine binding: machine must be in the list (or list is empty = not yet activated)
    if machines and req.machine_id not in machines:
        return {"valid": False, "reason": "machine_not_registered"}

    # Check expiry
    now = datetime.utcnow()
    expires_at = lic.expires_at

    # Trial: expires_at computed from first activation
    if lic.plan == "trial" and lic.trial_days:
        if lic.activated_at:
            expires_at = lic.activated_at + timedelta(days=lic.trial_days)
        else:
            # Never activated yet вЂ” expires_at not set
            expires_at = None

    if expires_at and now > expires_at:
        return {"valid": False, "reason": "expired"}

    features = PLAN_FEATURES.get(lic.plan, PLAN_FEATURES["starter"])
    days_left = None
    if expires_at:
        days_left = max(0, (expires_at - now).days)

    return {
        "valid": True,
        "plan": lic.plan,
        "features": features,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
    }


@app.post("/activate")
def activate(req: ActivateRequest, db: Session = Depends(_get_db)):
    """Bind machine_id to license key. Returns error if machine limit reached."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")

    machines: list[str] = json.loads(lic.machine_ids)

    if req.machine_id in machines:
        # Already registered вЂ” just return success
        pass
    elif len(machines) >= lic.max_machines:
        raise HTTPException(
            status_code=403,
            detail=f"Machine limit reached ({lic.max_machines}). Deactivate another machine first.",
        )
    else:
        machines.append(req.machine_id)
        lic.machine_ids = json.dumps(machines)
        if not lic.activated_at:
            lic.activated_at = datetime.utcnow()
        db.commit()

    # Compute expiry
    now = datetime.utcnow()
    expires_at = lic.expires_at
    if lic.plan == "trial" and lic.trial_days and lic.activated_at:
        expires_at = lic.activated_at + timedelta(days=lic.trial_days)

    features = PLAN_FEATURES.get(lic.plan, PLAN_FEATURES["starter"])
    days_left = None
    if expires_at:
        days_left = max(0, (expires_at - now).days)

    return {
        "valid": True,
        "plan": lic.plan,
        "features": features,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
    }


@app.post("/deactivate")
def deactivate(req: DeactivateRequest, db: Session = Depends(_get_db)):
    """Free up a machine slot (e.g. when migrating to new VPS)."""
    lic = db.query(License).filter(License.key == req.key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="key_not_found")

    machines: list[str] = json.loads(lic.machine_ids)
    if req.machine_id in machines:
        machines.remove(req.machine_id)
        lic.machine_ids = json.dumps(machines)
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


# ---------- Auto-update endpoints ----------

# Update these values on every release (do NOT rely on reading manifest.json from disk вЂ”
# Railway may not expose it reliably; hardcoding is simpler and always correct).
_MANIFEST = {
    "version": "1.2.3",
    "download_url": "https://github.com/RenatKost/ss/releases/download/v1.2.3/TrafficOS_Setup_v1.2.3.exe",
    "notes": "Relay-С‚СЂРµРєРёРЅРі РІРєР»СЋС‡Р°РµС‚СЃСЏ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РґР»СЏ РІСЃРµС… РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№. РђРЅР°Р»РёС‚РёРєР°: РёРєРѕРЅРєРё Р±СЂР°СѓР·РµСЂРѕРІ Рё РћРЎ, РіРѕСЂРѕРґ РІ СЃРѕР±С‹С‚РёСЏС…. UI: СѓР±СЂР°РЅС‹ РёРЅСЃС‚СЂСѓРєС†РёРё РёР· СЃС‚СЂР°РЅРёС†С‹ СЃСЃС‹Р»РѕРє.",
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

