"""
TGPars License Server
Minimal FastAPI service for managing license keys.
Deploy on Railway (free tier) or any VPS.

Plans: trial | starter | pro | enterprise
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_mod
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
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("license-server")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./licenses.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "changeme-admin-secret")
HMAC_SECRET = os.environ.get("HMAC_SECRET", "").encode()


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
    plan = Column(String(32), nullable=False, default="starter")  # trial|starter|pro|enterprise
    # JSON array of up to max_machines machine_id strings
    machine_ids = Column(Text, nullable=False, default="[]")
    max_machines = Column(Integer, nullable=False, default=2)
    expires_at = Column(DateTime, nullable=True)       # NULL = never expires
    trial_days = Column(Integer, nullable=True)        # only for trial plan
    activated_at = Column(DateTime, nullable=True)     # first activation timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.utcnow())
    notes = Column(Text, nullable=True)
    # JSON dict: {machine_id: {components: {...}, last_seen: "ISO"}}
    hwid_data = Column(Text, nullable=False, default="{}")


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
def activate(req: ActivateRequest, db: Session = Depends(_get_db)):
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


# ---------- Auto-update endpoints ----------

# Update these values on every release (do NOT rely on reading manifest.json from disk вЂ”
# Railway may not expose it reliably; hardcoding is simpler and always correct).
_MANIFEST = {
    "version": "1.4.8",
    "download_url": "https://github.com/RenatKost/ss/releases/download/v1.4.8/TrafficOS_Setup_v1.4.8.exe",
    "notes": "v1.4.8: HMAC-подпись ответов лицензионного сервера, защита от подмены через прокси.",
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

