"""
SOC Platform — Standalone Dev Server (No Docker Required)
=========================================================
Uses SQLite instead of PostgreSQL. No Kafka, no Redis.
Alerts are saved directly to DB (no pipeline needed for MVP demo).

Run:
    cd c:\\Users\\Cybernetic\\Desktop\\abc
    pip install fastapi uvicorn[standard] sqlalchemy[asyncio] aiosqlite passlib[bcrypt] python-jose[cryptography] python-multipart
    python standalone_server.py
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import (Boolean, Column, DateTime, Integer, JSON, String, Text,
                        select, func, and_, desc, event)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# ── Config ──────────────────────────────────────────────────────────────────
DB_URL       = "sqlite+aiosqlite:///./soc_dev.db"
JWT_SECRET   = "dev-secret-key-change-in-production-abc123xyz"
JWT_ALGO     = "HS256"
JWT_EXPIRE   = 120  # minutes
ADMIN_PASS   = "Admin@SOC123!"
LOG_LEVEL    = "INFO"

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("soc-standalone")

# ── DB ───────────────────────────────────────────────────────────────────────
engine = create_async_engine(DB_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id            = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username      = Column(String(128), unique=True, nullable=False)
    email         = Column(String(256), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role          = Column(String(32), nullable=False, default="analyst")
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login    = Column(DateTime(timezone=True), nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id             = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id        = Column(String(64))
    rule_name      = Column(String(256))
    severity       = Column(String(16), nullable=False)
    detection_type = Column(String(32), default="rule")
    status         = Column(String(32), default="open")
    host_name      = Column(String(256))
    user_name      = Column(String(128))
    source_ip      = Column(String(45))
    mitre_tactic   = Column(String(128))
    mitre_technique= Column(String(32))
    incident_id    = Column(String(36), nullable=True)
    raw_alert      = Column(JSON, default=dict)
    triggered_at   = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    acknowledged_at= Column(DateTime(timezone=True))

class Incident(Base):
    __tablename__ = "incidents"
    id              = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title           = Column(String(512), nullable=False)
    description     = Column(Text)
    severity        = Column(String(16), nullable=False)
    status          = Column(String(32), default="open")
    source_alert_id = Column(String(64))
    mitre_tactic    = Column(String(128))
    mitre_technique = Column(String(32))
    sla_due_at      = Column(DateTime(timezone=True))
    opened_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at     = Column(DateTime(timezone=True))
    resolution_note = Column(Text)
    evidence_pack   = Column(JSON, default=dict)

# ── Auth helpers (pure-Python PBKDF2, no external dep) ──────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def hash_pw(pw: str) -> str:
    """SHA-256 PBKDF2 with random 16-byte salt, stored as salt$hash."""
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260_000).hex()
    return f"{salt}${h}"

def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split('$', 1)
        return secrets.compare_digest(
            hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260_000).hex(), h
        )
    except Exception:
        return False
def make_token(data: dict) -> str:
    d = data.copy()
    d["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode(d, JWT_SECRET, algorithm=JWT_ALGO)

async def get_db():
    async with SessionLocal() as s:
        try:
            yield s
            await s.commit()
        except Exception:
            await s.rollback()
            raise

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    exc = HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        uname   = payload.get("sub")
        if not uname: raise exc
    except JWTError:
        raise exc
    r = await db.execute(select(User).where(User.username == uname))
    u = r.scalar_one_or_none()
    if not u or not u.is_active: raise exc
    return u

def require_role(*roles):
    async def _chk(u: User = Depends(get_current_user)):
        if u.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {roles}")
        return u
    return _chk

SAMPLE_RULES = [
    {"id": "det-001", "name": "Brute Force Authentication",   "severity": "high",   "tactic": "Credential Access",   "technique": "T1110.001", "enabled": True},
    {"id": "det-002", "name": "Impossible Travel Logon",      "severity": "high",   "tactic": "Initial Access",      "technique": "T1078", "enabled": True},
    {"id": "det-003", "name": "Suspicious PowerShell Flags",   "severity": "medium", "tactic": "Execution",           "technique": "T1059.001", "enabled": True},
    {"id": "det-004", "name": "Encoded Command Execution",     "severity": "high",   "tactic": "Defense Evasion",     "technique": "T1027", "enabled": True},
    {"id": "det-005", "name": "Scheduled Task Creation",       "severity": "medium", "tactic": "Persistence",         "technique": "T1053.005", "enabled": True},
    {"id": "det-006", "name": "Registry Run Key Persistence",  "severity": "high",   "tactic": "Persistence",         "technique": "T1547.001", "enabled": True},
    {"id": "det-007", "name": "Outbound to High-Risk Country", "severity": "medium", "tactic": "Exfiltration",        "technique": "T1048", "enabled": True},
    {"id": "det-008", "name": "Large Data Transfer over SMB",  "severity": "low",    "tactic": "Collection",          "technique": "T1039", "enabled": True},
    {"id": "det-009", "name": "Ransomware File Extensions",    "severity": "critical", "tactic": "Impact",            "technique": "T1486", "enabled": True},
    {"id": "det-010", "name": "Suspicious Process Hierarchy",  "severity": "high",   "tactic": "Execution",           "technique": "T1059", "enabled": True},
]

SAMPLE_ALERTS = [
    dict(rule_id="det-001", rule_name="Brute Force Authentication", severity="high",
         detection_type="rule", host_name="WIN-DC01", user_name="jsmith",
         source_ip="185.220.101.47", mitre_tactic="Credential Access", mitre_technique="T1110.001",
         triggered_at=datetime.now(timezone.utc) - timedelta(minutes=42)),
    dict(rule_id="det-004", rule_name="Encoded Command Execution", severity="high",
         detection_type="rule", host_name="WS-007", user_name="alee",
         source_ip="10.0.1.22", mitre_tactic="Defense Evasion", mitre_technique="T1027",
         triggered_at=datetime.now(timezone.utc) - timedelta(minutes=18)),
    dict(rule_id="det-003", rule_name="Suspicious PowerShell Flags", severity="medium",
         detection_type="rule", host_name="WS-012", user_name="mwilson",
         source_ip="10.0.2.5", mitre_tactic="Execution", mitre_technique="T1059.001",
         triggered_at=datetime.now(timezone.utc) - timedelta(minutes=7)),
    dict(rule_id="det-007", rule_name="Outbound to High-Risk Country", severity="medium",
         detection_type="rule", host_name="FIREWALL-01", user_name=None,
         source_ip="10.0.1.5", mitre_tactic="Exfiltration", mitre_technique="T1048",
         triggered_at=datetime.now(timezone.utc) - timedelta(hours=2)),
    dict(rule_id="det-001", rule_name="Brute Force Authentication", severity="high",
         detection_type="rule", host_name="WIN-DC02", user_name="rgarcia",
         source_ip="194.165.16.11", mitre_tactic="Credential Access", mitre_technique="T1110.001",
         triggered_at=datetime.now(timezone.utc) - timedelta(hours=5), status="acknowledged"),
    dict(rule_id="det-006", rule_name="Registry Run Key Persistence", severity="high",
         detection_type="rule", host_name="WS-003", user_name="ptaylor",
         source_ip="10.0.3.9", mitre_tactic="Persistence", mitre_technique="T1547.001",
         triggered_at=datetime.now(timezone.utc) - timedelta(hours=8), status="false_positive"),
    dict(rule_id="det-004", rule_name="Encoded Command Execution", severity="critical",
         detection_type="correlation", host_name="WIN-SQL01", user_name="svc_deploy",
         source_ip="10.0.0.50", mitre_tactic="Defense Evasion", mitre_technique="T1027",
         triggered_at=datetime.now(timezone.utc) - timedelta(hours=12)),
]

SAMPLE_INCIDENTS = [
    dict(title="Brute Force + Lateral Movement Chain — jsmith", severity="critical",
         mitre_tactic="Credential Access", mitre_technique="T1110.001",
         opened_at=datetime.now(timezone.utc) - timedelta(minutes=40),
         resolved_at=None, status="in_progress"),
    dict(title="Encoded PowerShell on WS-007 — alee", severity="high",
         mitre_tactic="Defense Evasion", mitre_technique="T1027",
         opened_at=datetime.now(timezone.utc) - timedelta(minutes=15),
         resolved_at=None, status="open"),
    dict(title="Registry Persistence on WS-003", severity="high",
         mitre_tactic="Persistence", mitre_technique="T1547.001",
         opened_at=datetime.now(timezone.utc) - timedelta(hours=9),
         resolved_at=datetime.now(timezone.utc) - timedelta(hours=7),
         status="resolved"),
]

# Simple in-memory settings store for the standalone dev server
SYSTEM_SETTINGS = {
    "ml_engine": "IsolationForest (Enabled)",
    "retention_days": 30
}

# Simple in-memory Playbooks
PLAYBOOKS = [
    {"id": "pb-001", "name": "Isolate Infected Host", "trigger": "Ransomware File Extensions", "action": "Network Isolation via EDR", "enabled": True},
    {"id": "pb-002", "name": "Block Malicious IP", "trigger": "Outbound to High-Risk Country", "action": "Add rule to perimeter Firewall", "enabled": True},
    {"id": "pb-003", "name": "Disable Compromised Account", "trigger": "Impossible Travel Logon", "action": "Lock AD Account", "enabled": False},
]

# ── App lifespan ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        # Seed admin user
        r = await db.execute(select(User).where(User.username == "admin"))
        if not r.scalar_one_or_none():
            db.add(User(username="admin", email="admin@soc.local",
                        password_hash=hash_pw(ADMIN_PASS), role="admin"))
            db.add(User(username="analyst1", email="analyst1@soc.local",
                        password_hash=hash_pw("Analyst@123!"), role="analyst"))
            db.add(User(username="responder1", email="responder1@soc.local",
                        password_hash=hash_pw("Responder@123!"), role="responder"))
            await db.commit()
            log.info("Seeded users: admin, analyst1, responder1")

        # Seed sample alerts
        count = (await db.execute(select(func.count()).select_from(Alert))).scalar_one()
        if count == 0:
            for a in SAMPLE_ALERTS:
                db.add(Alert(
                    rule_id=a.get("rule_id"), rule_name=a.get("rule_name"),
                    severity=a.get("severity","medium"),
                    detection_type=a.get("detection_type","rule"),
                    status=a.get("status","open"),
                    host_name=a.get("host_name"), user_name=a.get("user_name"),
                    source_ip=a.get("source_ip"),
                    mitre_tactic=a.get("mitre_tactic"), mitre_technique=a.get("mitre_technique"),
                    triggered_at=a.get("triggered_at", datetime.now(timezone.utc)),
                    raw_alert={k: str(v) for k, v in a.items() if k != "triggered_at"},
                ))
            await db.commit()
            log.info(f"Seeded {len(SAMPLE_ALERTS)} sample alerts")

        # Seed sample incidents
        count = (await db.execute(select(func.count()).select_from(Incident))).scalar_one()
        if count == 0:
            for inc in SAMPLE_INCIDENTS:
                db.add(Incident(**inc))
            await db.commit()
            log.info(f"Seeded {len(SAMPLE_INCIDENTS)} sample incidents")

    log.info("=" * 60)
    log.info("  SOC Platform Standalone Dev Server")
    log.info("  API:       http://localhost:8000")
    log.info("  Docs:      http://localhost:8000/docs")
    log.info("  Dashboard: http://localhost:3000")
    log.info("  Login:     admin / Admin@SOC123!")
    log.info("=" * 60)
    async def live_event_generator():
        import random
        while True:
            await asyncio.sleep(8)
            try:
                async with SessionLocal() as sdb:
                    active_rules = [r for r in SAMPLE_RULES if r["enabled"]]
                    if not active_rules: continue
                    rule = random.choice(active_rules)
                    new_alert = Alert(
                        rule_id=rule["id"], rule_name=rule["name"],
                        severity=rule["severity"], detection_type="rule",
                        status="open",
                        host_name=f"WS-{random.randint(100,999)}",
                        user_name=f"sim_user{random.randint(1,9)}",
                        source_ip=f"192.168.1.{random.randint(1,254)}",
                        mitre_tactic=rule["tactic"], mitre_technique=rule["technique"],
                        triggered_at=datetime.now(timezone.utc),
                        raw_alert={"simulated": True}
                    )
                    sdb.add(new_alert)
                    
                    # Occasionally generate an incident
                    if random.random() < 0.2:
                        inc = Incident(
                            title=f"Escalated: {rule['name']}",
                            severity=rule["severity"],
                            status="open",
                            mitre_tactic=rule["tactic"],
                            mitre_technique=rule["technique"],
                            opened_at=datetime.now(timezone.utc),
                        )
                        sdb.add(inc)
                    
                    await sdb.commit()
            except Exception as e:
                pass

    bg_task = asyncio.create_task(live_event_generator())
    try:
        yield
    finally:
        bg_task.cancel()

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="SOC Platform API (Standalone Dev)", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ── AUTH ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health(): return {"status": "ok", "mode": "standalone-sqlite"}

@app.post("/api/v1/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.username == form.username))
    u = r.scalar_one_or_none()
    if not u or not verify_pw(form.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    u.last_login = datetime.now(timezone.utc)
    await db.commit()
    token = make_token({"sub": u.username, "role": u.role})
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_EXPIRE * 60, "role": u.role}

@app.get("/api/v1/auth/me")
async def me(u: User = Depends(get_current_user)):
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role}

# ── ALERTS ───────────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts")
async def list_alerts(
    severity: Optional[str] = None, status: Optional[str] = None,
    rule_id:  Optional[str] = None,
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    q = select(Alert).order_by(desc(Alert.triggered_at))
    if severity: q = q.where(Alert.severity == severity)
    if status:   q = q.where(Alert.status   == status)
    if rule_id:  q = q.where(Alert.rule_id  == rule_id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(q.offset((page-1)*page_size).limit(page_size))).scalars().all()
    items = [dict(id=a.id, rule_name=a.rule_name, severity=a.severity,
                  detection_type=a.detection_type, status=a.status,
                  host_name=a.host_name, user_name=a.user_name, source_ip=a.source_ip,
                  mitre_tactic=a.mitre_tactic, mitre_technique=a.mitre_technique,
                  triggered_at=a.triggered_at.isoformat(), incident_id=a.incident_id)
             for a in rows]
    return {"total": total, "page": page, "page_size": page_size, "items": items}

@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    a = r.scalar_one_or_none()
    if not a: raise HTTPException(404, "Alert not found")
    return a.raw_alert or {}

@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    r  = await db.execute(select(Alert).where(Alert.id == alert_id))
    a  = r.scalar_one_or_none()
    if not a: raise HTTPException(404)
    a.status = "acknowledged"; a.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}

@app.post("/api/v1/alerts/{alert_id}/false-positive")
async def fp_alert(alert_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    a = r.scalar_one_or_none()
    if not a: raise HTTPException(404)
    a.status = "false_positive"; await db.commit()
    return {"status": "false_positive", "alert_id": alert_id}

# ── INCIDENTS ────────────────────────────────────────────────────────────────
@app.get("/api/v1/incidents")
async def list_incidents(
    status: Optional[str]   = None, severity: Optional[str] = None,
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    q = select(Incident).order_by(desc(Incident.opened_at))
    if status:   q = q.where(Incident.status   == status)
    if severity: q = q.where(Incident.severity == severity)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(q.offset((page-1)*page_size).limit(page_size))).scalars().all()
    items = [dict(id=i.id, title=i.title, severity=i.severity, status=i.status,
                  mitre_tactic=i.mitre_tactic,
                  opened_at=i.opened_at.isoformat(),
                  resolved_at=i.resolved_at.isoformat() if i.resolved_at else None)
             for i in rows]
    return {"total": total, "page": page, "page_size": page_size, "items": items}

@app.post("/api/v1/incidents", status_code=201)
async def create_incident(body: dict, db: AsyncSession = Depends(get_db),
                          _: User = Depends(require_role("responder","admin"))):
    inc = Incident(**{k: v for k, v in body.items()
                      if k in Incident.__table__.columns.keys() and k != "id"})
    db.add(inc); await db.commit(); await db.refresh(inc)
    return {"id": inc.id, "status": "open", "title": inc.title}

@app.get("/api/v1/incidents/{inc_id}")
async def get_incident(inc_id: str, db: AsyncSession = Depends(get_db),
                       _: User = Depends(get_current_user)):
    r = await db.execute(select(Incident).where(Incident.id == inc_id))
    i = r.scalar_one_or_none()
    if not i: raise HTTPException(404)
    return dict(id=i.id, title=i.title, description=i.description, severity=i.severity,
                status=i.status, mitre_tactic=i.mitre_tactic, mitre_technique=i.mitre_technique,
                opened_at=i.opened_at.isoformat(),
                resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
                resolution_note=i.resolution_note, evidence_pack=i.evidence_pack)

@app.put("/api/v1/incidents/{inc_id}/status")
async def update_inc_status(inc_id: str, body: dict, db: AsyncSession = Depends(get_db),
                             _: User = Depends(require_role("responder","admin"))):
    r   = await db.execute(select(Incident).where(Incident.id == inc_id))
    inc = r.scalar_one_or_none()
    if not inc: raise HTTPException(404)
    inc.status = body.get("status", inc.status)
    if body.get("resolution_note"): inc.resolution_note = body["resolution_note"]
    if inc.status in ("resolved","closed"): inc.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": inc_id, "status": inc.status}

# ── METRICS ──────────────────────────────────────────────────────────────────
@app.get("/api/v1/metrics/kpi")
async def kpi(days: int = 7, db: AsyncSession = Depends(get_db),
              _: User = Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    total_alerts  = (await db.execute(select(func.count()).select_from(Alert).where(Alert.triggered_at >= since))).scalar_one()
    open_incidents= (await db.execute(select(func.count()).select_from(Incident).where(and_(Incident.opened_at >= since, Incident.status == "open")))).scalar_one()
    critical_open = (await db.execute(select(func.count()).select_from(Incident).where(and_(Incident.status == "open", Incident.severity == "critical")))).scalar_one()
    fp_count      = (await db.execute(select(func.count()).select_from(Alert).where(and_(Alert.triggered_at >= since, Alert.status == "false_positive")))).scalar_one()
    resolved      = (await db.execute(select(Incident).where(and_(Incident.opened_at >= since, Incident.status.in_(["resolved","closed"]), Incident.resolved_at.isnot(None))))).scalars().all()
    mttr = round(sum((i.resolved_at - i.opened_at).total_seconds()/60 for i in resolved)/len(resolved), 1) if resolved else None
    fp_rate = round(fp_count/total_alerts, 3) if total_alerts else 0.0
    return dict(period=f"last_{days}_days", total_alerts=total_alerts, open_incidents=open_incidents,
                critical_incidents=critical_open, false_positive_count=fp_count,
                false_positive_rate=fp_rate, true_positive_rate=round(1-fp_rate,3),
                mttr_minutes=mttr, mttd_minutes=4.2)

@app.get("/api/v1/metrics/alert-volume")
async def alert_volume(days: int = 7, db: AsyncSession = Depends(get_db),
                       _: User = Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows  = (await db.execute(select(Alert.triggered_at, Alert.severity).where(Alert.triggered_at >= since))).all()
    daily: dict[str, dict] = {}
    for ts, sev in rows:
        day = ts.strftime("%Y-%m-%d")
        if day not in daily:
            daily[day] = {"date": day, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        daily[day]["total"] += 1
        if sev in daily[day]: daily[day][sev] += 1
    return {"period_days": days, "data": sorted(daily.values(), key=lambda x: x["date"])}

@app.get("/api/v1/metrics/attack-heatmap")
async def attack_heatmap(days: int = 7, db: AsyncSession = Depends(get_db)):
    """Returns frequency counts of MITRE Tactics for the heatmap."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(select(Alert.mitre_tactic).where(and_(Alert.triggered_at >= since, Alert.mitre_tactic.isnot(None))))).scalars().all()
    counts = {}
    for tactic in rows:
        counts[tactic] = counts.get(tactic, 0) + 1
    
    # Format for robust Recharts rendering
    return [{"tactic": k, "count": v} for k, v in counts.items()]

# ── RULES ────────────────────────────────────────────────────────────────────
@app.get("/api/v1/rules")
async def list_rules(_: User = Depends(get_current_user)):
    return [{"rule_id": r["id"], "name": r["name"], "severity": r["severity"],
             "mitre_tactic": r["tactic"], "mitre_technique": r["technique"], "enabled": r["enabled"]}
            for r in SAMPLE_RULES]

@app.put("/api/v1/rules/{rule_id}")
async def toggle_rule(rule_id: str, payload: dict, _: User = Depends(require_role("admin"))):
    for r in SAMPLE_RULES:
        if r["id"] == rule_id:
            r["enabled"] = payload.get("enabled", r["enabled"])
            return {"status": "ok", "rule_id": rule_id, "enabled": r["enabled"]}
    raise HTTPException(404, "Rule not found")

# ── SETTINGS ─────────────────────────────────────────────────────────────────
@app.get("/api/v1/settings")
async def get_settings(_: User = Depends(get_current_user)):
    return SYSTEM_SETTINGS

@app.put("/api/v1/settings")
async def update_settings(payload: dict, _: User = Depends(require_role("admin"))):
    if "ml_engine" in payload: SYSTEM_SETTINGS["ml_engine"] = payload["ml_engine"]
    if "retention_days" in payload: SYSTEM_SETTINGS["retention_days"] = payload["retention_days"]
    return SYSTEM_SETTINGS

# ── PLAYBOOKS ────────────────────────────────────────────────────────────────
@app.get("/api/v1/playbooks")
async def list_playbooks(_: User = Depends(get_current_user)):
    return PLAYBOOKS

@app.put("/api/v1/playbooks/{pb_id}/execute")
async def run_playbook(pb_id: str, _: User = Depends(get_current_user)):
    pb = next((p for p in PLAYBOOKS if p["id"] == pb_id), None)
    if not pb: raise HTTPException(404)
    # Simulate execution delay
    return {"status": "success", "message": f"Executed action: {pb['action']} successfully."}

# ── PURPLE-TEAM SIMULATOR ────────────────────────────────────────────────────
@app.post("/api/v1/simulate")
async def trigger_simulation(payload: dict, db: AsyncSession = Depends(get_db)):
    """Generates an immediate blast of synthetic alerts/incidents for demo."""
    scenario = payload.get("scenario", "ransomware")
    if scenario == "ransomware":
        rules = [r for r in SAMPLE_RULES if r["id"] in ("det-003", "det-004", "det-009")]
    elif scenario == "exfiltration":
        rules = [r for r in SAMPLE_RULES if r["id"] in ("det-008", "det-007")]
    else:
        rules = [r for r in SAMPLE_RULES if r["id"] == "det-001"]
        
    for r in rules:
        db.add(Alert(
            rule_id=r["id"], rule_name=r["name"], severity=r["severity"],
            detection_type="simulation", status="open",
            host_name=f"SIM-TARGET-{scenario.upper()}",
            user_name="admin_compromised", source_ip="203.0.113.5",
            mitre_tactic=r["tactic"], mitre_technique=r["technique"],
            triggered_at=datetime.now(timezone.utc),
            raw_alert={"purple_team_sim": True, "scenario": scenario}
        ))
    db.add(Incident(
        title=f"Critical Chain: {scenario.capitalize()} Emulation",
        severity="critical", status="open",
        mitre_tactic=rules[-1]["tactic"], mitre_technique=rules[-1]["technique"],
    ))
    await db.commit()
    return {"status": "simulated", "scenario": scenario, "alerts_generated": len(rules)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
