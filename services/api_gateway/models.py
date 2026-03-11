"""
ORM Models — SQLAlchemy async declarative models.
These mirror the PostgreSQL schema in init_schema.sql.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Text, Integer, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class User(Base):
    __tablename__ = "users"
    id:            Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username:      Mapped[str]       = mapped_column(String(128), unique=True, nullable=False)
    email:         Mapped[str]       = mapped_column(String(256), unique=True, nullable=False)
    password_hash: Mapped[str]       = mapped_column(Text, nullable=False)
    role:          Mapped[str]       = mapped_column(String(32), nullable=False, default="analyst")
    is_active:     Mapped[bool]      = mapped_column(Boolean, default=True)
    created_at:    Mapped[datetime]  = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_login:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id:             Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id:        Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_name:      Mapped[str | None] = mapped_column(String(256), nullable=True)
    severity:       Mapped[str]        = mapped_column(String(16), nullable=False)
    detection_type: Mapped[str]        = mapped_column(String(32), default="rule")
    status:         Mapped[str]        = mapped_column(String(32), default="open")
    host_name:      Mapped[str | None] = mapped_column(String(256), nullable=True)
    user_name:      Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_ip:      Mapped[str | None] = mapped_column(String(45), nullable=True)
    mitre_tactic:   Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique:Mapped[str | None] = mapped_column(String(32), nullable=True)
    incident_id:    Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    raw_alert:      Mapped[dict]       = mapped_column(JSON, nullable=False, default=dict)
    triggered_at:   Mapped[datetime]   = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at:Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    id:               Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title:            Mapped[str]       = mapped_column(String(512), nullable=False)
    description:      Mapped[str | None] = mapped_column(Text, nullable=True)
    severity:         Mapped[str]       = mapped_column(String(16), nullable=False)
    status:           Mapped[str]       = mapped_column(String(32), default="open")
    assigned_to:      Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    source_alert_id:  Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_tactic:     Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique:  Mapped[str | None] = mapped_column(String(32), nullable=True)
    sla_due_at:       Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    opened_at:        Mapped[datetime]  = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    resolved_at:      Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note:  Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_pack:    Mapped[dict]      = mapped_column(JSON, default=dict)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id:         Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id:    Mapped[str]       = mapped_column(String(64), unique=True, nullable=False)
    name:       Mapped[str]       = mapped_column(String(256), nullable=False)
    version:    Mapped[int]       = mapped_column(Integer, default=1)
    enabled:    Mapped[bool]      = mapped_column(Boolean, default=True)
    severity:   Mapped[str]       = mapped_column(String(16), nullable=False)
    rule_json:  Mapped[dict]      = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime]  = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime]  = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id:             Mapped[int]         = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id:       Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_username: Mapped[str | None]  = mapped_column(String(128), nullable=True)
    actor_role:     Mapped[str | None]  = mapped_column(String(32), nullable=True)
    action:         Mapped[str]         = mapped_column(String(128), nullable=False)
    resource_type:  Mapped[str | None]  = mapped_column(String(128), nullable=True)
    resource_id:    Mapped[str | None]  = mapped_column(String(256), nullable=True)
    detail:         Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address:     Mapped[str | None]  = mapped_column(String(45), nullable=True)
    created_at:     Mapped[datetime]    = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
