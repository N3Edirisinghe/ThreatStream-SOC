"""Incidents router — CRUD for incident management."""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel

from database import get_db
from models import Incident, User
from deps import get_current_user, require_role

router = APIRouter()


class CreateIncidentRequest(BaseModel):
    title:           str
    description:     Optional[str] = None
    severity:        str
    source_alert_id: Optional[str] = None
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None
    sla_response_minutes: int = 60


class UpdateStatusRequest(BaseModel):
    status:          str
    resolution_note: Optional[str] = None


class IncidentSummary(BaseModel):
    id:              str
    title:           str
    severity:        str
    status:          str
    mitre_tactic:    Optional[str]
    opened_at:       datetime
    resolved_at:     Optional[datetime]
    model_config = {"from_attributes": True}


@router.get("")
async def list_incidents(
    status:    Optional[str] = Query(None),
    severity:  Optional[str] = Query(None),
    page:      int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db:        AsyncSession = Depends(get_db),
    _:         User = Depends(get_current_user),
):
    q = select(Incident).order_by(desc(Incident.opened_at))
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)

    count_q = select(func.count()).select_from(q.subquery())
    total   = (await db.execute(count_q)).scalar_one()
    q       = q.offset((page - 1) * page_size).limit(page_size)
    result  = await db.execute(q)
    items   = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": str(i.id),
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "mitre_tactic": i.mitre_tactic,
                "opened_at": i.opened_at.isoformat(),
                "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
            }
            for i in items
        ],
    }


@router.post("", status_code=201)
async def create_incident(
    body: CreateIncidentRequest,
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(require_role("responder", "admin")),
):
    sla_due = None
    if body.sla_response_minutes:
        from datetime import timedelta
        sla_due = datetime.now(timezone.utc) + timedelta(minutes=body.sla_response_minutes)

    incident = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        source_alert_id=body.source_alert_id,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
        sla_due_at=sla_due,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return {"id": str(incident.id), "status": "open", "title": incident.title}


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _:  User = Depends(get_current_user),
):
    result   = await db.execute(select(Incident).where(Incident.id == uuid.UUID(incident_id)))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id":              str(incident.id),
        "title":           incident.title,
        "description":     incident.description,
        "severity":        incident.severity,
        "status":          incident.status,
        "mitre_tactic":    incident.mitre_tactic,
        "mitre_technique": incident.mitre_technique,
        "sla_due_at":      incident.sla_due_at.isoformat() if incident.sla_due_at else None,
        "opened_at":       incident.opened_at.isoformat(),
        "resolved_at":     incident.resolved_at.isoformat() if incident.resolved_at else None,
        "resolution_note": incident.resolution_note,
        "evidence_pack":   incident.evidence_pack,
    }


@router.put("/{incident_id}/status")
async def update_status(
    incident_id: str,
    body: UpdateStatusRequest,
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(require_role("responder", "admin")),
):
    result   = await db.execute(select(Incident).where(Incident.id == uuid.UUID(incident_id)))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    valid = {"open", "in_progress", "resolved", "closed", "false_positive"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")

    incident.status = body.status
    if body.resolution_note:
        incident.resolution_note = body.resolution_note
    if body.status in ("resolved", "closed"):
        incident.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    return {"id": incident_id, "status": incident.status}
