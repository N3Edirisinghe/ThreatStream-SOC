"""Alerts router — list, detail, acknowledge, false-positive."""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel

from database import get_db
from models import Alert, User
from deps import get_current_user

router = APIRouter()


class AlertSummary(BaseModel):
    id:             str
    rule_name:      Optional[str]
    severity:       str
    detection_type: str
    status:         str
    host_name:      Optional[str]
    user_name:      Optional[str]
    source_ip:      Optional[str]
    mitre_tactic:   Optional[str]
    mitre_technique:Optional[str]
    triggered_at:   datetime
    incident_id:    Optional[str]

    model_config = {"from_attributes": True}


class PaginatedAlerts(BaseModel):
    total: int
    page:  int
    page_size: int
    items: list[AlertSummary]


@router.get("", response_model=PaginatedAlerts)
async def list_alerts(
    severity:   Optional[str] = Query(None),
    status:     Optional[str] = Query(None),
    rule_id:    Optional[str] = Query(None),
    page:       int = Query(1, ge=1),
    page_size:  int = Query(20, ge=1, le=100),
    db:         AsyncSession = Depends(get_db),
    _:          User = Depends(get_current_user),
):
    q = select(Alert).order_by(desc(Alert.triggered_at))
    if severity:
        q = q.where(Alert.severity == severity)
    if status:
        q = q.where(Alert.status == status)
    if rule_id:
        q = q.where(Alert.rule_id == rule_id)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    alerts = result.scalars().all()

    items = [
        AlertSummary(
            id=str(a.id),
            rule_name=a.rule_name,
            severity=a.severity,
            detection_type=a.detection_type,
            status=a.status,
            host_name=a.host_name,
            user_name=a.user_name,
            source_ip=a.source_ip,
            mitre_tactic=a.mitre_tactic,
            mitre_technique=a.mitre_technique,
            triggered_at=a.triggered_at,
            incident_id=str(a.incident_id) if a.incident_id else None,
        )
        for a in alerts
    ]
    return PaginatedAlerts(total=total, page=page, page_size=page_size, items=items)


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == uuid.UUID(alert_id)))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.raw_alert


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == uuid.UUID(alert_id)))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/{alert_id}/false-positive")
async def false_positive(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == uuid.UUID(alert_id)))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "false_positive"
    await db.commit()
    return {"status": "false_positive", "alert_id": alert_id}
