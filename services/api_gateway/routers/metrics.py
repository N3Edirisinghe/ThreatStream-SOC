"""Metrics / KPI router — SOC performance indicators."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from database import get_db
from models import Alert, Incident, User
from deps import get_current_user

router = APIRouter()


@router.get("/kpi")
async def kpi_summary(
    days: int = Query(7, ge=1, le=90),
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(get_current_user),
):
    """Return key SOC performance indicators for a rolling window."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Total alerts in window
    total_alerts = (await db.execute(
        select(func.count()).where(Alert.triggered_at >= since)
    )).scalar_one()

    # Open incidents
    open_incidents = (await db.execute(
        select(func.count()).where(
            and_(Incident.opened_at >= since, Incident.status == "open")
        )
    )).scalar_one()

    # Critical open incidents
    critical_open = (await db.execute(
        select(func.count()).where(
            and_(Incident.status == "open", Incident.severity == "critical")
        )
    )).scalar_one()

    # False positive count
    fp_count = (await db.execute(
        select(func.count()).where(
            and_(Alert.triggered_at >= since, Alert.status == "false_positive")
        )
    )).scalar_one()

    # MTTR — average resolution time for resolved incidents (in minutes)
    resolved = (await db.execute(
        select(Incident).where(
            and_(
                Incident.opened_at >= since,
                Incident.status.in_(["resolved", "closed"]),
                Incident.resolved_at.isnot(None)
            )
        )
    )).scalars().all()

    mttr_minutes = None
    if resolved:
        deltas = [
            (i.resolved_at - i.opened_at).total_seconds() / 60
            for i in resolved
        ]
        mttr_minutes = round(sum(deltas) / len(deltas), 1)

    fp_rate = round(fp_count / total_alerts, 3) if total_alerts > 0 else 0.0
    tp_rate = round(1.0 - fp_rate, 3)

    return {
        "period": f"last_{days}_days",
        "total_alerts":        total_alerts,
        "open_incidents":      open_incidents,
        "critical_incidents":  critical_open,
        "false_positive_count": fp_count,
        "false_positive_rate": fp_rate,
        "true_positive_rate":  tp_rate,
        "mttr_minutes":        mttr_minutes,
        "mttd_minutes":        None,  # Requires event timestamp vs alert timestamp — future enhancement
    }


@router.get("/alert-volume")
async def alert_volume(
    days: int = Query(7, ge=1, le=30),
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(get_current_user),
):
    """Daily alert counts for sparklines and bar charts."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Alert.triggered_at, Alert.severity).where(Alert.triggered_at >= since)
    )
    rows = result.all()

    # Bucket by day
    daily: dict[str, dict] = {}
    for ts, sev in rows:
        day = ts.strftime("%Y-%m-%d")
        if day not in daily:
            daily[day] = {"date": day, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        daily[day]["total"] += 1
        if sev in daily[day]:
            daily[day][sev] += 1

    return {"period_days": days, "data": sorted(daily.values(), key=lambda x: x["date"])}


@router.get("/attack-heatmap")
async def attack_heatmap(
    days: int = Query(7, ge=1, le=30),
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(get_current_user),
):
    """Aggregate alert counts by MITRE Tactic."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Alert.mitre_tactic, func.count())
        .where(and_(Alert.triggered_at >= since, Alert.mitre_tactic.isnot(None)))
        .group_by(Alert.mitre_tactic)
    )
    rows = result.all()

    return [
        {"tactic": tactic, "count": count}
        for tactic, count in rows
    ]
