"""Detection rules router — admin CRUD for rules."""
import uuid
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from database import get_db
from models import DetectionRule, User
from deps import get_current_user, require_role

router = APIRouter()


class RuleCreate(BaseModel):
    rule_id:  str
    name:     str
    severity: str
    enabled:  bool = True
    rule_json: dict[str, Any]


@router.get("")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _:  User = Depends(get_current_user),
):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.rule_id))
    rules  = result.scalars().all()
    return [
        {
            "id":       str(r.id),
            "rule_id":  r.rule_id,
            "name":     r.name,
            "severity": r.severity,
            "enabled":  r.enabled,
            "version":  r.version,
        }
        for r in rules
    ]


@router.post("", status_code=201)
async def create_rule(
    body: RuleCreate,
    db:   AsyncSession = Depends(get_db),
    _:    User = Depends(require_role("admin")),
):
    rule = DetectionRule(
        rule_id=body.rule_id,
        name=body.name,
        severity=body.severity,
        enabled=body.enabled,
        rule_json=body.rule_json,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"id": str(rule.id), "rule_id": rule.rule_id}


@router.put("/{rule_id}")
async def update_rule(
    rule_id: str,
    body:    RuleCreate,
    db:      AsyncSession = Depends(get_db),
    _:       User = Depends(require_role("admin")),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule   = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.name      = body.name
    rule.severity  = body.severity
    rule.enabled   = body.enabled
    rule.rule_json = body.rule_json
    rule.version  += 1
    rule.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"rule_id": rule_id, "version": rule.version}


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db:      AsyncSession = Depends(get_db),
    _:       User = Depends(require_role("admin")),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule   = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
