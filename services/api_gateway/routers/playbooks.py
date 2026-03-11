from fastapi import APIRouter, Depends
from typing import List
from models import User
from deps import get_current_user

router = APIRouter()

# Full playbook definitions with trigger conditions and automated actions
PLAYBOOKS = [
    {
        "id": "pb-isolate-host",
        "name": "Isolate Compromised Host",
        "trigger": "critical / ransomware",
        "action": "EDR network isolation",
        "enabled": True,
        "description": "Network isolation for suspected ransomware or lateral movement.",
        "category": "Containment",
        "steps": [
            "Validate alert context",
            "Identify host MAC/IP",
            "Apply EDR isolation policy",
            "Notify host owner"
        ]
    },
    {
        "id": "pb-block-ip",
        "name": "Block Malicious IPv4",
        "trigger": "high / exfiltration",
        "action": "Firewall blacklist IP",
        "enabled": True,
        "description": "Blacklist external IP at the perimeter firewall.",
        "category": "Prevention",
        "steps": [
            "Extract source IP",
            "Check Threat Intel reputation",
            "Update PaloAlto/FortiGate DB",
            "Verify traffic drop"
        ]
    },
    {
        "id": "pb-reset-password",
        "name": "Force Password Reset",
        "trigger": "critical / credential",
        "action": "Disable AD account + reset",
        "enabled": True,
        "description": "Invalidate AD session and force reset for compromised credentials.",
        "category": "Remediation",
        "steps": [
            "Disable AD User Account",
            "Revoke OAuth Tokens",
            "Generate random temp pass",
            "Log remediation action"
        ]
    }
]


@router.get("")
async def list_playbooks(_: User = Depends(get_current_user)):
    return PLAYBOOKS


@router.put("/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, _: User = Depends(get_current_user)):
    pb = next((p for p in PLAYBOOKS if p["id"] == playbook_id), None)
    if not pb:
        return {"status": "error", "msg": f"Playbook {playbook_id} not found"}
    return {
        "status": "success",
        "playbook_id": playbook_id,
        "name": pb["name"],
        "msg": f"Playbook '{pb['name']}' initiated — executing {len(pb['steps'])} steps",
        "steps": pb["steps"]
    }
