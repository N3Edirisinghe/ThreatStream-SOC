from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import httpx
import os
import json
import asyncio
from models import User
from deps import require_role

router = APIRouter()

INGESTION_URL = os.getenv("INGESTION_URL", "http://ingestion-api:8001/api/v1/ingest/batch")
DATA_DIR = os.getenv("DATA_DIR", "/app/data/sample_logs")

class SimulationRequest(BaseModel):
    scenario: str

async def run_ingestion_task(filepath: str):
    """Background task to read a file and send batches to ingestion API."""
    if not os.path.exists(filepath):
        print(f"Simulation file not found: {filepath}")
        return

    async with httpx.AsyncClient() as client:
        with open(filepath, "r") as f:
            batch = []
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    data = json.loads(line)
                    batch.append({
                        "source_type": data.get("source_type", "generic"),
                        "host": data.get("host", "unknown"),
                        "message": json.dumps(data),
                        "timestamp": data.get("timestamp"),
                        "metadata": {k: v for k, v in data.items() if k not in ("source_type", "host", "message", "timestamp")}
                    })
                except: continue

                if len(batch) >= 100:
                    try:
                        await client.post(INGESTION_URL, json={"events": batch}, timeout=10.0)
                    except Exception as e:
                        print(f"Simulation ingestion error: {e}")
                    batch = []
                    await asyncio.sleep(0.1) # Throttling

            if batch:
                await client.post(INGESTION_URL, json={"events": batch}, timeout=10.0)

@router.post("")
async def trigger_simulation(
    body: SimulationRequest,
    _: User = Depends(require_role("admin"))
):
    # Mapping scenarios to files
    mapping = {
        "ransomware": "synthetic_attacks_ground_truth.jsonl",
        "exfiltration": "synthetic_attacks_ground_truth.jsonl" # In a larger system these would be different
    }

    filename = mapping.get(body.scenario)
    if not filename:
        raise HTTPException(status_code=400, detail="Unknown simulation scenario")

    filepath = os.path.join(DATA_DIR, filename)
    
    # Run in background to not block the request
    asyncio.create_task(run_ingestion_task(filepath))

    return {
        "status": "success", 
        "scenario": body.scenario, 
        "msg": f"Simulation '{body.scenario}' started. Logs are being streamed to ingestion pipeline."
    }
