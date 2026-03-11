"""
SOC Platform — Ingestion API Service
Accepts log events from any source (HTTP POST, JSON Lines batches, file upload)
and reliably enqueues them to Kafka topic: raw.logs
"""
import base64
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from confluent_kafka import Producer, KafkaException
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# ─── Configuration ────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    kafka_bootstrap: str = "kafka:9092"
    kafka_topic_raw: str = "raw.logs"
    kafka_topic_dlq: str = "raw.logs.dlq"
    ingestion_port: int = 8001

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("ingestion")

# ─── Kafka Producer ───────────────────────────────────────────────────────────

_producer: Producer | None = None

def get_producer() -> Producer:
    global _producer
    if _producer is None:
        _producer = Producer({
            "bootstrap.servers": settings.kafka_bootstrap,
            "socket.timeout.ms": 5000,
            "request.timeout.ms": 5000,
            "retries": 3,
        })
    return _producer


def delivery_report(err, msg):
    if err:
        log.error(f"Kafka delivery failed: {err} for topic={msg.topic()}")
    else:
        log.debug(f"Delivered to {msg.topic()} [{msg.partition()}] @ offset {msg.offset()}")


# ─── Pydantic Models ──────────────────────────────────────────────────────────

class LogEvent(BaseModel):
    """A single log event from any source."""
    source_type: str = Field(..., description="windows_event | linux_syslog | firewall_pfsense | nginx_access | generic")
    host: str = Field(..., description="Originating hostname or IP")
    message: str = Field(..., description="Raw log message or JSON-encoded log string")
    timestamp: str | None = Field(None, description="ISO8601 timestamp; uses server time if omitted")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extra key-value fields")


class BatchIngestRequest(BaseModel):
    events: list[LogEvent] = Field(..., min_length=1, max_length=1000)


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Ingestion API starting — connecting to Kafka …")
    try:
        p = get_producer()
        p.poll(0)  # trigger metadata fetch
        log.info(f"Kafka producer ready → {settings.kafka_bootstrap}")
    except Exception as e:
        log.warning(f"Kafka not yet available: {e} — will retry on first request")
    yield
    # Flush on shutdown
    if _producer:
        log.info("Flushing Kafka producer …")
        _producer.flush(timeout=10)
    log.info("Ingestion API stopped.")


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SOC Ingestion API",
    version="1.0.0",
    description="Receives log events from all sources and enqueues to Kafka",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def build_envelope(event: LogEvent) -> dict:
    """Wrap a raw log event in a standardised Kafka envelope."""
    return {
        "envelope_id": str(uuid.uuid4()),
        "source_type": event.source_type,
        "source_host": event.host,
        "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_timestamp": event.timestamp,
        "raw_payload": event.message,
        "metadata": event.metadata,
    }


def produce_event(envelope: dict, topic: str | None = None) -> bool:
    """Produce one envelope to Kafka. Returns False on failure."""
    target = topic or settings.kafka_topic_raw
    try:
        producer = get_producer()
        producer.produce(
            target,
            key=envelope["source_host"].encode(),
            value=json.dumps(envelope).encode(),
            callback=delivery_report,
        )
        producer.poll(0)
        return True
    except (KafkaException, BufferError) as e:
        log.error(f"Failed to produce to {target}: {e}")
        return False


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ingestion-api", "kafka": settings.kafka_bootstrap}


@app.post("/api/v1/ingest/event", status_code=202)
async def ingest_single_event(event: LogEvent):
    """
    Ingest a single log event.
    Returns 202 Accepted when queued to Kafka.
    """
    envelope = build_envelope(event)
    ok = produce_event(envelope)
    if not ok:
        # On failure, route to DLQ
        produce_event(envelope, topic=settings.kafka_topic_dlq)
        raise HTTPException(status_code=500, detail="Event routed to DLQ — Kafka delivery failed")
    return {"status": "queued", "envelope_id": envelope["envelope_id"]}


@app.post("/api/v1/ingest/batch", status_code=202)
async def ingest_batch(batch: BatchIngestRequest, bg: BackgroundTasks):
    """
    Ingest a batch of up to 1000 events.
    Processing happens asynchronously in background.
    Returns immediately with a batch ID.
    """
    batch_id = str(uuid.uuid4())
    envelopes = [build_envelope(e) for e in batch.events]

    async def _produce_all():
        ok_count = 0
        dlq_count = 0
        for env in envelopes:
            if produce_event(env):
                ok_count += 1
            else:
                produce_event(env, topic=settings.kafka_topic_dlq)
                dlq_count += 1
        if _producer:
            _producer.flush(timeout=30)
        log.info(f"Batch {batch_id}: {ok_count} queued, {dlq_count} to DLQ")

    bg.add_task(_produce_all)
    return {"status": "accepted", "batch_id": batch_id, "event_count": len(envelopes)}


@app.post("/api/v1/ingest/file")
async def ingest_jsonl_file(request: Request, bg: BackgroundTasks):
    """
    Accept a raw JSON Lines file upload (multipart or raw body).
    Each line is one log event JSON. Max 5MB.
    """
    body = await request.body()
    if len(body) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large (max 5MB)")

    lines = body.decode("utf-8", errors="replace").splitlines()
    events = []
    parse_errors = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            events.append(LogEvent(
                source_type=data.get("source_type", "generic"),
                host=data.get("host", "unknown"),
                message=json.dumps(data),
                timestamp=data.get("timestamp"),
                metadata={k: v for k, v in data.items() if k not in ("source_type", "host", "message", "timestamp")},
            ))
        except (json.JSONDecodeError, Exception):
            parse_errors += 1

    if not events:
        raise HTTPException(status_code=400, detail="No valid JSON Lines found in body")

    batch = BatchIngestRequest(events=events)
    return await ingest_batch(batch, bg)
