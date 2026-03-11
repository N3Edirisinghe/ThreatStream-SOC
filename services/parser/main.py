"""
SOC Platform — Parser/Normalizer Service
Consumes raw.logs, applies source-specific parsers, emits ECS-normalized
events to normalized.logs and bulk-indexes into OpenSearch.
"""
import json
import logging
import signal
import time
from typing import Any

from confluent_kafka import Consumer, Producer, KafkaError
from opensearchpy import OpenSearch, helpers
from pydantic_settings import BaseSettings

from parsers.windows_event import WindowsEventParser
from parsers.linux_syslog import LinuxSyslogParser
from parsers.firewall_pfsense import PfSenseParser
from parsers.nginx_access import NginxAccessParser

# ─── Settings ─────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    kafka_bootstrap: str = "kafka:9092"
    kafka_consumer_group_parser: str = "soc-parser-group"
    kafka_topic_raw: str = "raw.logs"
    kafka_topic_normalized: str = "normalized.logs"
    kafka_topic_dlq: str = "raw.logs.dlq"
    os_host: str = "opensearch"
    os_port: int = 9200
    os_use_ssl: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","svc":"parser","msg":"%(message)s"}'
)
log = logging.getLogger("parser")

# ─── Parser Registry ──────────────────────────────────────────────────────────

PARSERS: dict[str, Any] = {
    "windows_event":    WindowsEventParser(),
    "linux_syslog":     LinuxSyslogParser(),
    "firewall_pfsense": PfSenseParser(),
    "nginx_access":     NginxAccessParser(),
}


def parse_envelope(envelope: dict) -> dict:
    """
    Dispatch envelope to the correct parser.
    Returns an ECS-normalized event dict.
    Raises ValueError if no parser matches.
    """
    source_type = envelope.get("source_type", "unknown")
    parser = PARSERS.get(source_type)
    if not parser:
        # Generic fallback: wrap raw payload as-is
        return _generic_parse(envelope)
    return parser.parse(envelope)


def _generic_parse(envelope: dict) -> dict:
    """Fallback parser for unknown source types."""
    return {
        "@timestamp": envelope.get("event_timestamp") or envelope.get("received_at"),
        "event.kind": "event",
        "event.category": ["process"],
        "event.outcome": "unknown",
        "host.name": envelope.get("source_host", "unknown"),
        "message": envelope.get("raw_payload", ""),
        "log.original_source_type": envelope.get("source_type", "generic"),
        "_soc_meta": {
            "envelope_id": envelope.get("envelope_id"),
            "ingested_at": envelope.get("received_at"),
            "parser_version": "generic-1.0",
        },
    }


# ─── OpenSearch ───────────────────────────────────────────────────────────────

def get_os_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": settings.os_host, "port": settings.os_port}],
        use_ssl=settings.os_use_ssl,
        verify_certs=False,
        http_compress=True,
        timeout=30,
    )


def get_index_name(timestamp: str) -> str:
    """Return daily index name from ECS @timestamp."""
    try:
        date_part = timestamp[:10].replace("-", ".")
        return f"logs-{date_part}"
    except Exception:
        return f"logs-{time.strftime('%Y.%m.%d')}"


def bulk_index(os_client: OpenSearch, events: list[dict]):
    """Bulk-index a batch of normalized events into OpenSearch."""
    if not events:
        return
    actions = [
        {
            "_index": get_index_name(e.get("@timestamp", "")),
            "_source": e,
        }
        for e in events
    ]
    try:
        success, errors = helpers.bulk(os_client, actions, raise_on_error=False, stats_only=False)
        if errors:
            log.warning(f"OpenSearch bulk errors: {len(errors)} failures")
    except Exception as e:
        log.error(f"OpenSearch bulk failed: {e}")


# ─── Main Consumer Loop ───────────────────────────────────────────────────────

RUNNING = True

def shutdown_handler(sig, frame):
    global RUNNING
    log.info(f"Signal {sig} received — shutting down")
    RUNNING = False

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)


def main():
    log.info("Parser service starting …")

    consumer = Consumer({
        "bootstrap.servers": settings.kafka_bootstrap,
        "group.id": settings.kafka_consumer_group_parser,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
        "session.timeout.ms": 30000,
        "max.poll.interval.ms": 300000,
    })
    consumer.subscribe([settings.kafka_topic_raw])

    producer = Producer({"bootstrap.servers": settings.kafka_bootstrap})
    os_client = get_os_client()

    log.info(f"Subscribed to topic: {settings.kafka_topic_raw}")

    BATCH_SIZE = 100
    BATCH_TIMEOUT_MS = 5000
    batch_normalized: list[dict] = []
    last_flush = time.time()

    while RUNNING:
        msg = consumer.poll(timeout=1.0)

        if msg is None:
            # Flush batch on timeout if we have pending events
            if batch_normalized and (time.time() - last_flush) * 1000 >= BATCH_TIMEOUT_MS:
                _flush(producer, os_client, batch_normalized, settings)
                batch_normalized = []
                last_flush = time.time()
            continue

        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            log.error(f"Kafka error: {msg.error()}")
            continue

        try:
            envelope = json.loads(msg.value().decode("utf-8"))
            normalized = parse_envelope(envelope)
            batch_normalized.append(normalized)
        except Exception as e:
            log.warning(f"Parse error for envelope: {e} — routing to DLQ")
            producer.produce(settings.kafka_topic_dlq, msg.value())
            continue

        if len(batch_normalized) >= BATCH_SIZE:
            _flush(producer, os_client, batch_normalized, settings)
            batch_normalized = []
            last_flush = time.time()

    # Final flush
    if batch_normalized:
        _flush(producer, os_client, batch_normalized, settings)

    consumer.close()
    producer.flush(timeout=10)
    log.info("Parser service stopped.")


def _flush(producer: Producer, os_client: OpenSearch, events: list[dict], cfg: Settings):
    """Emit normalized events to Kafka + OpenSearch."""
    # → Kafka normalized.logs
    for event in events:
        producer.produce(
            cfg.kafka_topic_normalized,
            key=event.get("host.name", "unknown").encode(),
            value=json.dumps(event).encode(),
        )
    producer.poll(0)

    # → OpenSearch bulk index
    bulk_index(os_client, events)
    log.info(f"Flushed {len(events)} normalized events")


if __name__ == "__main__":
    main()
