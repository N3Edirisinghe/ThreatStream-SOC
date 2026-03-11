"""
SOC Platform — Detection Engine
Consumes normalized.logs, evaluates every event against:
  1. Rule-based engine  (single-event field matching + threshold)
  2. Correlation engine (stateful multi-step via Redis)
Positive matches are produced to Kafka topic: alerts
"""
import json
import logging
import os
import signal
import time
import uuid
from pathlib import Path

from confluent_kafka import Consumer, Producer, KafkaError
from pydantic_settings import BaseSettings

from rule_engine import RuleEngine
from correlation_engine import CorrelationEngine

# ─── Settings ─────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    kafka_bootstrap: str = "kafka:9092"
    kafka_consumer_group_detection: str = "soc-detection-group"
    kafka_topic_normalized: str = "normalized.logs"
    kafka_topic_alerts: str = "alerts"
    redis_host: str = "redis"
    redis_port: int = 6379
    rules_dir: str = "/app/rules"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","svc":"detection","msg":"%(message)s"}'
)
log = logging.getLogger("detection")

# ─── Shutdown ─────────────────────────────────────────────────────────────────

RUNNING = True

def shutdown_handler(sig, frame):
    global RUNNING
    log.info(f"Signal {sig} — shutting down")
    RUNNING = False

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ─── Alert Factory ────────────────────────────────────────────────────────────

def build_alert(rule: dict, event: dict, detection_type: str = "rule") -> dict:
    return {
        "id":            str(uuid.uuid4()),
        "rule_id":       rule.get("id"),
        "rule_name":     rule.get("name"),
        "severity":      rule.get("severity", "medium"),
        "detection_type": detection_type,
        "mitre":         rule.get("mitre", {}),
        "host_name":     event.get("host.name"),
        "user_name":     event.get("user.name"),
        "source_ip":     event.get("source.ip"),
        "triggered_at":  event.get("@timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_event":  event,
        "status":        "open",
    }

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    log.info(f"Detection engine starting with KAFKA={settings.kafka_bootstrap} GROUP={settings.kafka_consumer_group_detection}")

    # Load rules from /app/rules/*.json
    rules_path = Path(settings.rules_dir)
    rules = []
    for rule_file in sorted(rules_path.glob("*.json")):
        try:
            with open(rule_file) as f:
                rules.append(json.load(f))
            log.info(f"Loaded rule: {rule_file.name}")
        except Exception as e:
            log.error(f"Failed to load rule {rule_file}: {e}")

    if not rules:
        log.warning("No rules loaded! Check /app/rules directory.")

    rule_engine = RuleEngine(rules)
    correlation_engine = CorrelationEngine(
        rules,
        redis_host=settings.redis_host,
        redis_port=settings.redis_port,
    )

    consumer = Consumer({
        "bootstrap.servers": settings.kafka_bootstrap,
        "group.id": settings.kafka_consumer_group_detection,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
    })
    consumer.subscribe([settings.kafka_topic_normalized])

    producer = Producer({"bootstrap.servers": settings.kafka_bootstrap})

    log.info(f"Subscribed to {settings.kafka_topic_normalized} | {len(rules)} rules loaded")

    stats = {"processed": 0, "alerts": 0}
    last_stats_log = time.time()

    while RUNNING:
        msg = consumer.poll(timeout=1.0)

        if msg is None:
            if time.time() - last_stats_log > 60:
                log.info(f"Stats: processed={stats['processed']} alerts={stats['alerts']}")
                last_stats_log = time.time()
            continue

        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                log.error(f"Kafka error: {msg.error()}")
            continue

        try:
            event = json.loads(msg.value().decode("utf-8"))
            stats["processed"] += 1

            # ── Rule-based evaluation ───────────────────────────────────────
            matched_rules = rule_engine.evaluate(event)
            for rule in matched_rules:
                alert = build_alert(rule, event, detection_type="rule")
                _emit_alert(producer, alert, settings.kafka_topic_alerts)
                stats["alerts"] += 1

            # ── Correlation evaluation ──────────────────────────────────────
            corr_alerts = correlation_engine.evaluate(event)
            for alert in corr_alerts:
                _emit_alert(producer, alert, settings.kafka_topic_alerts)
                stats["alerts"] += 1

        except Exception as e:
            log.error(f"Detection error: {e}", exc_info=True)

    consumer.close()
    producer.flush(timeout=10)
    log.info(f"Detection engine stopped. Final stats: {stats}")


def _emit_alert(producer: Producer, alert: dict, topic: str):
    producer.produce(
        topic,
        key=alert.get("host_name", "unknown").encode(),
        value=json.dumps(alert).encode(),
    )
    producer.poll(0)


if __name__ == "__main__":
    main()
