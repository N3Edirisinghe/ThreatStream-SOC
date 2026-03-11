"""
SOC Platform — Alert Consumer
Consumes 'alerts' topic from Kafka and persists them to PostgreSQL.
"""
import json
import logging
import asyncio
from datetime import datetime
from confluent_kafka import Consumer, KafkaError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import AsyncSessionLocal
from models import Alert, Incident

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("alert-consumer")

async def consume_alerts(bootstrap_servers: str):
    conf = {
        'bootstrap.servers': bootstrap_servers,
        'group.id': 'api-gateway-alert-persistence',
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': True
    }

    consumer = Consumer(conf)
    consumer.subscribe(['alerts'])

    logger.info(f"Started Alert Consumer (listening on {bootstrap_servers})")

    try:
        while True:
            # Run in a thread-safe way for Kafka poll
            msg = await asyncio.to_thread(consumer.poll, 1.0)
            
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka error: {msg.error()}")
                continue

            try:
                alert_data = json.loads(msg.value().decode('utf-8'))
                logger.info(f"Processing alert: {alert_data.get('rule_name')}")

                async with AsyncSessionLocal() as db:
                    new_alert = Alert(
                        rule_id=alert_data.get("rule_id"),
                        rule_name=alert_data.get("rule_name"),
                        severity=alert_data.get("severity"),
                        detection_type=alert_data.get("detection_type", "rule"),
                        status="open",
                        host_name=alert_data.get("host_name"),
                        user_name=alert_data.get("user_name"),
                        source_ip=alert_data.get("source_ip"),
                        mitre_tactic=alert_data.get("mitre", {}).get("tactic"),
                        mitre_technique=alert_data.get("mitre", {}).get("technique"),
                        raw_alert=alert_data,
                        triggered_at=datetime.fromisoformat(alert_data.get("triggered_at").replace("Z", "+00:00"))
                    )
                    db.add(new_alert)
                    
                    # Auto-escalate high/critical alerts to Incidents
                    if alert_data.get("severity") in ("high", "critical"):
                        new_incident = Incident(
                            title=f"Auto-Escalated: {alert_data.get('rule_name')}",
                            description=f"Automated incident for critical alert on host {alert_data.get('host_name')}",
                            severity="critical",
                            status="open",
                            source_alert_id=str(new_alert.id),
                            mitre_tactic=alert_data.get("mitre", {}).get("tactic"),
                            mitre_technique=alert_data.get("mitre", {}).get("technique"),
                        )
                        db.add(new_incident)
                        logger.info(f"Auto-escalated alert {new_alert.id} to incident {new_incident.id}")

                    await db.commit()
                    logger.info(f"Persisted alert {new_alert.id} to DB")

            except Exception as e:
                logger.error(f"Error persisting alert: {e}")

    finally:
        consumer.close()
