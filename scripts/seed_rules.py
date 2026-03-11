import asyncio
import json
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from pathlib import Path

async def main():
    db_url = "postgresql+asyncpg://soc_app:changeme123@localhost:5432/soc_db"
    engine = create_async_engine(db_url)
    
    rules_dir = Path("services/detection/rules")
    
    async with engine.begin() as conn:
        for rule_file in rules_dir.glob("*.json"):
            rule_data = json.loads(rule_file.read_text())
            
            # Upsert rule
            await conn.execute(
                text("""
                    INSERT INTO detection_rules (rule_id, name, version, enabled, severity, rule_json)
                    VALUES (:rule_id, :name, :version, :enabled, :severity, :rule_json)
                    ON CONFLICT (rule_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        version = EXCLUDED.version,
                        enabled = EXCLUDED.enabled,
                        severity = EXCLUDED.severity,
                        rule_json = EXCLUDED.rule_json
                """),
                {
                    "rule_id": rule_data["id"],
                    "name": rule_data["name"],
                    "version": rule_data.get("version", 1),
                    "enabled": rule_data.get("enabled", True),
                    "severity": rule_data["severity"],
                    "rule_json": json.dumps(rule_data)
                }
            )
            print(f"Seeded rule: {rule_data['id']}")

    print("Detection rules seeded successfully")

asyncio.run(main())
