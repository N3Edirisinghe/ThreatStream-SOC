"""Windows Event Log parser → ECS normalization."""
import json
import re
from datetime import datetime, timezone


# Map Windows Event IDs to ECS event categories and outcomes
EVENT_ID_MAP = {
    4624: {"category": ["authentication"], "type": ["start"],  "outcome": "success", "kind": "event"},
    4625: {"category": ["authentication"], "type": ["start"],  "outcome": "failure", "kind": "event"},
    4634: {"category": ["authentication"], "type": ["end"],    "outcome": "success", "kind": "event"},
    4648: {"category": ["authentication"], "type": ["start"],  "outcome": "success", "kind": "event"},
    4657: {"category": ["configuration"],  "type": ["change"], "outcome": "success", "kind": "event"},
    4672: {"category": ["iam"],            "type": ["access"], "outcome": "success", "kind": "event"},
    4673: {"category": ["iam"],            "type": ["access"], "outcome": "unknown",  "kind": "event"},
    4674: {"category": ["iam"],            "type": ["access"], "outcome": "unknown",  "kind": "event"},
    4688: {"category": ["process"],        "type": ["start"],  "outcome": "success", "kind": "event"},
    4698: {"category": ["configuration"],  "type": ["creation"],"outcome": "success","kind": "event"},
    4720: {"category": ["iam"],            "type": ["user","creation"],"outcome": "success","kind": "event"},
    4732: {"category": ["iam"],            "type": ["group","change"],"outcome": "success","kind": "event"},
}


class WindowsEventParser:
    PARSER_VERSION = "winev-1.0"

    def parse(self, envelope: dict) -> dict:
        raw = envelope.get("raw_payload", "{}")
        # raw_payload may be JSON string or a raw dict
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"message": raw}
        else:
            data = raw

        event_id = int(data.get("winlog_event_id", 0) or data.get("EventID", 0))
        ecs_meta  = EVENT_ID_MAP.get(event_id, {
            "category": ["process"], "type": ["info"], "outcome": "unknown", "kind": "event"
        })

        ts = (data.get("timestamp")
              or data.get("TimeCreated")
              or envelope.get("event_timestamp")
              or envelope.get("received_at"))

        normalized = {
            "@timestamp":      ts,
            "event.kind":      ecs_meta["kind"],
            "event.category":  ecs_meta["category"],
            "event.type":      ecs_meta["type"],
            "event.outcome":   ecs_meta["outcome"],
            "host.name":       data.get("host") or envelope.get("source_host", "unknown"),
            "user.name":       data.get("user") or data.get("SubjectUserName"),
            "source.ip":       data.get("source_ip") or data.get("IpAddress"),
            "process.name":    data.get("process_name") or data.get("NewProcessName"),
            "process.args":    data.get("command_line") or data.get("CommandLine"),
            "message":         data.get("message", ""),
            "winlog.event_id": event_id,
            "winlog.logon_type": data.get("logon_type") or data.get("LogonType"),
            "winlog.auth_package": data.get("auth_package") or data.get("AuthenticationPackageName"),
            "registry.path":   data.get("registry_path"),
            "registry.value":  data.get("registry_value_name"),
            "log.original_source_type": "windows_event",
            "_soc_meta": {
                "envelope_id":    envelope.get("envelope_id"),
                "ingested_at":    envelope.get("received_at"),
                "parser_version": self.PARSER_VERSION,
            },
        }

        # Remove None values for cleanliness
        return {k: v for k, v in normalized.items() if v is not None}
