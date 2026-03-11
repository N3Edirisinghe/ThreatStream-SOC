"""pfSense firewall log parser → ECS normalization."""
import json


class PfSenseParser:
    PARSER_VERSION = "pfsense-1.0"

    def parse(self, envelope: dict) -> dict:
        raw = envelope.get("raw_payload", "")
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"message": raw}
        else:
            data = raw

        ts     = data.get("timestamp") or envelope.get("event_timestamp") or envelope.get("received_at")
        action = data.get("action", "unknown")
        direction = data.get("direction", "unknown")

        outcome = "success" if action == "pass" else "failure"

        normalized = {
            "@timestamp":               ts,
            "event.kind":               "event",
            "event.category":           ["network"],
            "event.type":               ["connection"],
            "event.outcome":            outcome,
            "host.name":                data.get("host") or envelope.get("source_host", "unknown"),
            "source.ip":                data.get("src_ip"),
            "source.port":              data.get("src_port"),
            "destination.ip":           data.get("dst_ip"),
            "destination.port":         data.get("dst_port"),
            "destination.geo.country_iso_code": data.get("dst_geo_country"),
            "network.direction":        direction,
            "network.transport":        (data.get("protocol") or "TCP").lower(),
            "network.bytes":            data.get("bytes"),
            "event.action":             action,
            "message":                  f"Firewall {action} {direction} {data.get('src_ip')} → {data.get('dst_ip')}:{data.get('dst_port')}",
            "log.original_source_type": "firewall_pfsense",
            "_soc_meta": {
                "envelope_id":    envelope.get("envelope_id"),
                "ingested_at":    envelope.get("received_at"),
                "parser_version": self.PARSER_VERSION,
            },
        }
        return {k: v for k, v in normalized.items() if v is not None}
