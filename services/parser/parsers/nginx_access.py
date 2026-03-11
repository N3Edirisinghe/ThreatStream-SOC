"""Nginx access log parser → ECS normalization."""
import json


class NginxAccessParser:
    PARSER_VERSION = "nginx-1.0"

    def parse(self, envelope: dict) -> dict:
        raw = envelope.get("raw_payload", "")
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"message": raw}
        else:
            data = raw

        ts      = data.get("timestamp") or envelope.get("event_timestamp") or envelope.get("received_at")
        status  = int(data.get("status_code", 0))
        outcome = "success" if status < 400 else "failure"

        normalized = {
            "@timestamp":              ts,
            "event.kind":              "event",
            "event.category":          ["web"],
            "event.type":              ["access"],
            "event.outcome":           outcome,
            "host.name":               data.get("host") or envelope.get("source_host", "unknown"),
            "source.ip":               data.get("src_ip"),
            "http.request.method":     data.get("method"),
            "url.path":                data.get("path"),
            "http.response.status_code": status,
            "http.response.bytes":     data.get("bytes_sent"),
            "user_agent.original":     data.get("user_agent"),
            "event.duration":          data.get("request_time_ms"),
            "message":                 f"{data.get('method')} {data.get('path')} {status}",
            "log.original_source_type": "nginx_access",
            "_soc_meta": {
                "envelope_id":    envelope.get("envelope_id"),
                "ingested_at":    envelope.get("received_at"),
                "parser_version": self.PARSER_VERSION,
            },
        }
        return {k: v for k, v in normalized.items() if v is not None}
