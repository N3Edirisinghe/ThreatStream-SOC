"""Linux syslog parser → ECS normalization."""
import json
import re


SYSLOG_REGEX = re.compile(
    r"^(?P<priority><\d+>)?"
    r"(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^:\[]+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.+)$"
)

SSH_AUTH_FAILURE = re.compile(r"authentication failure.*user=(?P<user>\S+)")
SSH_ACCEPTED     = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
SUDO_COMMAND     = re.compile(r"(?P<user>\S+) .*COMMAND=(?P<cmd>.+)$")


class LinuxSyslogParser:
    PARSER_VERSION = "syslog-1.0"

    def parse(self, envelope: dict) -> dict:
        raw = envelope.get("raw_payload", "")
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"message": raw}
        else:
            data = raw

        # Determine timestamp
        ts = (data.get("timestamp")
              or envelope.get("event_timestamp")
              or envelope.get("received_at"))

        message = data.get("message", "")
        facility = data.get("facility", "")
        severity = data.get("severity", "info")
        host     = data.get("host") or envelope.get("source_host", "unknown")
        user     = data.get("user")
        src_ip   = None

        # Classify event
        category = ["process"]
        outcome  = "unknown"
        kind     = "event"

        if "authentication failure" in message.lower():
            category = ["authentication"]
            outcome  = "failure"
            m = SSH_AUTH_FAILURE.search(message)
            if m:
                user = m.group("user")
        elif "accepted" in message.lower() and "for" in message.lower():
            category = ["authentication"]
            outcome  = "success"
            m = SSH_ACCEPTED.search(message)
            if m:
                user   = m.group("user")
                src_ip = m.group("ip")
        elif "COMMAND=" in message:
            category = ["process"]
            outcome  = "success"
            kind     = "event"

        normalized = {
            "@timestamp":     ts,
            "event.kind":     kind,
            "event.category": category,
            "event.outcome":  outcome,
            "host.name":      host,
            "user.name":      user,
            "source.ip":      src_ip,
            "message":        message,
            "log.syslog.facility.name": facility,
            "log.level":      severity,
            "log.original_source_type": "linux_syslog",
            "_soc_meta": {
                "envelope_id":    envelope.get("envelope_id"),
                "ingested_at":    envelope.get("received_at"),
                "parser_version": self.PARSER_VERSION,
            },
        }
        return {k: v for k, v in normalized.items() if v is not None}
