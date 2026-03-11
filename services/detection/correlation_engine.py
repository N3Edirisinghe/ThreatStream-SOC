"""
Correlation Engine — stateful multi-step attack sequence detection using Redis.
Each rule defines a sequence of conditions; engine tracks per-entity progress
through the sequence within a sliding time window using Redis hash keys.
"""
import hashlib
import json
import logging
import time
import uuid

import redis

log = logging.getLogger("detection.correlation")


def _get_field(event: dict, dotted_key: str):
    if not dotted_key:
        return None
    obj = event
    for p in dotted_key.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


class CorrelationEngine:
    def __init__(self, rules: list, redis_host: str = "redis", redis_port: int = 6379):
        self.rules = [
            r for r in rules
            if r.get("enabled", True)
            and r.get("detection", {}).get("logic_type") == "sequence"
        ]
        try:
            self.redis = redis.Redis(
                host=redis_host, port=redis_port,
                decode_responses=True, socket_connect_timeout=3
            )
            self.redis.ping()
            self.available = True
            log.info(f"CorrelationEngine: Redis connected ({redis_host}:{redis_port}), {len(self.rules)} sequence rules")
        except redis.ConnectionError as e:
            log.warning(f"Redis unavailable: {e} — correlation engine in degraded mode")
            self.available = False

    def evaluate(self, event: dict) -> list[dict]:
        if not self.available or not self.rules:
            return []
        alerts = []
        for rule in self.rules:
            alert = self._check_rule(rule, event)
            if alert:
                alerts.append(alert)
        return alerts

    def _check_rule(self, rule: dict, event: dict) -> dict | None:
        detection = rule.get("detection", {})
        steps     = detection.get("conditions", [])
        window    = detection.get("window_seconds", 300)
        group_by  = detection.get("group_by", [])

        if not steps:
            return None

        group_val = self._group_key(event, group_by)
        state_key = f"corr:{rule['id']}:{group_val}"
        now       = time.time()

        # Load current state
        try:
            raw_state = self.redis.hgetall(state_key)
        except redis.RedisError:
            return None

        current_step = int(raw_state.get("step", 0))
        last_ts      = float(raw_state.get("ts", 0))

        # Expire stale state
        if now - last_ts > window and current_step > 0:
            self.redis.delete(state_key)
            current_step = 0
            last_ts = now

        if current_step >= len(steps):
            # Should not happen — reset
            self.redis.delete(state_key)
            return None

        target = steps[current_step]
        if self._step_matches(event, target):
            next_step = current_step + 1
            try:
                self.redis.hset(state_key, mapping={"step": next_step, "ts": now})
                self.redis.expire(state_key, window + 60)
            except redis.RedisError:
                pass

            if next_step >= len(steps):
                # All steps matched — fire alert!
                try:
                    self.redis.delete(state_key)
                except redis.RedisError:
                    pass
                return self._build_alert(rule, event, group_val)

        return None

    def _step_matches(self, event: dict, condition: dict) -> bool:
        """Match a single condition step dict against an ECS event."""
        # Simple field-equality matching (extend as needed)
        for k, v in condition.items():
            if k.startswith("_"):  # internal meta-keys
                continue
            actual = _get_field(event, k)
            if str(actual) != str(v):
                return False
        return True

    def _group_key(self, event: dict, group_by: list) -> str:
        vals = [str(_get_field(event, f) or "") for f in group_by]
        return hashlib.md5(":".join(vals).encode()).hexdigest()[:12]

    def _build_alert(self, rule: dict, event: dict, group_val: str) -> dict:
        return {
            "id":            str(uuid.uuid4()),
            "rule_id":       rule.get("id"),
            "rule_name":     rule.get("name"),
            "severity":      rule.get("severity", "high"),
            "detection_type": "correlation",
            "mitre":         rule.get("mitre", {}),
            "host_name":     event.get("host.name"),
            "user_name":     event.get("user.name"),
            "source_ip":     event.get("source.ip"),
            "triggered_at":  event.get("@timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_event":  event,
            "correlation_group": group_val,
            "status":        "open",
        }
