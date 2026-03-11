"""
Rule Engine — single-event, field-matching/threshold detection.
Loads JSON rule definitions and evaluates one ECS event at a time.
"""
import logging
import re
import time
from collections import defaultdict

log = logging.getLogger("detection.rule_engine")

# In-memory threshold state: {(rule_id, group_key): [timestamps]}
_threshold_state: dict[str, list] = defaultdict(list)


class RuleEngine:
    def __init__(self, rules: list):
        self.rules = [r for r in rules
                      if r.get("enabled", True)
                      and r.get("detection", {}).get("logic_type") in ("field_match", "threshold")]
        log.info(f"RuleEngine loaded {len(self.rules)} rules")

    def evaluate(self, event: dict) -> list[dict]:
        """Evaluate one ECS event. Returns list of matched rule dicts."""
        matched = []
        for rule in self.rules:
            try:
                if self._matches(rule, event):
                    matched.append(rule)
            except Exception as e:
                log.warning(f"Rule {rule.get('id')} eval error: {e}")
        return matched

    def _matches(self, rule: dict, event: dict) -> bool:
        detection = rule.get("detection", {})
        logic = detection.get("logic_type")

        if logic == "field_match":
            return self._eval_conditions(detection.get("conditions", []), event)

        if logic == "threshold":
            # First check if base conditions match
            if not self._eval_conditions(detection.get("conditions", []), event):
                return False
            return self._eval_threshold(rule, event, detection)

        return False

    def _eval_conditions(self, conditions: list, event: dict) -> bool:
        """ALL conditions must pass (AND logic)."""
        for cond in conditions:
            if not self._eval_single(cond, event):
                return False
        return True

    def _eval_single(self, cond: dict, event: dict) -> bool:
        field  = cond.get("field")
        op     = cond.get("op")
        value  = cond.get("value")
        actual = _get_field(event, field)

        if actual is None:
            return False

        if op == "equals":
            return str(actual).lower() == str(value).lower()
        if op == "not_equals":
            return str(actual).lower() != str(value).lower()
        if op == "in":
            return actual in value
        if op == "not_in":
            return actual not in value
        if op == "contains":
            return str(value).lower() in str(actual).lower()
        if op == "regex":
            return bool(re.search(value, str(actual), re.IGNORECASE))
        if op == "greater_than":
            try:
                return float(actual) > float(value)
            except (TypeError, ValueError):
                return False
        if op == "in_threat_intel_list":
            # Stub: in MVP always False unless you load a list file
            return False

        return False

    def _eval_threshold(self, rule: dict, event: dict, detection: dict) -> bool:
        """Sliding-window threshold: count occurrences of matching events per group."""
        rule_id   = rule.get("id", "unknown")
        threshold = detection.get("threshold", 5)
        window    = detection.get("window_seconds", 60)
        group_by  = detection.get("group_by", [])

        # Build a group key from event fields
        group_val = ":".join(str(_get_field(event, f) or "") for f in group_by)
        state_key = f"{rule_id}:{group_val}"

        now = time.time()
        cutoff = now - window

        # Record this timestamp
        _threshold_state[state_key].append(now)

        # Purge old timestamps outside window
        _threshold_state[state_key] = [t for t in _threshold_state[state_key] if t >= cutoff]

        count = len(_threshold_state[state_key])

        if count >= threshold:
            # Reset after firing to avoid duplicate alerts every event
            _threshold_state[state_key] = []
            log.debug(f"Threshold rule {rule_id} fired: {count} occurrences in {window}s (key={group_val})")
            return True

        return False


def _get_field(event: dict, dotted_key: str):
    """
    Traverse ECS field path. 
    Supports both flattened ("user.name": "val") and nested ({"user": {"name": "val"}}) keys.
    """
    if not dotted_key:
        return None
        
    # 1. Try flattened key first (common in ECS/JSON logs)
    if dotted_key in event:
        return event[dotted_key]
        
    # 2. Try nested traversal
    parts = dotted_key.split(".")
    obj = event
    for p in parts:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj
