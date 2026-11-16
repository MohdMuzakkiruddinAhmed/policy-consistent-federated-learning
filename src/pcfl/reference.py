"""Candidate-enforcement semantics. The oracle is independently implemented elsewhere.

This is a Python executable specification; it does not replace the planned Rego engine.
"""

from .contracts import ACTIONS, ORGANIZATIONS, positive_integer


def validate_event(event: dict) -> None:
    if not isinstance(event, dict):
        raise ValueError("malformed_policy_event")
    if event.get("org_id") not in ORGANIZATIONS:
        raise ValueError("unknown_organization")
    if not isinstance(event.get("event_id"), str) or not event["event_id"].strip():
        raise ValueError("missing_event_id")
    if not positive_integer(event.get("order")) or not positive_integer(event.get("epoch")):
        raise ValueError("invalid_policy_order")
    if event.get("kind") not in ("GRANT", "CHANGE", "REVOKE", "EXPIRE"):
        raise ValueError("invalid_policy_kind")
    rules = event.get("rules")
    if not isinstance(rules, list):
        raise ValueError("missing_rules")
    if event["kind"] in ("REVOKE", "EXPIRE") and rules:
        raise ValueError("revocation_cannot_allow")
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("effect") not in ("allow", "deny"):
            raise ValueError("invalid_rule")
        if not isinstance(rule.get("purpose"), str) or not rule["purpose"].strip():
            raise ValueError("invalid_purpose")
        if rule.get("action") not in ACTIONS:
            raise ValueError("invalid_action")


def permits(rules: list[dict], purpose: str) -> bool:
    for action in ACTIONS:
        effects = {r["effect"] for r in rules if r["purpose"] == purpose and r["action"] == action}
        if "deny" in effects or "allow" not in effects:
            return False
    return True


def evaluate_history(events: list[dict], query: dict) -> dict:
    """Fail closed; check the start state and each subsequent state through commit."""
    try:
        start, end = query["start_order"], query["commit_order"]
        if not positive_integer(start) or not positive_integer(end) or end < start:
            raise ValueError("invalid_interval")
        if query["org_id"] not in ORGANIZATIONS:
            raise ValueError("unknown_organization")
        if not isinstance(query["purpose"], str) or not query["purpose"].strip():
            raise ValueError("invalid_purpose")
        if sorted(query["actions"]) != sorted(ACTIONS):
            raise ValueError("incomplete_lifecycle_actions")
        relevant_time = []
        for event in events:
            if not isinstance(event, dict) or not positive_integer(event.get("order")):
                raise ValueError("invalid_policy_order")
            if event["order"] <= end:
                validate_event(event)
                relevant_time.append(event)
        ordered = sorted(relevant_time, key=lambda e: e["order"])
        ids, orders, epochs = set(), set(), {}
        for event in ordered:
            if event["event_id"] in ids or event["order"] in orders:
                raise ValueError("duplicate_policy_event")
            ids.add(event["event_id"])
            orders.add(event["order"])
            org = event["org_id"]
            if event["epoch"] != epochs.get(org, 0) + 1:
                raise ValueError("incomplete_policy_history")
            epochs[org] = event["epoch"]
        own = [e for e in ordered if e["org_id"] == query["org_id"]]
        before = [e for e in own if e["order"] <= start]
        if not before:
            raise ValueError("missing_start_policy")
        states = [before[-1]] + [e for e in own if start < e["order"] <= end]
        for state in states:
            if not permits(state["rules"], query["purpose"]):
                return {"valid": False, "reason": "authorization_interrupted",
                        "invalid_order": max(start, state["order"])}
        return {"valid": True, "reason": "continuous_authorization", "invalid_order": None}
    except (KeyError, TypeError, ValueError) as error:
        return {"valid": False, "reason": str(error), "invalid_order": None}
