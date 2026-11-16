"""Independent authorization-history reference model.

This module deliberately imports no PCFL implementation code. It consumes plain
JSON-shaped records so production decisions can be compared with an independently
coded specification. Logical authority order, never client timestamps, decides
whether an update has remained authorized through publication.
"""

from collections.abc import Mapping, Sequence


_LIFECYCLE_ACTIONS = frozenset({"train", "submit_update", "aggregate"})
_EVENT_KINDS = frozenset({"GRANT", "REVOKE", "EXPIRE", "CHANGE"})
# The study contains exactly eight fictional organizations. This independent
# declaration intentionally does not import the candidate implementation registry.
_STUDY_ORGANIZATIONS = frozenset({
    "org_01", "org_02", "org_03", "org_04",
    "org_05", "org_06", "org_07", "org_08",
})


def _result(valid, reason, order=None):
    return {"valid": valid, "reason": reason, "invalid_order": order}


def _positive_integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def _is_sequence(value):
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def evaluate_interval(events, query):
    """Return a fail-closed decision for the inclusive lifecycle interval.

    Events contain replacement rule sets, not deltas. Every lifecycle action
    needs an exact purpose/action allow, and any matching deny takes precedence.
    Missing policy state is a denial. An invalid state anywhere between start
    and commit permanently invalidates that lifecycle, even after regrant.

    Events may be supplied in any delivery order. Authority-assigned ``order``
    values are unique globally; epochs must start at one and increase by one for
    each organization. All supplied history through commit is validated. Future
    events are ignored before validating their other fields because later policy
    changes cannot invalidate a past publication. An unreadable order fails
    closed because its temporal relevance cannot be established.
    """
    if not isinstance(query, Mapping):
        return _result(False, "malformed_query")
    org = query.get("org_id")
    purpose = query.get("purpose")
    start = query.get("start_order")
    commit = query.get("commit_order")
    actions = query.get("actions")
    if (
        not _nonempty_string(org)
        or org not in _STUDY_ORGANIZATIONS
        or not _nonempty_string(purpose)
        or not _positive_integer(start)
        or not _positive_integer(commit)
        or start > commit
        or not _is_sequence(actions)
        or not all(isinstance(action, str) for action in actions)
        or len(actions) != len(_LIFECYCLE_ACTIONS)
        or frozenset(actions) != _LIFECYCLE_ACTIONS
    ):
        return _result(False, "malformed_query")
    if not _is_sequence(events):
        return _result(False, "malformed_history")

    past = []
    for event in events:
        if not isinstance(event, Mapping) or not _positive_integer(event.get("order")):
            return _result(False, "malformed_history")
        if event["order"] <= commit:
            past.append(event)
    past.sort(key=lambda event: event["order"])

    seen_ids = set()
    seen_orders = set()
    previous_epochs = {}
    for event in past:
        order = event["order"]
        event_id = event.get("event_id")
        event_org = event.get("org_id")
        epoch = event.get("epoch")
        kind = event.get("kind")
        rules = event.get("rules")
        if (
            not _nonempty_string(event_id)
            or not _nonempty_string(event_org)
            or event_org not in _STUDY_ORGANIZATIONS
            or not _positive_integer(epoch)
            or not isinstance(kind, str)
            or kind not in _EVENT_KINDS
            or not _is_sequence(rules)
        ):
            return _result(False, "malformed_history", order)
        if event_id in seen_ids or order in seen_orders:
            return _result(False, "duplicate_history_identity", order)
        seen_ids.add(event_id)
        seen_orders.add(order)
        if epoch != previous_epochs.get(event_org, 0) + 1:
            return _result(False, "incomplete_epoch_history", order)
        previous_epochs[event_org] = epoch
        if kind in {"REVOKE", "EXPIRE"} and rules:
            return _result(False, "malformed_history", order)
        for rule in rules:
            if (
                not isinstance(rule, Mapping)
                or not _nonempty_string(rule.get("purpose"))
                or not isinstance(rule.get("action"), str)
                or rule["action"] not in _LIFECYCLE_ACTIONS
                or not isinstance(rule.get("effect"), str)
                or rule["effect"] not in {"allow", "deny"}
            ):
                return _result(False, "malformed_history", order)

    states = [event for event in past if event["org_id"] == org]
    preceding = [event for event in states if event["order"] <= start]
    if not preceding:
        return _result(False, "missing_start_policy", start)
    active = preceding[-1]
    checkpoints = [(start, active)]
    checkpoints.extend(
        (event["order"], event) for event in states if start < event["order"] <= commit
    )
    for order, state in checkpoints:
        for action in actions:
            matching = [
                rule["effect"]
                for rule in state["rules"]
                if rule["purpose"] == purpose and rule["action"] == action
            ]
            if "deny" in matching:
                return _result(False, "explicit_deny", order)
            if "allow" not in matching:
                reason = "expired" if state["kind"] == "EXPIRE" else "not_authorized"
                return _result(False, reason, order)
    return _result(True, "continuous_authorization")
