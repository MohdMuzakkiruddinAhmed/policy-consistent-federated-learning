"""Allowlist-only experiment logging. Never pass source dataset rows to this API."""

import json

ALLOWED_FIELDS = frozenset({
    "event", "org_id", "update_id", "task_id", "round_id", "run_id", "reason",
    "outcome", "order", "epoch", "digest", "scenario_id", "seed", "count",
    "schema_version", "duration_ms", "correlation_id",
})


def validate_log_record(record: dict) -> None:
    if not isinstance(record, dict) or set(record) - ALLOWED_FIELDS:
        raise ValueError("log_contains_unapproved_fields")
    if not isinstance(record.get("event"), str) or not record["event"]:
        raise ValueError("missing_log_event")
    if any(type(value) not in (str, int, float, bool, type(None)) for value in record.values()):
        raise ValueError("nested_log_payload_forbidden")
    json.dumps(record, allow_nan=False)


def encode_log(record: dict) -> str:
    validate_log_record(record)
    return json.dumps(record, sort_keys=True, allow_nan=False)
