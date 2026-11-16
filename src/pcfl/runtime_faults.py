"""Explicit bounded research injections; never implicit full-protocol behavior."""

from copy import deepcopy
import re
import time

from .contracts import ORGANIZATIONS, digest


def validate_host_restart(spec, run_id, *, scenario, rounds):
    fields = {"request_id", "org_id", "run_id", "phase", "round_id"}
    if (not isinstance(spec, dict) or set(spec) != fields or spec.get("run_id") != run_id
            or spec.get("org_id") not in ORGANIZATIONS or not isinstance(spec.get("request_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", spec["request_id"])
            or spec.get("phase") not in {"before-case", "between-rounds"}
            or (spec["phase"] == "before-case" and spec.get("round_id") != "initial")
            or (spec["phase"] == "between-rounds" and (spec.get("round_id") != "round-2" or rounds < 2
                or scenario not in {"S7", "duplicate_restart"}))):
        raise ValueError("explicit_bound_host_restart_spec_required")
    return deepcopy(spec)


def host_restart_barrier(ddb, table, spec, *, timeout=300):
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("bounded_host_restart_timeout_required")
    key = {"PK": {"S": "RUN#" + spec["run_id"]}, "SK": {"S": "CONTROL#HOST_RESTART#" + spec["request_id"]}}
    expected = {**spec, "kind": "client_restart"}
    item = {**key, **{name: {"S": value} for name, value in expected.items()}, "status": {"S": "READY"}}
    try:
        ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": item,
            "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)"}}], ClientRequestToken=digest(item)[:36])
    except Exception:
        saved = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item", {})
        if any(saved.get(name) != value for name, value in item.items() if name != "status"):
            raise
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        saved = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item", {})
        if saved.get("status") == {"S": "ACKNOWLEDGED"}:
            allowed = set(item) | {"completed", "old_task_arn_sha256", "new_task_arn_sha256"}
            old, new = saved.get("old_task_arn_sha256", {}).get("S"), saved.get("new_task_arn_sha256", {}).get("S")
            if (set(saved) != allowed or any(saved.get(name) != value for name, value in item.items() if name != "status")
                    or saved.get("completed") != {"BOOL": True} or old == new
                    or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in (old, new))):
                raise ValueError("host_restart_ack_binding_mismatch")
            return {**expected, "status": "ACKNOWLEDGED", "completed": True,
                    "old_task_arn_sha256": old, "new_task_arn_sha256": new}
        if saved != item:
            raise ValueError("host_restart_request_binding_mismatch")
        time.sleep(min(.2, max(0, deadline - time.monotonic())))
    raise TimeoutError("host_client_restart_not_acknowledged")


class AuditTransportGate:
    """Block an actual audit transaction at SDK dispatch, not a provider outage."""
    def __init__(self, client):
        self.client, self.armed, self.blocked_calls = client, False, 0

    def __getattr__(self, name):
        return getattr(self.client, name)

    def transact_write_items(self, **request):
        audit = any(action.get("Put", {}).get("Item", {}).get("SK", {}).get("S", "").startswith("AUDIT#")
                    for action in request.get("TransactItems", []))
        if self.armed and audit:
            self.blocked_calls += 1
            raise OSError("scripted_audit_SDK_transport_unavailable_before_dispatch")
        return self.client.transact_write_items(**request)
