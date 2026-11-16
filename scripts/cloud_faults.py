"""Explicit, bounded operator restarts of recorded learning tasks only.

The coordinator controls the pause through an exact DynamoDB record. The host
acknowledges only after observing a replacement and seven unchanged live peers.
"""
from datetime import datetime, timezone
import hashlib
import re
import time

ORGS = {f"org_{number:02d}" for number in range(1, 9)}
FIELDS = ("request_id", "org_id", "run_id", "phase", "round_id")


def validate_restarts(specs):
    if not isinstance(specs, list) or len(specs) > 32:
        raise ValueError("bounded_explicit_host_restarts_required")
    seen = set()
    for spec in specs:
        if (not isinstance(spec, dict) or set(spec) != set(FIELDS)
                or any(not isinstance(spec[field], str) or not spec[field] for field in FIELDS)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", spec["request_id"])
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,79}", spec["run_id"])
                or spec["org_id"] not in ORGS or spec["phase"] not in {"before-case", "between-rounds"}
                or (spec["phase"] == "before-case" and spec["round_id"] != "initial")
                or (spec["phase"] == "between-rounds" and not re.fullmatch(r"round-[1-9][0-9]{0,2}", spec["round_id"]))
                or spec["request_id"] in seen):
            raise ValueError("invalid_or_duplicate_host_restart")
        seen.add(spec["request_id"])
    return specs


def learning_tasks(rows):
    return {name: row for row in rows for name in ORGS
            if row.get("last_status") == "RUNNING" and row.get("effective_commands") == {name: ["client"]}}


def unchanged_peers(rows, before, target):
    live = learning_tasks(rows)
    return all(name in live and all(live[name].get(field) == old.get(field) and old.get(field)
               for field in ("task_arn", "private_ip")) for name, old in before.items() if name != target)


def validate_restart_evidence(inventory):
    """Replay retained SDK/control bindings without calling AWS."""
    from validate_cloud_placement import sha, validate_snapshot
    application = inventory.get("application_campaign_id", inventory.get("campaign_id"))
    specs = inventory.get("host_restart_requests_by_application", {}).get(application, [])
    checked = []
    try:
        validate_restarts(specs)
        for spec in specs:
            event = inventory["client_restart_events"][spec["request_id"]]
            if (event["spec"] != spec or event["application_campaign_id"] != application or event["completed"] is not True
                    or event["runtime_generation"] != inventory["runtime_generation"]):
                raise ValueError("restart_scope_or_completion_mismatch")
            snapshots = [event["before_snapshot"], event["after_snapshot"]]
            actors = []
            for snapshot in snapshots:
                if (snapshot["snapshot_sha256"] != sha({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
                        or not all(validate_snapshot(snapshot).values()) or snapshot["application_campaign_id"] != application
                        or snapshot["runtime_generation"] != event["runtime_generation"]
                        or snapshot["cluster_arn"] != inventory["runtime_contract"]["cluster_arn"]
                        or snapshot["expected_roles"] != inventory["runtime_contract"]["task_role_arns"]
                        or snapshot["public_key_bindings"] != snapshots[0]["public_key_bindings"]):
                    raise ValueError("restart_snapshot_not_bound")
                actors.append({row["name"]: row for row in snapshot["tasks"] if row["name"] in ORGS})
            target = spec["org_id"]
            if (actors[0][target]["task_arn"] != event["old_task_arn"] or actors[1][target]["task_arn"] != event["new_task_arn"]
                    or event["old_task_arn"] == event["new_task_arn"] or not unchanged_peers(list(actors[1].values()), actors[0], target)):
                raise ValueError("restart_replacement_or_peers_mismatch")
            for label, status in (("control_ready", "READY"), ("control_acknowledged", "ACKNOWLEDGED")):
                control = event[label]
                if (control.get("PK") != {"S": "RUN#" + spec["run_id"]}
                        or control.get("SK") != {"S": "CONTROL#HOST_RESTART#" + spec["request_id"]}
                        or control.get("kind") != {"S": "client_restart"} or control.get("status") != {"S": status}
                        or any(control.get(field) != {"S": spec[field]} for field in FIELDS)):
                    raise ValueError("restart_control_not_bound")
            ack = event["control_acknowledged"]
            if (ack.get("completed") != {"BOOL": True} or any(ack.get(field + "_task_arn_sha256") != {"S": hashlib.sha256(event[field + "_task_arn"].encode()).hexdigest()}
                                                               for field in ("old", "new"))):
                raise ValueError("restart_ack_not_bound")
            checked.append(spec["request_id"])
        return {"requested": len(specs), "verified": checked, "successful": bool(specs) and len(checked) == len(specs)}
    except (KeyError, ValueError, TypeError, AttributeError):
        return {"requested": len(specs) if isinstance(specs, list) else None, "verified": checked, "successful": False}


def handle_client_restarts(runner, observed, *, monotonic=time.monotonic):
    from validate_cloud_placement import capture_placement, validate_snapshot
    specs = validate_restarts(runner.request.get("host_restarts", []))
    clients, contract = runner.sdk(), runner.inventory["runtime_contract"]
    table = runner.inventory["foundation"]["state_table_name"]
    events = runner.inventory.setdefault("client_restart_events", {})
    previous = runner.inventory.setdefault("host_restart_requests_by_application", {}).get(runner.application_id())
    if previous is not None and previous != specs:
        raise ValueError("application_restart_requests_are_immutable")
    runner.inventory["host_restart_requests_by_application"][runner.application_id()] = specs
    runner.save()
    for spec in specs:
        key = {"PK": {"S": "RUN#" + spec["run_id"]}, "SK": {"S": "CONTROL#HOST_RESTART#" + spec["request_id"]}}
        item = clients["dynamodb"].get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        if not item:
            continue
        if any(item.get(field) != {"S": spec[field]} for field in FIELDS) or item.get("kind") != {"S": "client_restart"}:
            raise ValueError("restart_control_not_bound_to_explicit_request")
        event = events.get(spec["request_id"])
        if event and (event["spec"] != spec or event["application_campaign_id"] != runner.application_id()
                      or event["runtime_generation"] != runner.inventory["runtime_generation"]):
            raise ValueError("restart_request_rebound_to_other_application")
        if item.get("status") == {"S": "ACKNOWLEDGED"}:
            if (not event or event.get("completed") is not True or item.get("completed") != {"BOOL": True}
                    or any(item.get(field + "_task_arn_sha256") != {"S": hashlib.sha256(event[field + "_task_arn"].encode()).hexdigest()}
                           for field in ("old", "new"))):
                raise ValueError("restart_ack_has_no_recorded_observation")
            continue
        if item.get("status") != {"S": "READY"}:
            raise ValueError("unexpected_restart_control_status")
        if not event or not event.get("completed"):
            before = learning_tasks(observed)
            if set(before) != ORGS:
                raise RuntimeError("restart_requires_eight_live_learning_clients")
            snapshot = capture_placement(runner.inventory, runner.request, clients)
            if not all(validate_snapshot(snapshot).values()):
                raise RuntimeError("restart_before_placement_not_verified")
            target, old = spec["org_id"], before[spec["org_id"]]
            event = {"spec": dict(spec), "application_campaign_id": runner.application_id(),
                "runtime_generation": runner.inventory["runtime_generation"], "old_task_arn": old["task_arn"],
                "before_snapshot": snapshot, "control_ready": item, "completed": False, "started_at_utc": datetime.now(timezone.utc).isoformat()}
            events[spec["request_id"]] = event
            runner.save()
            deadline = monotonic() + 270
            clients["ecs"].stop_task(cluster=contract["cluster_arn"], task=old["task_arn"], reason="PCFL explicit controlled client restart")
            while True:
                observed = runner.budget_check()
                if not unchanged_peers(observed, before, target):
                    raise RuntimeError("restart_changed_one_of_seven_peer_tasks")
                old_rows = [row for row in observed if row["task_arn"] == old["task_arn"]]
                if len(old_rows) == 1 and old_rows[0]["last_status"] == "STOPPED":
                    break
                if monotonic() >= deadline:
                    raise RuntimeError("controlled_restart_stop_timeout")
                runner.sleep(2)
            replacement = runner.start_task(target, launch_intent="host-restart:" + spec["request_id"])
            event["new_task_arn"] = replacement
            runner.save()
            if replacement == old["task_arn"]:
                raise RuntimeError("restart_replayed_old_task_launch")
            while True:
                observed = runner.budget_check()
                if not unchanged_peers(observed, before, target):
                    raise RuntimeError("restart_changed_one_of_seven_peer_tasks")
                live = learning_tasks(observed)
                if set(live) == ORGS and live[target]["task_arn"] == replacement:
                    after = capture_placement(runner.inventory, runner.request, clients)
                    if not all(validate_snapshot(after).values()):
                        raise RuntimeError("restart_after_placement_not_verified")
                    event.update(after_snapshot=after, completed=True, completed_at_utc=datetime.now(timezone.utc).isoformat())
                    runner.inventory.setdefault("learning_placement_snapshots", []).append(after)
                    runner.save()
                    break
                if monotonic() >= deadline:
                    raise RuntimeError("controlled_restart_replacement_timeout")
                runner.sleep(2)
        old_hash = hashlib.sha256(event["old_task_arn"].encode()).hexdigest()
        new_hash = hashlib.sha256(event["new_task_arn"].encode()).hexdigest()
        if old_hash == new_hash:
            raise ValueError("restart_requires_distinct_actual_task_arns")
        names = {"#status": "status", **{"#" + field: field for field in (*FIELDS, "kind")}}
        values = {":ready": {"S": "READY"}, ":ack": {"S": "ACKNOWLEDGED"}, ":yes": {"BOOL": True},
            ":old": {"S": old_hash}, ":new": {"S": new_hash}, ":kind": {"S": "client_restart"},
            **{":" + field: {"S": spec[field]} for field in FIELDS}}
        clients["dynamodb"].update_item(TableName=table, Key=key,
            UpdateExpression="SET #status = :ack, completed = :yes, old_task_arn_sha256 = :old, new_task_arn_sha256 = :new",
            ConditionExpression="#status = :ready AND #kind = :kind AND " + " AND ".join("#" + field + " = :" + field for field in FIELDS),
            ExpressionAttributeNames=names, ExpressionAttributeValues=values)
        confirmed = clients["dynamodb"].get_item(TableName=table, Key=key, ConsistentRead=True).get("Item", {})
        if (confirmed.get("status") != {"S": "ACKNOWLEDGED"} or confirmed.get("completed") != {"BOOL": True}
                or confirmed.get("old_task_arn_sha256") != {"S": old_hash} or confirmed.get("new_task_arn_sha256") != {"S": new_hash}
                or any(confirmed.get(field) != {"S": spec[field]} for field in FIELDS)):
            raise RuntimeError("restart_ack_strong_read_not_confirmed")
        event["control_acknowledged"] = confirmed
        event["acknowledged_at_utc"] = datetime.now(timezone.utc).isoformat()
        runner.save()
