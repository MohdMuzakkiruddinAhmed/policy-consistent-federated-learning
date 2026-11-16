"""Retain bounded, exact-task operator-probe logs using read-only AWS APIs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from cloud_io import file_sha256, task_evidence


def owned_path(path, directory):
    path, directory = Path(path).absolute(), Path(directory).absolute()
    if (not path.is_relative_to(directory) or not path.resolve().is_relative_to(directory.resolve())
            or any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
                   for parent in (path, *path.parents) if parent.is_relative_to(directory))):
        raise ValueError("probe_log_retention_path_outside_owned_campaign")
    return path


def retain_probe_logs(inventory_path, clients, output, *, max_task_bytes=2 * 1024 ** 2, max_total_bytes=64 * 1024 ** 2):
    """Preserve observations, including empty/missing streams, without grading IAM."""
    inventory_path = Path(inventory_path)
    inventory_bytes = inventory_path.read_bytes()
    inventory_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    inventory = json.loads(inventory_bytes)
    directory = inventory_path.parent
    account, region, project, campaign = (inventory[name] for name in ("account_id", "region", "project_id", "campaign_id"))
    if clients["sts"].get_caller_identity()["Account"] != account:
        raise ValueError("probe_log_retention_account_mismatch")
    contract = inventory["runtime_contract"]
    cluster = contract["cluster_arn"]
    if cluster != f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime":
        raise ValueError("probe_log_retention_cluster_scope_mismatch")
    if type(max_task_bytes) is not int or type(max_total_bytes) is not int or min(max_task_bytes, max_total_bytes) <= 0:
        raise ValueError("positive_probe_log_retention_bounds_required")
    output = owned_path(output, directory)
    candidates = {}
    sources = [*inventory.get("task_observation_history", {}).values(), *inventory.get("observed_tasks", []),
               *inventory.get("client_probe_task_history", []), *inventory.get("client_probe_tasks", [])]
    for row in sources:
        commands = row.get("effective_commands", {})
        if not any(command == ["operator"] for command in commands.values()):
            continue
        if len(commands) != 1:
            raise ValueError("probe_log_retention_ambiguous_operator_command")
        name = next(iter(commands))
        arn = row["task_arn"]
        if (name not in {"coordinator", *(f"org_{number:02d}" for number in range(1, 9))}
                or commands != {name: ["operator"]}
                or not arn.startswith(cluster.replace(":cluster/", ":task/") + "/")
                or not re.fullmatch(r"[a-f0-9]{32}", arn.rsplit("/", 1)[-1])):
            raise ValueError("probe_log_retention_task_scope_mismatch")
        previous = candidates.get(arn)
        if previous and any(previous[1].get(key) != row.get(key) for key in ("task_definition_arn", "task_role_arn", "effective_commands")):
            raise ValueError("probe_log_retention_conflicting_task_identity")
        candidates[arn] = name, row
    if len(candidates) > 512:
        raise ValueError("probe_log_retention_task_count_exceeded")
    receipts, total = [], 0
    for arn, (name, historical) in sorted(candidates.items()):
        definition_arn = historical["task_definition_arn"]
        recorded = inventory.get("task_definition_history", {}).get(definition_arn)
        if (not re.fullmatch(rf"arn:aws:ecs:{re.escape(region)}:{account}:task-definition/{re.escape(project)}-[A-Za-z0-9_-]+:[1-9][0-9]*", definition_arn)
                or historical.get("task_role_arn") != f"arn:aws:iam::{account}:role/{project}-{name}"
                or recorded is None or recorded.get("name") != name
                or historical.get("task_role_arn") != contract["task_role_arns"][name]
                or recorded.get("task_role_arn") != historical["task_role_arn"]):
            raise ValueError("probe_log_retention_unregistered_task_or_role")
        definition = clients["ecs"].describe_task_definition(taskDefinition=definition_arn)["taskDefinition"]
        if (definition.get("taskDefinitionArn") != definition_arn or definition.get("taskRoleArn") != historical["task_role_arn"]
                or len(definition.get("containerDefinitions", [])) != 1 or definition["containerDefinitions"][0]["name"] != name
                or [{"name": row["name"], "image": row["image"]} for row in definition["containerDefinitions"]] != recorded.get("containers")):
            raise ValueError("probe_log_retention_actual_definition_mismatch")
        response = clients["ecs"].describe_tasks(cluster=cluster, tasks=[arn], include=["TAGS"])
        tasks, failures = response.get("tasks"), response.get("failures", [])
        if tasks:
            if len(tasks) != 1 or failures or tasks[0].get("taskArn") != arn:
                raise ValueError("probe_log_retention_actual_task_mismatch")
            actual = tasks[0]
            tags = {row["key"]: row["value"] for row in actual.get("tags", [])}
            overrides = actual.get("overrides", {})
            commands = {row["name"]: row.get("command", []) for row in overrides.get("containerOverrides", [])}
            if (actual.get("taskDefinitionArn") != definition_arn or actual.get("lastStatus") != "STOPPED" or commands != {name: ["operator"]}
                    or overrides.get("taskRoleArn", historical["task_role_arn"]) != historical["task_role_arn"]
                    or any(tags.get(key) != value for key, value in {"Project": project, "Stage": "runtime", "Campaign": campaign}.items())):
                raise ValueError("probe_log_retention_actual_task_binding_mismatch")
            observed, source = task_evidence(actual, account, region, cluster), "AWS_DescribeTasks"
        elif (tasks == [] and failures == [{"arn": arn, "reason": "MISSING"}] and historical.get("last_status") == "STOPPED"):
            fields = {"task_arn", "task_definition_arn", "private_ip", "eni_id", "last_status", "cpu", "memory_mib",
                      "started_at", "billing_started_at", "stopped_at", "container_exit_codes", "image_digests", "containers"}
            observed = {key: value for key, value in historical.items() if key in fields}
            source = "retained_historical_STOPPED_with_current_exact_MISSING"
        else:
            raise ValueError("probe_log_retention_task_absence_unconfirmed")
        observed.update(task_role_arn=historical["task_role_arn"], effective_commands={name: ["operator"]})
        group = contract["log_groups"][name]
        if project not in group:
            raise ValueError("probe_log_retention_log_group_scope_mismatch")
        stream = "runtime/" + name + "/" + arn.rsplit("/", 1)[-1]
        events, token, seen, used, state = [], None, set(), 0, "observed"
        for _ in range(64):
            try:
                page = clients["logs"].get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True,
                    limit=1000, **({"nextToken": token} if token else {}))
            except Exception as error:
                if token is None and getattr(error, "response", {}).get("Error", {}).get("Code") == "ResourceNotFoundException":
                    state = "explicit_stream_not_found"
                    break
                raise
            if not isinstance(page.get("events"), list):
                raise ValueError("probe_log_retention_unrecognized_events")
            for event in page["events"]:
                if (not isinstance(event, dict) or set(event) - {"timestamp", "message", "ingestionTime"}
                        or not isinstance(event.get("message"), str)
                        or any(type(event[key]) is not int for key in ("timestamp", "ingestionTime") if key in event)):
                    raise ValueError("probe_log_retention_unrecognized_event")
                used += len(json.dumps(event, ensure_ascii=False).encode("utf-8"))
                if used > max_task_bytes or total + used > max_total_bytes:
                    raise ValueError("probe_log_retention_byte_bound_exceeded")
                events.append(event)
            next_token = page.get("nextForwardToken")
            if not next_token or next_token == token:
                break
            if not isinstance(next_token, str) or next_token in seen:
                raise ValueError("probe_log_retention_repeated_pagination_token")
            seen.add(next_token)
            token = next_token
        else:
            raise ValueError("probe_log_retention_page_bound_exceeded")
        body = {"kind": "operator-observed-isolation-probe-task-log", "task": observed, "task_observation_source": source,
            "log_group": group, "log_stream": stream, "events": events, "pagination_complete": True, "log_stream_state": state}
        raw = (json.dumps(body, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        path = owned_path(output.parent / "probe-logs" / (hashlib.sha256(arn.encode()).hexdigest()[:8] + "-" + digest[:16] + ".json"), directory)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != raw:
            raise ValueError("probe_log_retention_local_collision")
        if not path.exists():
            with path.open("xb") as target: target.write(raw)
        receipts.append({"task_arn": arn, "task_definition_arn": definition_arn, "task_role_arn": observed["task_role_arn"],
            "task_observation_source": source, "log_group": group, "log_stream": stream, "path": str(path),
            "sha256": digest, "size_bytes": len(raw), "event_count": len(events), "log_stream_state": state})
        total += used
    if file_sha256(inventory_path) != inventory_sha256:
        raise ValueError("probe_log_retention_inventory_changed_during_read")
    report = {"kind": "read-only-owned-probe-task-log-retention", "successful": True, "performed_read_only": True,
        "account_id": account, "region": region, "project_id": project, "campaign_id": campaign,
        "inventory_sha256": inventory_sha256, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "tasks": receipts, "limits": {"max_task_event_bytes": max_task_bytes, "max_total_event_bytes": max_total_bytes},
        "iam_probe_validation_performed": False,
        "limitations": ["Raw log retention does not establish successful IAM denials or a successful campaign",
                        "Expired ECS descriptions use explicitly labeled retained STOPPED observations; no fresh task identity is fabricated"]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as target: json.dump(report, target, indent=2, sort_keys=True); target.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    import boto3
    from botocore.config import Config
    config = Config(ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=30, retries={"max_attempts": 2})
    clients = {name: boto3.client(name, region_name=inventory["region"], config=config) for name in ("sts", "ecs", "logs")}
    report = retain_probe_logs(args.inventory, clients, args.output)
    print(json.dumps({"successful": report["successful"], "tasks_retained": len(report["tasks"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
