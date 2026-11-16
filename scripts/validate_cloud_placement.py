"""Read-only AWS placement/identity gate; operator probes never count as clients."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cloud_io import file_sha256, task_evidence, validate_probe_evidence

ORGS = tuple(f"org_{number:02d}" for number in range(1, 9))


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def effective_commands(definition, task):
    overrides = {item["name"]: item for item in task.get("overrides", {}).get("containerOverrides", [])}
    return {item["name"]: deepcopy(overrides.get(item["name"], {}).get("command", item.get("command", [])))
            for item in definition["containerDefinitions"]}


def public_key_bindings(request, inventory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    specs = [item for item in request.get("secrets", []) if item["logical_name"] == "coordinator-config"]
    if len(specs) != 1:
        raise ValueError("coordinator_public_identity_config_required")
    body = Path(specs[0]["payload_path"]).read_bytes()
    version = inventory["secret_versions"]["coordinator-config"]
    if hashlib.sha256(body).hexdigest() != version["sha256"]:
        raise ValueError("coordinator_secret_config_digest_mismatch")
    config = json.loads(body)
    paths_file = Path(request.get("runtime_input", specs[0]["payload_path"])).parent / "node-key-paths.json"
    public_paths = json.loads(paths_file.read_text(encoding="utf-8")) if paths_file.is_file() else {}
    if set(config.get("node_public_keys", {})) != set(ORGS):
        raise ValueError("eight_public_node_keys_required")
    bindings = {}
    for org, text in config["node_public_keys"].items():
        key = serialization.load_ssh_public_key(text.encode())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
            raise ValueError("P384_node_identity_required")
        prepared = Path(public_paths[org]["public"]).read_bytes() if org in public_paths else text.encode()
        prepared_key = serialization.load_ssh_public_key(prepared)
        raw_hash = hashlib.sha256(prepared).hexdigest()
        wire = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        if prepared_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) != wire:
            raise ValueError("prepared_and_registered_public_key_differ")
        if raw_hash != inventory["runtime_plan"]["registered_node_bindings"][org]["public_key_sha256"]:
            raise ValueError("prepared_node_public_key_mismatch")
        bindings[org] = {"ssh_sha256": raw_hash, "flower_wire_pem_sha256": hashlib.sha256(wire).hexdigest()}
    if len({item["flower_wire_pem_sha256"] for item in bindings.values()}) != 8:
        raise ValueError("duplicate_canonical_node_keys")
    return {"config_sha256": version["sha256"], "secret_version_id": version["version_id"], "keys": bindings}


def image_relation(ecr, reference, actual_digest, *, architecture=None, operating_system_family=None):
    repository, index_digest = reference.split("@")
    repo = repository.split("/", 1)[1]
    def read(digest):
        response = ecr.batch_get_image(repositoryName=repo, imageIds=[{"imageDigest": digest}])
        images = response.get("images", [])
        if len(images) != 1 or "sha256:" + hashlib.sha256(images[0]["imageManifest"].encode()).hexdigest() != digest:
            raise ValueError("registry_manifest_bytes_do_not_match_digest")
        return json.loads(images[0]["imageManifest"])
    index = read(index_digest)
    children = [item["digest"] for item in index.get("manifests", []) if item.get("platform", {}).get("os") == "linux"
                and item.get("platform", {}).get("architecture") == "amd64"]
    reported_leaf = "manifests" in index and actual_digest in children
    inferred_leaf = ("manifests" in index and actual_digest == index_digest and len(children) == 1
                     and architecture == "X86_64" and operating_system_family == "LINUX")
    valid = reported_leaf or inferred_leaf or ("manifests" not in index and actual_digest == index_digest)
    selected_digest = children[0] if inferred_leaf else actual_digest
    leaf = read(selected_digest) if valid and selected_digest != index_digest else index
    return {"pinned_reference": reference, "index_digest": index_digest, "actual_container_digest": actual_digest,
            "linux_amd64_children": children, "platform_leaf_digest": selected_digest if valid else None,
            "leaf_config_digest": leaf.get("config", {}).get("digest"), "verified": bool(valid),
            "leaf_observed_by_ecs": bool(valid and not inferred_leaf),
            "relation_mode": "ecs_reported_pinned_index_unique_platform_leaf" if inferred_leaf else "ecs_reported_manifest_digest",
            "runtime_platform": {"cpu_architecture": architecture, "operating_system_family": operating_system_family}}


def capture_placement(inventory, request, clients):
    """Fetch exact recorded tasks, their definitions and ENIs; no account-wide list."""
    account, region, project = (inventory[key] for key in ("account_id", "region", "project_id"))
    contract = inventory["runtime_contract"]
    cluster = f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime"
    if clients["sts"].get_caller_identity()["Account"] != account or contract["cluster_arn"] != cluster:
        raise ValueError("placement_target_account_or_cluster_mismatch")
    prefix = f"arn:aws:ecs:{region}:{account}:task/{project}-runtime/"
    arns = sorted(set(inventory.get("task_arns", [])))
    if any(not arn.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{32}", arn[len(prefix):]) for arn in arns):
        raise ValueError("task_outside_recorded_cluster")
    allowed = set(contract["task_definition_arns"].values()) | set(inventory.get("task_definition_history", {}))
    tasks, definitions, failures = [], {}, []
    for start in range(0, len(arns), 100):
        response = clients["ecs"].describe_tasks(cluster=cluster, tasks=arns[start:start + 100], include=["TAGS"])
        failures.extend(response.get("failures", []))
        for raw in response["tasks"]:
            arn = raw["taskDefinitionArn"]
            if raw["taskArn"] not in arns or arn not in allowed:
                raise ValueError("unrecorded_task_or_definition")
            if arn not in definitions:
                definitions[arn] = clients["ecs"].describe_task_definition(taskDefinition=arn)["taskDefinition"]
            definition = definitions[arn]
            commands = effective_commands(definition, raw)
            if len(commands) != 1 or next(iter(commands.values())) not in (["client"], ["coordinator"]):
                continue
            name = next(iter(commands))
            if name not in {*ORGS, "coordinator"} or raw.get("lastStatus") != "RUNNING":
                continue
            overrides = {item["name"]: item for item in raw.get("overrides", {}).get("containerOverrides", [])}
            container = definition["containerDefinitions"][0]
            env = {item["name"]: item["value"] for item in container.get("environment", [])}
            env.update({item["name"]: item["value"] for item in overrides.get(name, {}).get("environment", [])})
            record = task_evidence(raw, account, region, cluster)
            record.update(name=name, effective_commands=commands, launch_type=raw.get("launchType"),
                platform_version=raw.get("platformVersion"), group=raw.get("group"), cluster_arn=raw.get("clusterArn"),
                task_role_arn=raw.get("overrides", {}).get("taskRoleArn", definition.get("taskRoleArn")),
                org_id=env.get("PCFL_ORG_ID"), definition_image=container["image"],
                port_mappings=container.get("portMappings", []), entrypoint=container.get("entryPoint"),
                source_task_sha256=sha(raw), source_definition_sha256=sha(definition),
                runtime_generation=next((tag["value"] for tag in raw.get("tags", []) if tag["key"] == "RuntimeGeneration"), None),
                runtime_platform=definition.get("runtimePlatform", {}), coordinator_autorun=env.get("PCFL_COORDINATOR_AUTORUN"))
            tasks.append(record)
    ids = sorted({item["eni_id"] for item in tasks if item.get("eni_id")})
    interfaces = []
    for start in range(0, len(ids), 100):
        interfaces.extend(clients["ec2"].describe_network_interfaces(NetworkInterfaceIds=ids[start:start + 100])["NetworkInterfaces"])
    network = [{"eni_id": item["NetworkInterfaceId"], "vpc_id": item["VpcId"], "subnet_id": item["SubnetId"],
        "private_ip": item["PrivateIpAddress"], "groups": sorted(group["GroupId"] for group in item["Groups"]),
        "public_ips": [value for value in [item.get("Association", {}).get("PublicIp"),
            *[value.get("Association", {}).get("PublicIp") for value in item.get("PrivateIpAddresses", [])]] if value],
        "source_sha256": sha(item)} for item in interfaces]
    subnets = clients["ec2"].describe_subnets(SubnetIds=contract["subnet_ids"])["Subnets"]
    subnet_rows = [{"subnet_id": row["SubnetId"], "vpc_id": row["VpcId"], "map_public_ip_on_launch": row["MapPublicIpOnLaunch"],
                   "source_sha256": sha(row)} for row in subnets]
    relations = {}
    for task in tasks:
        for actual in task["image_digests"]:
            if actual and actual not in relations:
                platform = task["runtime_platform"]
                relations[actual] = image_relation(clients["ecr"], inventory["image"]["reference"], actual,
                    architecture=platform.get("cpuArchitecture"), operating_system_family=platform.get("operatingSystemFamily"))
    result = {"kind": "aws-live-learning-placement-snapshot", "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "account_id": account, "region": region, "project_id": project, "cluster_arn": cluster,
        "application_campaign_id": request.get("application_campaign_id", inventory["campaign_id"]),
        "runtime_generation": inventory.get("runtime_generation"), "tasks": tasks, "interfaces": network, "subnets": subnet_rows,
        "image_relations": relations, "public_key_bindings": public_key_bindings(request, inventory),
        "expected_roles": contract["task_role_arns"], "expected_security_groups": contract["security_group_ids"],
        "expected_subnets": contract["subnet_ids"], "expected_vpc": contract["vpc_id"], "source_failures": failures}
    result["definition_ports"] = {arn: [port["containerPort"] for container in definition["containerDefinitions"] for port in container.get("portMappings", [])] for arn, definition in definitions.items()}
    result["snapshot_sha256"] = sha(result)
    return result


def supplement_image_relations(inventory, clients):
    """Append an AWS-read supplement; preserve the original live network snapshot."""
    original = inventory["learning_placement_snapshots"][-1]
    if original.get("snapshot_sha256") != sha({key: value for key, value in original.items() if key != "snapshot_sha256"}):
        raise ValueError("original_live_snapshot_changed")
    if clients["sts"].get_caller_identity()["Account"] != inventory["account_id"]:
        raise ValueError("supplement_account_mismatch")
    updated = deepcopy(original)
    updated["original_snapshot_sha256"] = original["snapshot_sha256"]
    updated["image_verification_supplement_at_utc"] = datetime.now(timezone.utc).isoformat()
    for task in updated["tasks"]:
        definition = clients["ecs"].describe_task_definition(taskDefinition=task["task_definition_arn"])["taskDefinition"]
        if (definition["taskDefinitionArn"] != task["task_definition_arn"] or definition["taskRoleArn"] != task["task_role_arn"]
                or definition["containerDefinitions"][0]["image"] != task["definition_image"]):
            raise ValueError("immutable_task_definition_supplement_mismatch")
        platform = definition.get("runtimePlatform", {})
        task["runtime_platform"] = platform
        if task["name"] == "coordinator":
            response = clients["ecs"].describe_tasks(cluster=inventory["runtime_contract"]["cluster_arn"], tasks=[task["task_arn"]])
            rows = response.get("tasks", [])
            if len(rows) != 1 or rows[0]["taskArn"] != task["task_arn"]:
                raise ValueError("coordinator_effective_environment_not_observable")
            environment = {item["name"]: item["value"] for item in definition["containerDefinitions"][0].get("environment", [])}
            override = next((item for item in rows[0].get("overrides", {}).get("containerOverrides", []) if item["name"] == "coordinator"), {})
            environment.update({item["name"]: item["value"] for item in override.get("environment", [])})
            task["coordinator_autorun"] = environment.get("PCFL_COORDINATOR_AUTORUN")
        for digest in task["image_digests"]:
            updated["image_relations"][digest] = image_relation(clients["ecr"], task["definition_image"], digest,
                architecture=platform.get("cpuArchitecture"), operating_system_family=platform.get("operatingSystemFamily"))
    updated["snapshot_sha256"] = sha({key: value for key, value in updated.items() if key != "snapshot_sha256"})
    inventory["learning_placement_snapshots"].append(updated)
    return updated


def validate_snapshot(snapshot):
    clients = [item for item in snapshot["tasks"] if item["name"] in ORGS and item["effective_commands"].get(item["name"]) == ["client"]]
    coordinators = [item for item in snapshot["tasks"] if item["name"] == "coordinator" and item["effective_commands"].get("coordinator") == ["coordinator"]]
    actor_rows = clients + coordinators
    interfaces = {row["eni_id"]: row for row in snapshot["interfaces"]}
    checks = {"eight_distinct_learning_clients": len(clients) == 8 and {item["name"] for item in clients} == set(ORGS),
        "one_finite_coordinator": len(coordinators) == 1 and coordinators[0].get("coordinator_autorun") == "true" and not (coordinators[0].get("group") or "").startswith("service:"),
        "simultaneously_running_fargate": len(actor_rows) == 9 and all(row["last_status"] == "RUNNING" and row["launch_type"] == "FARGATE" for row in actor_rows),
        "distinct_task_eni_and_private_ip": len(actor_rows) == 9 and all(len({row.get(field) for row in actor_rows}) == 9 and all(row.get(field) for row in actor_rows) for field in ("task_arn", "eni_id", "private_ip")),
        "actual_role_and_org_binding": bool(actor_rows) and all(row["task_role_arn"] == snapshot["expected_roles"][row["name"]] and (row["name"] == "coordinator" or row["org_id"] == row["name"]) for row in actor_rows),
        "same_runtime_generation": bool(snapshot.get("runtime_generation")) and len(actor_rows) == 9 and all(row.get("runtime_generation") == snapshot["runtime_generation"] for row in actor_rows),
        "actual_linux_amd64_platform": len(actor_rows) == 9 and all(row.get("runtime_platform", {}).get("cpuArchitecture") == "X86_64"
            and row.get("runtime_platform", {}).get("operatingSystemFamily") == "LINUX" for row in actor_rows),
        "actual_private_network_boundary": len(actor_rows) == 9 and all(row["eni_id"] in interfaces and interfaces[row["eni_id"]]["vpc_id"] == snapshot["expected_vpc"]
            and interfaces[row["eni_id"]]["subnet_id"] in snapshot["expected_subnets"] and not interfaces[row["eni_id"]]["public_ips"]
            and interfaces[row["eni_id"]]["groups"] == [snapshot["expected_security_groups"][row["name"]]]
            and interfaces[row["eni_id"]]["private_ip"] == row["private_ip"] and ipaddress.ip_address(row["private_ip"]).is_private for row in actor_rows),
        "actual_private_subnets": bool(snapshot["subnets"]) and {row["subnet_id"] for row in snapshot["subnets"]} == set(snapshot["expected_subnets"])
            and all(row["vpc_id"] == snapshot["expected_vpc"] and row["map_public_ip_on_launch"] is False for row in snapshot["subnets"]),
        "no_internal_appio_ports": bool(actor_rows) and all(not {9091, 9094} & set(ports) for ports in snapshot.get("definition_ports", {}).values()) and all(not {9091, 9094} & {port["containerPort"] for port in row["port_mappings"]} and not row.get("entrypoint") for row in actor_rows),
        "actual_image_manifest_relation": bool(actor_rows) and all(row["definition_image"] == snapshot["image_relations"][digest]["pinned_reference"]
            and snapshot["image_relations"][digest]["verified"] is True for row in actor_rows for digest in row["image_digests"]) and all(row["image_digests"] and all(row["image_digests"]) for row in actor_rows),
        "distinct_public_key_config_bindings": set(snapshot["public_key_bindings"]["keys"]) == set(ORGS) and len({row["flower_wire_pem_sha256"] for row in snapshot["public_key_bindings"]["keys"].values()}) == 8}
    return checks


def validate_placement(inventory, *, export_root=None):
    # Retained evidence can be incomplete after a failed run. Fail closed while
    # still returning a report, including when individual records are malformed.
    inventory = inventory if isinstance(inventory, dict) else {}
    evidence_errors = (KeyError, ValueError, TypeError, AttributeError, IndexError, OSError, OverflowError)

    def checked(test):
        try:
            return bool(test())
        except evidence_errors:
            return False

    def snapshot_checks(value):
        try:
            result = validate_snapshot(value)
            return result if isinstance(result, dict) and result else {"live_learning_snapshot_available": False}
        except evidence_errors:
            return {"live_learning_snapshot_available": False, "source_snapshot_well_formed": False}

    expected_application = inventory.get("application_campaign_id", inventory.get("campaign_id"))

    def current_bindings(value):
        return {
            "source_snapshot_integrity": checked(lambda: isinstance(value, dict) and bool(value)
                and value.get("snapshot_sha256") == sha({key: item for key, item in value.items() if key != "snapshot_sha256"})),
            "captured_target_matches_recorded_scope": checked(lambda: bool(value)
                and all(value[key] == inventory[key] for key in ("account_id", "region", "project_id"))
                and value["cluster_arn"] == inventory["runtime_contract"]["cluster_arn"]),
            "snapshot_matches_current_runtime_generation": checked(lambda: bool(inventory.get("runtime_generation"))
                and re.fullmatch(r"[0-9a-f]{64}", inventory["runtime_generation"]) is not None
                and value["runtime_generation"] == inventory["runtime_generation"]),
            "snapshot_matches_current_application": checked(lambda: bool(expected_application)
                and value["application_campaign_id"] == expected_application),
            "snapshot_matches_current_image": checked(lambda: bool(value["tasks"]) and bool(value["image_relations"])
                and re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", inventory["image"]["reference"]) is not None
                and all(row["definition_image"] == inventory["image"]["reference"] for row in value["tasks"])
                and all(row["pinned_reference"] == inventory["image"]["reference"] for row in value["image_relations"].values())),
            "snapshot_matches_current_config": checked(lambda:
                re.fullmatch(r"[0-9a-f]{64}", inventory["secret_versions"]["coordinator-config"]["sha256"]) is not None
                and bool(inventory["secret_versions"]["coordinator-config"]["version_id"])
                and inventory["secret_versions"]["coordinator-config"]["version_id"] != "null"
                and value["public_key_bindings"]["config_sha256"] == inventory["secret_versions"]["coordinator-config"]["sha256"]
                and value["public_key_bindings"]["secret_version_id"] == inventory["secret_versions"]["coordinator-config"]["version_id"]
                and set(value["public_key_bindings"]["keys"]) == set(ORGS)
                and all(re.fullmatch(r"[0-9a-f]{64}", value["public_key_bindings"]["keys"][org]["ssh_sha256"]) is not None
                    and value["public_key_bindings"]["keys"][org]["ssh_sha256"]
                    == inventory["runtime_plan"]["registered_node_bindings"][org]["public_key_sha256"] for org in ORGS)),
            "snapshot_matches_current_role_and_network_contracts": checked(lambda:
                bool(value["expected_roles"]) and bool(value["expected_security_groups"]) and bool(value["expected_subnets"])
                and value["expected_roles"] == inventory["runtime_contract"]["task_role_arns"]
                and value["expected_security_groups"] == inventory["runtime_contract"]["security_group_ids"]
                and set(value["expected_subnets"]) == set(inventory["runtime_contract"]["subnet_ids"])
                and value["expected_vpc"] == inventory["runtime_contract"]["vpc_id"]),
            "snapshot_matches_current_task_definitions": checked(lambda: bool(value["tasks"])
                and all(row["task_definition_arn"] == inventory["runtime_contract"]["task_definition_arns"][row["name"]]
                    for row in value["tasks"])),
        }

    snapshots = inventory.get("learning_placement_snapshots", [])
    snapshots = snapshots if isinstance(snapshots, list) else []
    passing = [value for value in snapshots if all(current_bindings(value).values()) and all(snapshot_checks(value).values())]
    snapshot = passing[-1] if passing else (snapshots[-1] if snapshots and isinstance(snapshots[-1], dict) else None)
    checks = snapshot_checks(snapshot)
    checks.update(current_bindings(snapshot))

    probe_rows = inventory.get("client_probe_tasks", [])
    probe_rows = probe_rows if isinstance(probe_rows, list) else []
    probe_ok, probe_names, probe_arns = False, set(), set()
    try:
        plan, contract = inventory["runtime_plan"], inventory["runtime_contract"]
        templates = [*plan["client_access_probe_templates"], plan["coordinator_access_probe_template"]]
        expected_configs = {}
        if len(templates) != 9 or len(probe_rows) != 9:
            raise ValueError("nine_probe_templates_and_records_required")
        for template in templates:
            name = template["task_definition_name"]
            overrides = template["overrides"]["containerOverrides"]
            if (name not in {*ORGS, "coordinator"} or name in expected_configs or len(overrides) != 1
                    or overrides[0]["name"] != name or overrides[0]["command"] != ["operator"]):
                raise ValueError("role_bound_operator_probe_template_required")
            environment = overrides[0]["environment"]
            configs = [row["value"] for row in environment if row["name"] == "PCFL_OPERATOR_CONFIG_JSON"]
            if len(configs) != 1:
                raise ValueError("one_probe_config_required")
            config = json.loads(configs[0])
            kind = "coordinator" if name == "coordinator" else "client"
            allowed = config["allowed_object"]
            denied = config["denied_objects"]
            distribution = allowed["key"].split("/")[1] if kind == "client" else None
            denied_distributions = {row["key"].split("/")[1] for row in denied if row["key"].startswith("partitions/")}
            denied_keys = ({f"partitions/{distribution}/{org}/train.csv" for org in ORGS if org != name}
                if kind == "client" else {f"partitions/{split}/{org}/train.csv" for org in ORGS
                    for split in denied_distributions})
            denied_keys |= {"evaluation/frozen/validation.csv", "evaluation/frozen/test.csv"}
            if (config.get("role_kind", "client") != kind or config["expected_task_role_arn"] != contract["task_role_arns"][name]
                    or config["storage"]["region"] != inventory["region"]
                    or config["storage"]["expected_account_id"] != inventory["account_id"]
                    or config["bucket"] != inventory["foundation"]["bucket_name"]
                    or config["table_name"] != inventory["foundation"]["state_table_name"]
                    or (kind == "client" and (config["org_id"] != name or distribution not in {"iid", "non_iid"}
                        or allowed["key"] != f"partitions/{distribution}/{name}/train.csv"))
                    or (kind == "coordinator" and (not allowed["key"].startswith("metadata/")
                        or len(denied_distributions) != 1 or not denied_distributions <= {"iid", "non_iid"}))
                    or not re.fullmatch(r"[0-9a-f]{64}", allowed["sha256"])
                    or not allowed.get("version_id") or allowed["version_id"] == "null"
                    or len(denied) != (9 if kind == "client" else 10)
                    or len(denied_keys) != len(denied) or {row["key"] for row in denied} != denied_keys
                    or any(not row.get("version_id") or row["version_id"] == "null" for row in denied)):
                raise ValueError("complete_current_role_bound_probe_config_required")
            expected_configs[name] = config
        prefix = contract["cluster_arn"].replace(":cluster/", ":task/") + "/"
        observed = inventory.get("observed_tasks", [])
        actual_by_arn = {row["task_arn"]: row for row in observed if isinstance(row, dict) and row.get("task_arn")}
        for row in probe_rows:
            value = row["probe_response"]
            name = value.get("org_id") if value.get("role_kind") == "client" else "coordinator"
            validate_probe_evidence(value, expected_configs[name])
            arn, reference = row["task_arn"], row["probe_log_reference"]
            actual = {**actual_by_arn.get(arn, {}), **row}
            if (not isinstance(arn, str) or not arn.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{32}", arn[len(prefix):])
                    or arn in probe_arns or name in probe_names or row["container_exit_codes"] != [0]
                    or actual["last_status"] != "STOPPED" or actual["effective_commands"] != {name: ["operator"]}
                    or actual["task_role_arn"] != contract["task_role_arns"][name]
                    or actual["task_definition_arn"] != contract["task_definition_arns"][name]
                    or reference["log_group"] != contract["log_groups"][name]
                    or reference["log_stream"] != "runtime/" + name + "/" + arn.rsplit("/", 1)[1]
                    or reference["response_sha256"] != hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()):
                raise ValueError("probe_task_identity_or_log_attribution_mismatch")
            probe_names.add(name)
            probe_arns.add(arn)
        probe_ok = probe_names == {*ORGS, "coordinator"} and len(probe_arns) == 9
    except evidence_errors:
        probe_ok = False
    checks["nine_actual_attributable_iam_probes"] = probe_ok
    anchor_configs = [item.get("protected_anchor_object") for item in expected_configs.values()] if probe_ok else []
    anchor_write_denied = bool(anchor_configs) and len(anchor_configs) == 9 and all(anchor_configs) and all(
        row["probe_response"].get("anchor_write_denied") is True for row in probe_rows)
    if anchor_write_denied:
        recorded_witnesses = [{key: row.get(key, inventory["foundation"]["bucket_name"] if key == "bucket" else None)
                               for key in ("bucket", "key", "version_id", "sha256")}
                              for row in inventory.get("protected_operator_witnesses", [])]
        from probe_anchor import sentinel_references
        try:
            recorded_targets = [*recorded_witnesses, *sentinel_references(inventory, ROOT / "results/aws" / inventory["campaign_id"])]
        except (KeyError, TypeError, ValueError, OSError):
            recorded_targets = []
        anchor_write_denied = all(reference == anchor_configs[0] and reference in recorded_targets for reference in anchor_configs)
    if any(anchor_configs):
        checks["protected_operator_anchor_write_denied"] = anchor_write_denied

    registry_ok, registry = False, {}
    try:
        if not export_root or not snapshot:
            raise ValueError("placement_snapshot_and_export_required")
        root, exported = Path(export_root).resolve(), inventory["export"]
        index_path = root / "campaign_result.json"
        if file_sha256(index_path) != exported["index_sha256"]:
            raise ValueError("raw_campaign_index_digest_mismatch")
        index = json.loads(index_path.read_text(encoding="utf-8"))
        registry = index["node_registry"]
        if (not isinstance(registry, dict) or len(registry) != 8 or set(registry.values()) != set(ORGS)
                or any(not isinstance(node, str) or not node.isdigit() or str(int(node)) != node
                    or not 0 < int(node) < 2 ** 64 for node in registry)
                or index["campaign_id"] != expected_application or index["campaign_id"] != snapshot["application_campaign_id"]):
            raise ValueError("current_coordinator_registry_required")
        cases, directories = index["cases"], exported["case_directories"]
        case_ids = [case["cell_id"] for case in cases]
        if (not isinstance(cases, list) or not cases or any(not isinstance(cell, str) or not cell for cell in case_ids)
                or len(set(case_ids)) != len(case_ids) or set(directories) != set(case_ids)
                or exported["cases"] != len(cases)):
            raise ValueError("exact_nonempty_indexed_case_set_required")
        seen = set()
        for case in cases:
            cell_id = case["cell_id"]
            directory = Path(directories[cell_id]).resolve()
            if not directory.is_relative_to(root):
                raise ValueError("case_directory_outside_export")
            runtime_artifacts = [row for row in case["artifacts"] if row["key"].rsplit("/", 1)[-1] == "runtime_result.json"]
            if len(runtime_artifacts) != 1:
                raise ValueError("one_indexed_raw_runtime_result_required")
            artifact = runtime_artifacts[0]
            path = directory / "runtime_result.json"
            if (artifact["key"] != f"evidence/campaigns/{expected_application}/{cell_id}/runtime_result.json"
                    or artifact["bucket"] != inventory["foundation"]["bucket_name"]
                    or not artifact["version_id"] or artifact["version_id"] == "null"
                    or file_sha256(path) != artifact["sha256"] or path.stat().st_size != artifact["size_bytes"]):
                raise ValueError("indexed_runtime_result_identity_or_body_mismatch")
            result = json.loads(path.read_text(encoding="utf-8"))
            raw_registry = result.get("node_registry")
            # The exception envelope omits the convenience registry. Its actual
            # durable tasks still bind every node to the current exact index.
            if (((result.get("successful") is not False or raw_registry is not None) and raw_registry != registry)
                    or result["cloud_campaign_id"] != expected_application
                    or result["cell_id"] != cell_id or not isinstance(result["tasks"], list) or not result["tasks"]):
                raise ValueError("raw_runtime_registry_or_case_binding_mismatch")
            for task in result["tasks"]:
                if type(task["node_id"]) is not int or registry.get(str(task["node_id"])) != task["org_id"]:
                    raise ValueError("actual_learning_task_registry_mismatch")
                seen.add(task["org_id"])
        registry_ok = seen == set(ORGS)
    except evidence_errors:
        registry_ok = False
    checks["coordinator_registry_and_actual_learning_bindings"] = registry_ok
    from cloud_faults import validate_restart_evidence
    restarts = validate_restart_evidence(inventory)
    if restarts["requested"]:
        checks["independent_client_restart"] = restarts["successful"]
    return {"schema_version": "0.1.0", "kind": "actual-aws-learning-placement-validation", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "account_id": inventory.get("account_id"), "region": inventory.get("region"), "project_id": inventory.get("project_id"),
        "campaign_id": inventory.get("campaign_id"), "successful": bool(checks) and all(checks.values()), "checks": checks,
        "snapshot_sha256": snapshot.get("snapshot_sha256") if snapshot else None, "source_snapshot": snapshot,
        "probe_task_arns": [row.get("task_arn") for row in probe_rows if isinstance(row, dict)], "node_registry": registry,
        "protected_anchor_write_denial_complete": anchor_write_denied, "client_restart_evidence": restarts,
        "limitations": ["Operator probes are excluded from learning-client placement",
            "This gate does not establish restart/key-rotation tests, replication, clinical authorization, teardown or reconciled charges",
            "Registry-to-key association relies on the pinned supervisor's actual registration responses and verified config hash; raw server key bytes are not present in registry export"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output", default="reports/cloud_placement_validation.json", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--refresh-image-relations", action="store_true", help="Read AWS immutable manifests/definitions and append an assessment supplement after the run")
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    if args.refresh_image_relations:
        from aws_campaign import CampaignRunner, ROOT as CAMPAIGN_ROOT, exclusive_file, load_request, write_json
        request = load_request(args.request or args.inventory.parent / "request.json")
        runner = CampaignRunner(request)
        if runner.inventory_path.resolve() != args.inventory.resolve():
            raise ValueError("supplement_requires_original_owned_campaign_inventory")
        with exclusive_file(CAMPAIGN_ROOT / "results/aws/campaign-operation.lock"):
            inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
            supplement_image_relations(inventory, runner.sdk())
            write_json(args.inventory, inventory)
    report = validate_placement(inventory, export_root=inventory.get("export", {}).get("export_root", str(args.inventory.parent / "r")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"successful": report["successful"], "checks": report["checks"]}, sort_keys=True))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
