"""Placement gates use observed records, never task-definition counts alone."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_cloud_placement as placement
import aws_campaign as campaign


def snapshot():
    result = {"account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-test", "application_campaign_id": "campaign-one",
        "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/pcfl-test-runtime", "runtime_generation": "g" * 64,
        "tasks": [], "interfaces": [], "subnets": [{"subnet_id": "subnet-one", "vpc_id": "vpc-one", "map_public_ip_on_launch": False}],
        "expected_roles": {}, "expected_security_groups": {}, "expected_subnets": ["subnet-one"], "expected_vpc": "vpc-one",
        "definition_ports": {}, "public_key_bindings": {"config_sha256": "c" * 64, "keys": {}}, "image_relations": {"leaf": {"pinned_reference": "registry@sha256:index", "verified": True}}}
    for number, name in enumerate([*placement.ORGS, "coordinator"], 1):
        role, group = "arn:aws:iam::123456789012:role/" + name, f"sg-{number}"
        result["expected_roles"][name], result["expected_security_groups"][name] = role, group
        result["tasks"].append({"name": name, "effective_commands": {name: ["coordinator" if name == "coordinator" else "client"]},
            "task_arn": f"task-{number}", "eni_id": f"eni-{number}", "private_ip": f"10.73.1.{number}", "last_status": "RUNNING", "launch_type": "FARGATE",
            "task_role_arn": role, "org_id": name, "runtime_generation": "g" * 64, "port_mappings": [], "entrypoint": None,
            "definition_image": "registry@sha256:index", "image_digests": ["leaf"], "group": "family:test", "coordinator_autorun": "true",
            "runtime_platform": {"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"}})
        result["interfaces"].append({"eni_id": f"eni-{number}", "vpc_id": "vpc-one", "subnet_id": "subnet-one", "private_ip": f"10.73.1.{number}", "groups": [group], "public_ips": []})
        if name != "coordinator":
            result["public_key_bindings"]["keys"][name] = {"flower_wire_pem_sha256": f"{number:064x}"}
    result["snapshot_sha256"] = placement.sha(result)
    return result


def complete_fixture(directory):
    """An index and exact raw artifact bodies accompany the nine AWS actors."""
    value = snapshot()
    reference = "123456789012.dkr.ecr.us-east-1.amazonaws.com/project@sha256:" + "f" * 64
    value["runtime_generation"] = "b" * 64
    value["public_key_bindings"]["secret_version_id"] = "config-version-one"
    value["source_failures"] = []
    value["image_relations"] = {"leaf": {"pinned_reference": reference, "verified": True}}
    definitions = {}
    for number, task in enumerate(value["tasks"], 1):
        name = task["name"]
        definitions[name] = f"arn:aws:ecs:us-east-1:123456789012:task-definition/{name}:1"
        task.update(task_arn=value["cluster_arn"].replace(":cluster/", ":task/") + f"/{number:032x}",
            task_definition_arn=definitions[name], definition_image=reference, runtime_generation=value["runtime_generation"],
            runtime_platform={"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"}, coordinator_autorun="true")
        if name != "coordinator":
            value["public_key_bindings"]["keys"][name]["ssh_sha256"] = f"{number + 16:064x}"
    value["snapshot_sha256"] = placement.sha({key: item for key, item in value.items() if key != "snapshot_sha256"})
    inventory = {"account_id": value["account_id"], "region": value["region"], "project_id": value["project_id"],
        "campaign_id": "campaign-one", "runtime_generation": value["runtime_generation"], "image": {"reference": reference},
        "learning_placement_snapshots": [value], "foundation": {"bucket_name": "test-bucket", "state_table_name": "test-table"},
        "secret_versions": {"coordinator-config": {"sha256": "c" * 64, "version_id": "config-version-one"}},
        "runtime_contract": {"cluster_arn": value["cluster_arn"], "task_role_arns": deepcopy(value["expected_roles"]),
            "security_group_ids": deepcopy(value["expected_security_groups"]), "subnet_ids": ["subnet-one"], "vpc_id": "vpc-one",
            "task_definition_arns": definitions, "log_groups": {name: "/pcfl-research/" + name for name in definitions}},
        "runtime_plan": {"registered_node_bindings": {org: {"public_key_sha256": row["ssh_sha256"]}
            for org, row in value["public_key_bindings"]["keys"].items()}, "client_access_probe_templates": []}, "client_probe_tasks": []}
    for number, name in enumerate([*placement.ORGS, "coordinator"], 101):
        kind = "coordinator" if name == "coordinator" else "client"
        denied = [{"key": f"partitions/iid/{org}/train.csv", "version_id": "partition-version"}
            for org in placement.ORGS if kind == "coordinator" or org != name]
        denied.extend({"key": f"evaluation/frozen/{split}.csv", "version_id": "holdout-version"} for split in ("validation", "test"))
        config = {"role_kind": kind, "org_id": name, "expected_task_role_arn": value["expected_roles"][name],
            "storage": {"region": inventory["region"], "expected_account_id": inventory["account_id"]},
            "bucket": "test-bucket", "table_name": "test-table",
            "allowed_object": {"key": "metadata/model.json" if kind == "coordinator" else f"partitions/iid/{name}/train.csv", "sha256": "d" * 64, "version_id": "allowed-version"},
            "denied_objects": denied}
        template = {"task_definition_name": name, "overrides": {"containerOverrides": [{"name": name, "command": ["operator"],
            "environment": [{"name": "PCFL_OPERATOR_CONFIG_JSON", "value": json.dumps(config)}]}]}}
        if kind == "client":
            inventory["runtime_plan"]["client_access_probe_templates"].append(template)
        else:
            inventory["runtime_plan"]["coordinator_access_probe_template"] = template
        response = {"successful": True, "role_kind": kind, "role": kind + "-isolation-probe", "task_role_arn": config["expected_task_role_arn"],
            "own_object_sha256": config["allowed_object"]["sha256"], "policy_write_denied": True, "record_rows_exported": False,
            "denied_reads": [{"key_sha256": hashlib.sha256(row["key"].encode()).hexdigest(), "code": "AccessDenied"} for row in denied]}
        if kind == "client":
            response["org_id"] = name
        suffix = f"{number:032x}"
        inventory["client_probe_tasks"].append({"task_arn": value["cluster_arn"].replace(":cluster/", ":task/") + "/" + suffix,
            "task_definition_arn": definitions[name], "task_role_arn": value["expected_roles"][name], "last_status": "STOPPED",
            "container_exit_codes": [0], "effective_commands": {name: ["operator"]}, "probe_response": response,
            "probe_log_reference": {"log_group": inventory["runtime_contract"]["log_groups"][name], "log_stream": "runtime/" + name + "/" + suffix,
                "response_sha256": hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()}})
    registry = {str(number): org for number, org in enumerate(placement.ORGS, 1)}
    root = Path(directory)
    case = root / "case-one"
    case.mkdir()
    result = {"node_registry": registry, "cloud_campaign_id": "campaign-one", "cell_id": "case-one",
        "tasks": [{"node_id": number, "org_id": org} for number, org in enumerate(placement.ORGS, 1)]}
    result_path = case / "runtime_result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    index = {"campaign_id": "campaign-one", "node_registry": registry, "cases": [{"cell_id": "case-one", "artifacts": [{
        "key": "evidence/campaigns/campaign-one/case-one/runtime_result.json", "bucket": "test-bucket", "version_id": "result-version",
        "sha256": placement.file_sha256(result_path), "size_bytes": result_path.stat().st_size}]}]}
    index_path = root / "campaign_result.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    inventory["export"] = {"index_sha256": placement.file_sha256(index_path), "cases": 1, "case_directories": {"case-one": str(case)}}
    return inventory


class CloudPlacementTests(unittest.TestCase):
    def test_nine_learning_tasks_pass_physical_snapshot_checks(self):
        self.assertTrue(all(placement.validate_snapshot(snapshot()).values()))

    def test_operator_probe_overrides_never_count_as_learning_clients(self):
        value = snapshot()
        for task in value["tasks"][:8]:
            task["effective_commands"] = {task["name"]: ["operator"]}
        self.assertFalse(placement.validate_snapshot(value)["eight_distinct_learning_clients"])
        definition = {"containerDefinitions": [{"name": "org_01", "command": ["client"]}]}
        actual = {"overrides": {"containerOverrides": [{"name": "org_01", "command": ["operator"]}]}}
        self.assertEqual(placement.effective_commands(definition, actual), {"org_01": ["operator"]})

    def test_public_ip_wrong_role_group_subnet_and_appio_fail(self):
        cases = []
        value = snapshot(); value["interfaces"][0]["public_ips"] = ["44.1.2.3"]; cases.append((value, "actual_private_network_boundary"))
        value = snapshot(); value["tasks"][0]["task_role_arn"] = "coordinator-role"; cases.append((value, "actual_role_and_org_binding"))
        value = snapshot(); value["interfaces"][0]["groups"] = ["shared-default"]; cases.append((value, "actual_private_network_boundary"))
        value = snapshot(); value["interfaces"][0]["subnet_id"] = "public-subnet"; cases.append((value, "actual_private_network_boundary"))
        value = snapshot(); value["tasks"][0]["port_mappings"] = [{"containerPort": 9094}]; cases.append((value, "no_internal_appio_ports"))
        value = snapshot(); value["tasks"][0]["last_status"] = "STOPPED"; cases.append((value, "simultaneously_running_fargate"))
        for value, check in cases:
            with self.subTest(check=check):
                self.assertFalse(placement.validate_snapshot(value)[check])

    def test_mixed_runtime_generation_cannot_claim_current_fleet(self):
        value = snapshot()
        value["tasks"][0]["runtime_generation"] = "previous"
        self.assertFalse(placement.validate_snapshot(value)["same_runtime_generation"])

    def test_coordinator_requires_finite_autorun_and_actor_platform_is_explicit(self):
        for autorun in (None, "false", True):
            with self.subTest(autorun=autorun):
                value = snapshot()
                value["tasks"][-1]["coordinator_autorun"] = autorun
                self.assertFalse(placement.validate_snapshot(value)["one_finite_coordinator"])
        value = snapshot()
        value["tasks"][0]["runtime_platform"] = {"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"}
        self.assertFalse(placement.validate_snapshot(value)["actual_linux_amd64_platform"])

    def test_zero_probe_records_and_missing_registry_cannot_pass(self):
        value = snapshot()
        inventory = {"account_id": value["account_id"], "region": value["region"], "project_id": value["project_id"], "campaign_id": "campaign-one",
            "runtime_contract": {"cluster_arn": value["cluster_arn"]}, "learning_placement_snapshots": [value], "client_probe_tasks": []}
        report = placement.validate_placement(inventory)
        self.assertFalse(report["successful"])
        self.assertFalse(report["checks"]["nine_actual_attributable_iam_probes"])
        self.assertFalse(report["checks"]["coordinator_registry_and_actual_learning_bindings"])

    def test_mutated_source_snapshot_cannot_pass_integrity(self):
        value = snapshot()
        value["project_id"] = "other"
        inventory = {"account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-test", "campaign_id": "campaign-one",
            "runtime_contract": {"cluster_arn": value["cluster_arn"]}, "learning_placement_snapshots": [value]}
        report = placement.validate_placement(inventory)
        self.assertFalse(report["checks"]["source_snapshot_integrity"])
        self.assertFalse(report["checks"]["captured_target_matches_recorded_scope"])

    def test_actual_oci_index_to_leaf_relation_is_hash_checked(self):
        leaf = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "a" * 64}})
        leaf_hash = "sha256:" + hashlib.sha256(leaf.encode()).hexdigest()
        index = json.dumps({"manifests": [{"digest": leaf_hash, "platform": {"os": "linux", "architecture": "amd64"}}]})
        index_hash = "sha256:" + hashlib.sha256(index.encode()).hexdigest()
        ecr = Mock()
        ecr.batch_get_image.side_effect = [{"images": [{"imageManifest": index}]}, {"images": [{"imageManifest": leaf}]}]
        result = placement.image_relation(ecr, "registry/project@" + index_hash, leaf_hash)
        self.assertTrue(result["verified"])
        self.assertEqual(result["actual_container_digest"], leaf_hash)
        ecr.batch_get_image.side_effect = [{"images": [{"imageManifest": index + " "}]}]
        with self.assertRaisesRegex(ValueError, "manifest_bytes"):
            placement.image_relation(ecr, "registry/project@" + index_hash, leaf_hash)

    def test_ecs_reported_index_preserves_observation_and_labels_platform_inference(self):
        leaf = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "a" * 64}})
        leaf_hash = "sha256:" + hashlib.sha256(leaf.encode()).hexdigest()
        index = json.dumps({"manifests": [{"digest": leaf_hash, "platform": {"os": "linux", "architecture": "amd64"}}]})
        index_hash = "sha256:" + hashlib.sha256(index.encode()).hexdigest()
        ecr = Mock()
        ecr.batch_get_image.side_effect = [{"images": [{"imageManifest": index}]}, {"images": [{"imageManifest": leaf}]}]
        result = placement.image_relation(ecr, "registry/project@" + index_hash, index_hash,
            architecture="X86_64", operating_system_family="LINUX")
        self.assertTrue(result["verified"])
        self.assertEqual(result["actual_container_digest"], index_hash)
        self.assertEqual(result["platform_leaf_digest"], leaf_hash)
        self.assertFalse(result["leaf_observed_by_ecs"])
        self.assertEqual(result["relation_mode"], "ecs_reported_pinned_index_unique_platform_leaf")
        ecr.batch_get_image.side_effect = [{"images": [{"imageManifest": index}]}]
        self.assertFalse(placement.image_relation(ecr, "registry/project@" + index_hash, index_hash)["verified"])
        ecr.batch_get_image.side_effect = [{"images": [{"imageManifest": index}]}, {"images": [{"imageManifest": leaf + " "}]}]
        with self.assertRaisesRegex(ValueError, "manifest_bytes"):
            placement.image_relation(ecr, "registry/project@" + index_hash, index_hash,
                architecture="X86_64", operating_system_family="LINUX")

    def test_index_platform_inference_requires_one_matching_leaf(self):
        for manifests in ([], [
                {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "amd64"}}]):
            with self.subTest(matches=len(manifests)):
                index = json.dumps({"manifests": manifests})
                index_hash = "sha256:" + hashlib.sha256(index.encode()).hexdigest()
                ecr = Mock()
                ecr.batch_get_image.return_value = {"images": [{"imageManifest": index}]}
                self.assertFalse(placement.image_relation(ecr, "registry/project@" + index_hash, index_hash,
                    architecture="X86_64", operating_system_family="LINUX")["verified"])

    def test_launch_generation_changes_with_secret_versions_not_incidental_reports(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            request = {"campaign_id": "campaign-one", "account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-test", "preparation_stage": "connectivity-iid"}
            runner = campaign.CampaignRunner(request)
            runner.inventory.update(runtime_contract={"task_definition_arns": {"coordinator": "definition-one"}}, secret_versions={"coordinator-config": {"version_id": "v1", "sha256": "a" * 64}})
            first = runner.generation()
            request["source_reports"] = {"new_timestamp": "irrelevant"}
            self.assertEqual(runner.generation(), first)
            runner.inventory["secret_versions"]["coordinator-config"]["version_id"] = "v2"
            self.assertNotEqual(runner.generation(), first)

    def test_complete_current_snapshot_probes_and_raw_registry_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            report = placement.validate_placement(complete_fixture(directory), export_root=directory)
            self.assertTrue(report["successful"], report["checks"])

    def test_anchor_write_denial_requires_all_nine_logs_and_recorded_existing_witness(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, root = complete_fixture(directory), directory
            witness = {"bucket": "test-bucket", "key": "anchors/campaign-one/cell/witness.json", "version_id": "witness-v1", "sha256": "a" * 64}
            inventory["protected_operator_witnesses"] = [witness]
            for template in [*inventory["runtime_plan"]["client_access_probe_templates"], inventory["runtime_plan"]["coordinator_access_probe_template"]]:
                environment = template["overrides"]["containerOverrides"][0]["environment"][0]
                environment["value"] = json.dumps({**json.loads(environment["value"]), "protected_anchor_object": witness})
            for row in inventory["client_probe_tasks"]:
                row["probe_response"]["anchor_write_denied"] = True
                row["probe_log_reference"]["response_sha256"] = hashlib.sha256(json.dumps(row["probe_response"], sort_keys=True).encode()).hexdigest()
            report = placement.validate_placement(inventory, export_root=root)
            self.assertTrue(report["successful"], report["checks"])
            self.assertTrue(report["protected_anchor_write_denial_complete"])
            inventory["protected_operator_witnesses"] = []
            report = placement.validate_placement(inventory, export_root=root)
            self.assertFalse(report["successful"])
            self.assertFalse(report["checks"]["protected_operator_anchor_write_denied"])

    def test_historical_snapshot_cannot_satisfy_changed_current_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = complete_fixture(directory)
            changes = [
                (lambda item: item.update(runtime_generation="e" * 64), "snapshot_matches_current_runtime_generation"),
                (lambda item: item.update(application_campaign_id="other-campaign"), "snapshot_matches_current_application"),
                (lambda item: item["image"].update(reference="registry@sha256:" + "e" * 64), "snapshot_matches_current_image"),
                (lambda item: item["secret_versions"]["coordinator-config"].update(sha256="e" * 64), "snapshot_matches_current_config"),
                (lambda item: item["secret_versions"]["coordinator-config"].update(version_id="other-version"), "snapshot_matches_current_config"),
                (lambda item: item["runtime_plan"]["registered_node_bindings"]["org_01"].update(public_key_sha256="e" * 64), "snapshot_matches_current_config"),
                (lambda item: item["runtime_contract"]["task_role_arns"].update(org_01="other-role"), "snapshot_matches_current_role_and_network_contracts"),
                (lambda item: item["runtime_contract"]["security_group_ids"].update(org_01="other-group"), "snapshot_matches_current_role_and_network_contracts"),
                (lambda item: item["runtime_contract"].update(vpc_id="other-vpc"), "snapshot_matches_current_role_and_network_contracts"),
                (lambda item: item["runtime_contract"].update(subnet_ids=["other-subnet"]), "snapshot_matches_current_role_and_network_contracts"),
                (lambda item: item["runtime_contract"]["task_definition_arns"].update(org_01="other-definition"), "snapshot_matches_current_task_definitions"),
            ]
            for change, check in changes:
                with self.subTest(check=check):
                    changed = deepcopy(inventory)
                    change(changed)
                    report = placement.validate_placement(changed, export_root=directory)
                    self.assertFalse(report["successful"])
                    self.assertFalse(report["checks"][check])

    def test_nine_probe_rows_require_distinct_actual_operator_tasks_and_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = complete_fixture(directory)
            changes = [
                lambda item: item["client_probe_tasks"][0].update(task_arn=item["client_probe_tasks"][1]["task_arn"]),
                lambda item: item["client_probe_tasks"][0].update(task_role_arn="wrong-role"),
                lambda item: item["client_probe_tasks"][0].update(effective_commands={"org_01": ["client"]}),
                lambda item: item["client_probe_tasks"][0].update(last_status="RUNNING"),
                lambda item: item["client_probe_tasks"][0]["probe_log_reference"].update(response_sha256="wrong-digest"),
                lambda item: item["client_probe_tasks"][0]["probe_log_reference"].update(log_stream="other-task-stream"),
                lambda item: item["client_probe_tasks"][0]["probe_log_reference"].update(log_group="other-group"),
                lambda item: item["client_probe_tasks"][0].update(task_definition_arn="old-definition"),
            ]
            for number, change in enumerate(changes):
                with self.subTest(number=number):
                    changed = deepcopy(inventory)
                    change(changed)
                    report = placement.validate_placement(changed, export_root=directory)
                    self.assertFalse(report["successful"])
                    self.assertFalse(report["checks"]["nine_actual_attributable_iam_probes"])

    def test_probe_command_and_role_can_come_from_exact_arn_sdk_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = complete_fixture(directory)
            inventory["observed_tasks"] = deepcopy(inventory["client_probe_tasks"])
            for row in inventory["client_probe_tasks"]:
                del row["effective_commands"]
                del row["task_role_arn"]
            self.assertTrue(placement.validate_placement(inventory, export_root=directory)["successful"])
            inventory["observed_tasks"][0]["task_arn"] = "different-task"
            self.assertFalse(placement.validate_placement(inventory, export_root=directory)["checks"]["nine_actual_attributable_iam_probes"])

    def test_runtime_registry_requires_exact_indexed_raw_case_body(self):
        for mutation in ("body", "index", "missing", "unindexed", "empty_cases", "empty_tasks", "wrong_registry", "wrong_node"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                inventory = complete_fixture(directory)
                root = Path(directory)
                path = root / "case-one/runtime_result.json"
                result = json.loads(path.read_text(encoding="utf-8"))
                index_path = root / "campaign_result.json"
                index = json.loads(index_path.read_text(encoding="utf-8"))
                if mutation == "body":
                    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
                elif mutation == "index":
                    index_path.write_text(index_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
                elif mutation == "missing":
                    path.unlink()
                elif mutation == "unindexed":
                    inventory["export"]["case_directories"]["extra"] = str(root / "case-one")
                elif mutation == "empty_cases":
                    index["cases"] = []
                    inventory["export"]["cases"] = 0
                else:
                    if mutation == "empty_tasks":
                        result["tasks"] = []
                    elif mutation == "wrong_registry":
                        result["node_registry"]["1"], result["node_registry"]["2"] = result["node_registry"]["2"], result["node_registry"]["1"]
                    else:
                        result["tasks"][0]["node_id"] = 2
                    path.write_text(json.dumps(result), encoding="utf-8")
                    index["cases"][0]["artifacts"][0].update(sha256=placement.file_sha256(path), size_bytes=path.stat().st_size)
                if mutation in {"empty_cases", "empty_tasks", "wrong_registry", "wrong_node"}:
                    index_path.write_text(json.dumps(index), encoding="utf-8")
                    inventory["export"]["index_sha256"] = placement.file_sha256(index_path)
                report = placement.validate_placement(inventory, export_root=directory)
                self.assertFalse(report["successful"])
                self.assertFalse(report["checks"]["coordinator_registry_and_actual_learning_bindings"])

    def test_missing_or_malformed_retained_evidence_returns_failed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = complete_fixture(directory)
            malformed = [None, {}, {"learning_placement_snapshots": [None]},
                {**inventory, "learning_placement_snapshots": [{"tasks": "malformed"}]},
                {**inventory, "client_probe_tasks": [None] * 9},
                {**inventory, "runtime_plan": None}, {**inventory, "observed_tasks": None}]
            for number, item in enumerate(malformed):
                with self.subTest(number=number):
                    self.assertFalse(placement.validate_placement(item, export_root=directory)["successful"])

    def test_image_supplement_appends_without_rewriting_original_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = complete_fixture(directory)
            original = deepcopy(inventory["learning_placement_snapshots"][0])
            definitions = {row["task_definition_arn"]: {"taskDefinitionArn": row["task_definition_arn"], "taskRoleArn": row["task_role_arn"],
                "runtimePlatform": row["runtime_platform"], "containerDefinitions": [{"image": row["definition_image"],
                    "environment": [{"name": "PCFL_COORDINATOR_AUTORUN", "value": "true"}]}]} for row in original["tasks"]}
            clients = {name: Mock() for name in ("sts", "ecs", "ecr")}
            clients["sts"].get_caller_identity.return_value = {"Account": inventory["account_id"]}
            clients["ecs"].describe_task_definition.side_effect = lambda **kwargs: {"taskDefinition": definitions[kwargs["taskDefinition"]]}
            clients["ecs"].describe_tasks.return_value = {"tasks": [{"taskArn": original["tasks"][-1]["task_arn"]}]}
            with patch.object(placement, "image_relation", return_value={"verified": True}):
                supplemented = placement.supplement_image_relations(inventory, clients)
            self.assertEqual(inventory["learning_placement_snapshots"][0], original)
            self.assertEqual(len(inventory["learning_placement_snapshots"]), 2)
            self.assertEqual(supplemented["original_snapshot_sha256"], original["snapshot_sha256"])
            self.assertNotEqual(supplemented["snapshot_sha256"], original["snapshot_sha256"])
            self.assertEqual(supplemented["snapshot_sha256"], placement.sha({key: value for key, value in supplemented.items() if key != "snapshot_sha256"}))


if __name__ == "__main__":
    unittest.main()
