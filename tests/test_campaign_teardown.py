"""Mocked exact-resource absence proofs; no AWS, clinical rows or mutations."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_campaign_teardown import CHECKS, operator_auxiliary_custody, resource_targets, sha, validate_teardown


class AwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code, "Message": code}}
        super().__init__(code)


class Client:
    def __init__(self, service, calls, overrides):
        self.service, self.calls, self.overrides = service, calls, overrides

    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((self.service, operation, kwargs))
            override = self.overrides.get((self.service, operation))
            if override is not None:
                return override(kwargs) if callable(override) else deepcopy(override)
            if self.service == "sts": return {"Account": "111111111111"}
            if operation == "describe_log_groups": return {"logGroups": []}
            if operation == "list_task_definitions": return {"taskDefinitionArns": []}
            codes = {"s3": "NoSuchBucket", "dynamodb": "ResourceNotFoundException", "ecr": "RepositoryNotFoundException",
                "iam": "NoSuchEntity", "secretsmanager": "ResourceNotFoundException", "lambda": "ResourceNotFoundException",
                "scheduler": "ResourceNotFoundException", "sqs": "QueueDoesNotExist", "sns": "NotFound", "budgets": "NotFoundException",
                "ecs": "ClusterNotFoundException", "route53": "NoSuchHostedZone"}
            if self.service == "servicediscovery":
                raise AwsError("NamespaceNotFound" if operation == "get_namespace" else "ServiceNotFound")
            if self.service == "ec2":
                raise AwsError({"describe_vpcs": "InvalidVpcID.NotFound", "describe_vpc_endpoints": "InvalidVpcEndpointId.NotFound",
                    "describe_subnets": "InvalidSubnetID.NotFound", "describe_security_groups": "InvalidGroup.NotFound",
                    "describe_route_tables": "InvalidRouteTableID.NotFound"}[operation])
            raise AwsError(codes[self.service])
        return call


def fixture(directory):
    project, account, region = "pcfl-synthetic", "111111111111", "us-east-1"
    arn = lambda service, resource: f"arn:aws:{service}:{'' if service == 'iam' else region}:{account}:{resource}"
    bucket = f"{project}-{account}-{region}"
    cluster = arn("ecs", f"cluster/{project}-runtime")
    role = arn("iam", f"role/{project}-client")
    inventory = {"account_id": account, "region": region, "project_id": project, "campaign_id": "synthetic-deployment",
        "teardown_complete": True, "foundation": {"bucket_name": bucket, "state_table_name": project + "-state",
            "image_repositories": {name: f"{account}.dkr.ecr.{region}.amazonaws.com/{project}/{name}" for name in ("client", "coordinator", "governance")},
            "client_task_role_arns": {"org_01": role}},
        "runtime_contract": {"cluster_arn": cluster, "vpc_id": "vpc-0123", "interface_endpoint_ids": {"one": "vpce-0001", "two": "vpce-0002"},
            "gateway_endpoint_ids": {"s3": "vpce-0003"}, "service_names": {"opa": project + "-opa", "evaluation": project + "-evaluation"},
            "task_definition_arns": {"client": arn("ecs", f"task-definition/{project}-client:1")},
            "secret_arns": {"one": arn("secretsmanager", f"secret:{project}/runtime/root-ca-abcdef")},
            "task_role_arns": {"org_01": role}, "log_groups": {"one": "/" + project + "/runtime"},
            "automatic_cleanup": {"function_arn": arn("lambda", f"function:{project}-expiry"),
                "schedule_arn": arn("scheduler", f"schedule/default/{project}-expiry"),
                "provisional_schedule_arn": arn("scheduler", f"schedule/default/{project}-provisional-expiry"),
                "failure_queue_url": f"https://sqs.{region}.amazonaws.com/{account}/{project}-failures"},
            "machine_cost_alerts": {"budget_name": project + "-budget", "sns_topic_arn": arn("sns", project + "-alerts"),
                "queue_url": f"https://sqs.{region}.amazonaws.com/{account}/{project}-alerts"}},
        "task_arns": [cluster.replace(":cluster/", ":task/") + "/task-1"],
        "observed_tasks": [{"task_arn": cluster.replace(":cluster/", ":task/") + "/task-2"}],
        "state_paths": {}, "pre_teardown_state_snapshots": {}}
    resources = {
        "foundation": [("aws_s3_bucket", {"bucket": bucket}), ("aws_dynamodb_table", {"name": project + "-state"}),
            ("aws_iam_role", {"arn": role}), *[("aws_ecr_repository", {"name": f"{project}/{name}"}) for name in ("client", "coordinator", "governance")]],
        "runtime": [("aws_vpc", {"id": "vpc-0123"}), ("aws_subnet", {"id": "subnet-0123"}),
            ("aws_security_group", {"id": "sg-0123"}), ("aws_route_table", {"id": "rtb-0123"}),
            ("aws_service_discovery_private_dns_namespace", {"id": "ns-0123", "hosted_zone": "Z0123"}),
            ("aws_service_discovery_service", {"id": "srv-0123"}),
            ("aws_lambda_function", {"arn": arn("lambda", f"function:{project}-provisional-expiry")}),
            ("aws_iam_role", {"arn": arn("iam", f"role/{project}-provisional-expiry")})]}
    for stack, values in resources.items():
        current, snapshot = directory / "state" / (stack + ".tfstate"), directory / "state" / (stack + "-before-destroy.json")
        current.parent.mkdir(exist_ok=True)
        current.write_text(json.dumps({"version": 4, "lineage": stack, "serial": 2, "resources": []}))
        snapshot.write_text(json.dumps({"version": 4, "lineage": stack, "serial": 1,
            "resources": [{"mode": "managed", "type": type_, "name": "synthetic", "instances": [{"attributes": {**attrs, "tags": {"Project": project}}}]} for type_, attrs in values]}))
        inventory["state_paths"][stack] = str(current)
        inventory["pre_teardown_state_snapshots"][stack] = {"path": str(snapshot), "sha256": sha(snapshot)}
    application, cell = "synthetic-application", "synthetic-S0"
    export = directory / "r"
    case = export / hashlib.sha256(cell.encode()).hexdigest()[:8]
    case.mkdir(parents=True)
    (case / "cell.json").write_text(json.dumps({"cell_id": cell}))
    model = case / "model.npz"
    model.write_bytes(b"synthetic-byte-retention-fixture")
    records = []
    def ref(path, key, version):
        value = {"bucket": bucket, "key": key, "version_id": version, "sha256": sha(path), "size_bytes": path.stat().st_size, "local_path": str(path)}
        records.append(value)
        return {key: value[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
    model_ref = ref(model, "models/candidates/synthetic/model.npz", "version-model")
    raw = case / "runtime_result.json"
    raw.write_text(json.dumps({"successful": False, "test_holdout_evaluated": False, "model": {"backend": "s3", **model_ref}}))
    raw_ref = ref(raw, f"evidence/campaigns/{application}/{cell}/runtime_result.json", "version-raw")
    (case / "artifact_paths.json").write_text(json.dumps({sha(model): model.name}))
    index = export / "campaign_result.json"
    index.write_text(json.dumps({"campaign_id": application, "cases": [{"cell_id": cell, "successful": False, "artifacts": [model_ref, raw_ref]}]}))
    index_ref = ref(index, f"evidence/campaigns/{application}/campaign_result.json", "version-index")
    witness = case / "operator_witness.json"
    witness.write_text(json.dumps({"synthetic": "byte-retention-only"}))
    witness_ref = ref(witness, "anchors/synthetic-deployment/synthetic/witness.json", "version-witness")
    inventory["protected_operator_witnesses"] = [{**witness_ref, "local_path": str(witness), "cell_id": cell,
        "application_campaign_id": application, "raw_result_sha256": sha(raw)}]
    inventory["retained_artifact_versions"] = records
    inventory["export"] = {"application_campaign_id": application, "export_root": str(export), "index_key": index_ref["key"],
        "index_version_id": index_ref["version_id"], "index_sha256": sha(index), "case_directories": {cell: str(case)}}
    path = directory / "inventory.json"
    path.write_text(json.dumps(inventory))
    return path, inventory


def clients(overrides=None):
    calls, overrides = [], overrides or {}
    names = ("sts", "s3", "dynamodb", "ecr", "iam", "secretsmanager", "lambda", "scheduler", "sqs", "sns", "budgets", "servicediscovery", "route53", "logs", "ec2", "ecs")
    return {name: Client(name, calls, overrides) for name in names}, calls


def operator_recovery(directory, inventory):
    run, manifest = "aborted-run", "b" * 64
    pointer = {"PK": {"S": "RUN#" + run}, "SK": {"S": "POINTER"}, "manifest_id": {"S": manifest}, "commit_order": {"N": "10"}}
    snapshot = {"kind": "operator-observed-partial-persistent-state", "producer_runtime_result": False,
        "snapshot_coherent": True, "run_id": run, "table_name": inventory["foundation"]["state_table_name"],
        "authority_order": 20, "sequence": {"order": {"N": "20"}}, "run_records": [pointer], "model_pointer": deepcopy(pointer),
        "observed_counts": {"indeterminate_tasks": 8}}
    path = directory / "operator-snapshot.json"; path.write_text(json.dumps(snapshot))
    observation = {"path": str(path), "source_path": str(path), "sha256": sha(path), "run_id": run,
        "authority_order": 20, "observed_counts": snapshot["observed_counts"]}
    index = inventory["retained_artifact_versions"][2]
    source = {"kind": "operator-partial-cloud-export-recovery", "successful": False, "campaign_complete": False,
        "application_campaign_id": "synthetic-application", "bucket": inventory["foundation"]["bucket_name"],
        "account_id": inventory["account_id"], "producer_source_index": index,
        "retained_versions": deepcopy(inventory["retained_artifact_versions"]), "operator_observations": [deepcopy(observation)]}
    source_path = directory / "operator-source-report.json"; source_path.write_text(json.dumps(source))
    receipt = {"bucket": inventory["foundation"]["bucket_name"], "prefixes": ["evidence/", "models/candidates/"],
        "at_utc": "2026-11-13T03:00:00Z", "observed_versions": [{key: row[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
            for row in inventory["retained_artifact_versions"] if row["key"].startswith(("evidence/", "models/candidates/"))]}
    receipt_path = directory / "orphan-discovery.json"; receipt_path.write_text(json.dumps(receipt))
    record = {"kind": "registered-operator-partial-cloud-recovery", "campaign_successful": False,
        "application_campaign_id": "synthetic-application", "orphan_discovery_complete": True,
        "source_report": {"path": str(source_path), "sha256": sha(source_path)}, "source_index": index,
        "operator_observations": [observation], "orphan_discovery_receipt": {"path": str(receipt_path), "sha256": sha(receipt_path)}}
    inventory["operator_recoveries"] = [record]
    inventory["retired_publication_pointers"] = [{"run_pk": "RUN#" + run, "manifest_id": manifest}]
    return record, source_path, path, receipt_path


def auxiliary_fixture(directory, inventory):
    def write(name, body):
        path = directory / name; path.write_text(json.dumps(body))
        return {"path": str(path), "sha256": sha(path)}
    scope = {key: inventory[key] for key in ("account_id", "region", "project_id", "campaign_id")}
    cluster = inventory["runtime_contract"]["cluster_arn"]
    task_arn = cluster.replace(":cluster/", ":task/") + "/" + "a" * 32
    definition = f"arn:aws:ecs:{scope['region']}:{scope['account_id']}:task-definition/{scope['project_id']}-org_01:3"
    role = f"arn:aws:iam::{scope['account_id']}:role/{scope['project_id']}-org_01"
    observed = {"task_arn": task_arn, "task_definition_arn": definition, "task_role_arn": role,
        "last_status": "STOPPED", "effective_commands": {"org_01": ["operator"]}}
    group, stream = "/" + scope["project_id"] + "/runtime/org_01", "runtime/org_01/" + "a" * 32
    source = {**scope, "runtime_contract": {"cluster_arn": cluster, "task_definition_arns": {"org_01": definition},
        "task_role_arns": {"org_01": role}, "log_groups": {"org_01": group}}, "observed_tasks": [observed],
        "task_definition_history": {definition: {"name": "org_01", "task_role_arn": role}}}
    source_ref = write("aux-source.json", source)
    archive = {"kind": "operator-observed-isolation-probe-task-log", "task": observed, "task_observation_source": "AWS_DescribeTasks",
        "log_group": group, "log_stream": stream, "log_stream_state": "observed", "pagination_complete": True,
        "events": [{"timestamp": 1, "message": "synthetic probe diagnostic"}]}
    archive_ref = write("aux-log.json", archive)
    receipt = {**archive_ref, "size_bytes": Path(archive_ref["path"]).stat().st_size, "event_count": 1,
        **{key: observed[key] for key in ("task_arn", "task_definition_arn", "task_role_arn")},
        **{key: archive[key] for key in ("task_observation_source", "log_group", "log_stream", "log_stream_state")}}
    report = {**scope, "kind": "read-only-owned-probe-task-log-retention", "successful": True, "performed_read_only": True,
        "inventory_sha256": source_ref["sha256"], "tasks": [receipt]}
    report_ref = write("aux-report.json", report)
    registration = {"kind": "registered-read-only-probe-log-custody", "report": report_ref, "source_inventory": source_ref,
        "task_count": 1, "latest_revision_task_count": 1}
    inventory["operator_probe_log_exports"] = [registration]
    original = {"kind": "operator-interrupted-development-launch", "application_campaign_id": "synthetic-application", "training_started": False,
        "real_test_evaluated": False}
    original_ref = write("aux-original.json", original)
    observation = {**scope, "kind": "read-only-latest-revision-pre-training-interruption-observation", "successful": True,
        "performed_read_only": True, "aws_mutations": False, "source_inventory": source_ref, "original_interruption": original_ref,
        "probe_log_report": report_ref, "latest_tasks": [observed], "guard": {"account_id": scope["account_id"], "active_tasks": 0,
            "service_desired_running_pending": 0}}
    observation_ref = write("aux-observation.json", observation)
    interruption = {**original, "original_operator_record": original_ref, "actual_aws_observation": observation_ref, "retained_probe_logs": report_ref}
    interruption_ref = write("aux-interruption.json", interruption)
    inventory["operator_launch_interruptions"] = [{**interruption_ref, "application_campaign_id": "synthetic-application", "training_started": False,
        "original_operator_record": original_ref, "actual_aws_observation": observation_ref, "retained_probe_logs": report_ref}]
    return registration, receipt, interruption_ref


class CampaignTeardownTests(unittest.TestCase):
    def test_original_probe_archives_and_interruption_observation_custody_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path, inv = fixture(directory)
            auxiliary_fixture(directory, inv); path.write_text(json.dumps(inv))
            sdk, _ = clients(); result = validate_teardown(path, sdk)
            self.assertTrue(result["successful"], result.get("errors"))
            self.assertEqual(result["evidence_custody"]["operator_probe_task_archives_checked"], 1)
            self.assertEqual(result["evidence_custody"]["operator_launch_interruptions_checked"], 1)

    def test_probe_archive_or_interruption_reference_tampering_rejects(self):
        for mode in ("archive", "source", "observation", "original", "interruption", "size", "count"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); _, inv = fixture(directory)
                registration, receipt, _ = auxiliary_fixture(directory, inv)
                if mode in {"archive", "source", "observation", "original", "interruption"}:
                    target = directory / {"archive": "aux-log.json", "source": "aux-source.json", "observation": "aux-observation.json",
                        "original": "aux-original.json", "interruption": "aux-interruption.json"}[mode]
                    target.write_bytes(target.read_bytes() + b"changed")
                else:
                    report_path = Path(registration["report"]["path"]); body = json.loads(report_path.read_text())
                    body["tasks"][0]["size_bytes" if mode == "size" else "event_count"] += 1
                    report_path.write_text(json.dumps(body)); registration["report"]["sha256"] = sha(report_path)
                with self.assertRaises(ValueError): operator_auxiliary_custody(inv, directory)

    def test_coherently_rebound_probe_wrong_task_identity_still_rejects(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); _, inv = fixture(directory)
            registration, receipt, _ = auxiliary_fixture(directory, inv)
            archive_path = Path(receipt["path"]); body = json.loads(archive_path.read_text())
            body["task"]["task_role_arn"] += "-wrong"
            archive_path.write_text(json.dumps(body))
            report_path = Path(registration["report"]["path"]); report = json.loads(report_path.read_text())
            report["tasks"][0].update(sha256=sha(archive_path), size_bytes=archive_path.stat().st_size)
            report_path.write_text(json.dumps(report)); registration["report"]["sha256"] = sha(report_path)
            with self.assertRaisesRegex(ValueError, "identity_or_bytes"): operator_auxiliary_custody(inv, directory)

    def test_exhaustive_owned_absence_and_all_local_versions_checked_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            path, inventory = fixture(Path(temp))
            sdk, calls = clients()
            before = sha(path)
            result = validate_teardown(path, sdk)
            self.assertTrue(result["successful"], result)
            self.assertEqual(set(result["checks"]), CHECKS)
            self.assertTrue(all(result["checks"].values()))
            self.assertEqual(result["inventory_sha256"], before)
            self.assertEqual(sha(path), before)
            self.assertEqual(calls[0][:2], ("sts", "get_caller_identity"))
            self.assertEqual(sum(service == "ecr" for service, _, _ in calls), 3)
            self.assertEqual(sum(operation == "describe_tasks" for _, operation, _ in calls), 2)
            self.assertEqual(sum(service == "scheduler" for service, _, _ in calls), 2)
            self.assertEqual(sum(service == "lambda" for service, _, _ in calls), 2)
            self.assertEqual(result["evidence_custody"]["retained_versions_checked"], 4)
            self.assertTrue(all(operation.startswith(("get_", "describe_", "list_")) for _, operation, _ in calls))

    def test_wrong_account_or_foreign_arn_stops_before_resource_reads(self):
        for mode in ("account", "arn"):
            with tempfile.TemporaryDirectory() as temp:
                path, inventory = fixture(Path(temp))
                overrides = {("sts", "get_caller_identity"): {"Account": "222222222222"}} if mode == "account" else {}
                if mode == "arn":
                    inventory["runtime_contract"]["secret_arns"]["one"] = "arn:aws:secretsmanager:us-east-1:222222222222:secret:pcfl-synthetic/runtime/foreign"
                    path.write_text(json.dumps(inventory))
                sdk, calls = clients(overrides)
                self.assertFalse(validate_teardown(path, sdk)["successful"])
                self.assertEqual(len(calls), 1)

    def test_permission_generic_404_and_unknown_errors_never_mean_absence(self):
        for code in ("AccessDenied", "404", "InternalFailure", "ClientException"):
            with tempfile.TemporaryDirectory() as temp:
                path, _ = fixture(Path(temp))
                def failure(_): raise AwsError(code)
                sdk, _ = clients({("s3", "get_bucket_location"): failure})
                result = validate_teardown(path, sdk, attempts=3, sleep=lambda _: self.fail("unknown-error-must-not-retry"))
                self.assertFalse(result["successful"])
                self.assertFalse(result["checks"]["foundation_removed"])
                self.assertEqual(len(result["attempts"]), 1)

    def test_bounded_eventual_deletion_retries_present_resource_and_retains_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path, _ = fixture(Path(temp))
            count = 0
            def bucket(_):
                nonlocal count
                count += 1
                if count == 1: return {"LocationConstraint": "us-east-1"}
                raise AwsError("NoSuchBucket")
            waits = []
            sdk, _ = clients({("s3", "get_bucket_location"): bucket})
            result = validate_teardown(path, sdk, attempts=2, retry_seconds=1, sleep=waits.append)
            self.assertTrue(result["successful"])
            self.assertEqual(len(result["attempts"]), 2)
            self.assertEqual(waits, [1])

    def test_scheduled_secret_deletion_or_active_service_or_definition_still_fails(self):
        for mode in ("secret", "service", "definition"):
            with tempfile.TemporaryDirectory() as temp:
                path, inv = fixture(Path(temp))
                if mode == "secret": override = {("secretsmanager", "describe_secret"): {"DeletedDate": "future"}}
                elif mode == "service":
                    override = {("ecs", "describe_services"): lambda args: {"services": [{"serviceArn": args["services"][0], "status": "ACTIVE", "runningCount": 0, "pendingCount": 0, "desiredCount": 0}]}}
                else:
                    override = {("ecs", "list_task_definitions"): {"taskDefinitionArns": list(inv["runtime_contract"]["task_definition_arns"].values())}}
                sdk, _ = clients(override)
                self.assertFalse(validate_teardown(path, sdk)["successful"])

    def test_stopped_tasks_and_bound_missing_ecs_are_explicit_not_empty_response(self):
        with tempfile.TemporaryDirectory() as temp:
            path, _ = fixture(Path(temp))
            sdk, _ = clients({("ecs", "describe_tasks"): lambda args: {"tasks": [{"taskArn": args["tasks"][0], "lastStatus": "STOPPED"}]}})
            self.assertTrue(validate_teardown(path, sdk)["successful"])
            sdk, _ = clients({("ecs", "describe_tasks"): {"tasks": [], "failures": []}})
            self.assertFalse(validate_teardown(path, sdk)["successful"])

    def test_changed_retained_model_witness_or_snapshot_cannot_pass(self):
        for mode in ("model", "witness", "snapshot"):
            with tempfile.TemporaryDirectory() as temp:
                path, inv = fixture(Path(temp))
                if mode == "model": target = Path(inv["retained_artifact_versions"][0]["local_path"])
                elif mode == "witness": target = Path(inv["protected_operator_witnesses"][0]["local_path"])
                else: target = Path(inv["pre_teardown_state_snapshots"]["runtime"]["path"])
                target.write_bytes(target.read_bytes() + b"changed")
                sdk, _ = clients()
                self.assertFalse(validate_teardown(path, sdk)["successful"])

    def test_serialized_durable_model_reference_must_also_have_its_exact_version(self):
        with tempfile.TemporaryDirectory() as temp:
            path, inv = fixture(Path(temp))
            raw = Path(inv["retained_artifact_versions"][1]["local_path"])
            body = json.loads(raw.read_text())
            body["candidate_json"] = json.dumps({"bucket": inv["foundation"]["bucket_name"], "key": "models/candidates/unretained.npz",
                "version_id": "missing-version", "sha256": "a" * 64})
            raw.write_text(json.dumps(body))
            # Rebind outer transport checks coherently so only the missing
            # nested immutable model version triggers the custody failure.
            inv["retained_artifact_versions"][1].update(sha256=sha(raw), size_bytes=raw.stat().st_size)
            inv["protected_operator_witnesses"][0]["raw_result_sha256"] = sha(raw)
            index = Path(inv["retained_artifact_versions"][2]["local_path"])
            value = json.loads(index.read_text())
            value["cases"][0]["artifacts"][1].update(sha256=sha(raw), size_bytes=raw.stat().st_size)
            index.write_text(json.dumps(value))
            inv["retained_artifact_versions"][2].update(sha256=sha(index), size_bytes=index.stat().st_size)
            inv["export"]["index_sha256"] = sha(index)
            path.write_text(json.dumps(inv))
            sdk, _ = clients()
            report = validate_teardown(path, sdk)
            self.assertFalse(report["successful"])
            self.assertTrue(any(error["code"] == "raw_model_exact_version_not_retained" for error in report["errors"]))

    def test_state_nonempty_unknown_resource_and_missing_stack_fail_closed(self):
        for mode in ("nonempty", "unknown", "missing"):
            with tempfile.TemporaryDirectory() as temp:
                path, inv = fixture(Path(temp))
                if mode == "missing":
                    del inv["state_paths"]["runtime"]
                    path.write_text(json.dumps(inv))
                elif mode == "nonempty":
                    state = Path(inv["state_paths"]["runtime"])
                    value = json.loads(state.read_text()); value["resources"] = [{"type": "leftover"}]
                    state.write_text(json.dumps(value))
                else:
                    snapshot = Path(inv["pre_teardown_state_snapshots"]["runtime"]["path"])
                    value = json.loads(snapshot.read_text()); value["resources"].append({"mode": "managed", "type": "aws_unhandled_resource", "instances": [{"attributes": {"id": "unknown"}}]})
                    snapshot.write_text(json.dumps(value)); inv["pre_teardown_state_snapshots"]["runtime"]["sha256"] = sha(snapshot)
                    path.write_text(json.dumps(inv))
                sdk, _ = clients()
                result = validate_teardown(path, sdk)
                self.assertFalse(result["successful"])
                self.assertFalse(result["checks"]["all_recorded_stacks_destroyed"])

    def test_operator_source_snapshot_receipt_and_exact_pointer_retirement_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path, inv = fixture(directory)
            operator_recovery(directory, inv); path.write_text(json.dumps(inv))
            sdk, _ = clients(); result = validate_teardown(path, sdk)
            self.assertTrue(result["successful"], result.get("errors"))
            self.assertEqual(result["evidence_custody"]["operator_observations_checked"], 1)
            self.assertEqual(result["evidence_custody"]["orphan_discovery_receipts_checked"], 1)
            self.assertEqual(result["evidence_custody"]["pointer_retirements_checked"], 1)

    def test_operator_source_snapshot_receipt_tamper_and_deferred_discovery_reject(self):
        for mode in ("source", "snapshot", "receipt", "deferred", "missing-receipt"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); path, inv = fixture(directory)
                record, source, snapshot, receipt = operator_recovery(directory, inv)
                if mode in {"source", "snapshot", "receipt"}:
                    target = {"source": source, "snapshot": snapshot, "receipt": receipt}[mode]
                    target.write_bytes(target.read_bytes() + b"changed")
                elif mode == "deferred": record["orphan_discovery_complete"] = False
                else: del record["orphan_discovery_receipt"]
                path.write_text(json.dumps(inv)); sdk, _ = clients()
                self.assertFalse(validate_teardown(path, sdk)["successful"])

    def test_wrong_or_missing_retirement_and_coherently_rebound_fake_pointer_reject(self):
        for mode in ("wrong", "missing", "fake-pointer"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); path, inv = fixture(directory)
                record, source_path, snapshot_path, _ = operator_recovery(directory, inv)
                if mode == "wrong": inv["retired_publication_pointers"][0]["manifest_id"] = "c" * 64
                elif mode == "missing": inv["retired_publication_pointers"] = []
                else:
                    body = json.loads(snapshot_path.read_text()); body["model_pointer"]["manifest_id"] = {"S": "c" * 64}
                    snapshot_path.write_text(json.dumps(body)); record["operator_observations"][0]["sha256"] = sha(snapshot_path)
                    source = json.loads(source_path.read_text()); source["operator_observations"][0]["sha256"] = sha(snapshot_path)
                    source_path.write_text(json.dumps(source)); record["source_report"]["sha256"] = sha(source_path)
                path.write_text(json.dumps(inv)); sdk, _ = clients(); result = validate_teardown(path, sdk)
                self.assertFalse(result["successful"])
                self.assertTrue(any("pointer" in row["code"] or "retirement" in row["code"] for row in result["errors"]))

    def test_completed_aborted_case_pointer_is_checked_from_canonical_raw_blob(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path, inv = fixture(directory)
            record, source_path, _, receipt_path = operator_recovery(directory, inv)
            raw_ref, index_ref = inv["retained_artifact_versions"][1:3]
            raw_path, index_path = Path(raw_ref["local_path"]), Path(index_ref["local_path"])
            raw = json.loads(raw_path.read_text()); raw.update(persistent_run_id="completed-aborted-run",
                durable_evidence={"sequence": {"order": 15}, "run_records": [{"PK": "RUN#completed-aborted-run", "SK": "POINTER", "manifest_id": "d" * 64}]})
            raw_path.write_text(json.dumps(raw)); raw_ref.update(sha256=sha(raw_path), size_bytes=raw_path.stat().st_size)
            index = json.loads(index_path.read_text()); index["cases"][0]["artifacts"][1].update(sha256=raw_ref["sha256"], size_bytes=raw_ref["size_bytes"])
            index_path.write_text(json.dumps(index)); index_ref.update(sha256=sha(index_path), size_bytes=index_path.stat().st_size)
            inv["export"]["index_sha256"] = index_ref["sha256"]; inv["protected_operator_witnesses"][0]["raw_result_sha256"] = raw_ref["sha256"]
            source = json.loads(source_path.read_text()); source.update(producer_source_index=index_ref, retained_versions=inv["retained_artifact_versions"])
            source_path.write_text(json.dumps(source)); record["source_report"]["sha256"] = sha(source_path)
            record["source_index"] = index_ref
            receipt = json.loads(receipt_path.read_text()); receipt["observed_versions"] = [{key: row[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
                for row in inv["retained_artifact_versions"] if row["key"].startswith(("evidence/", "models/candidates/"))]
            receipt_path.write_text(json.dumps(receipt)); record["orphan_discovery_receipt"]["sha256"] = sha(receipt_path)
            # Only the original partial producer index resolves this raw blob;
            # no normal completed export/filename traversal can find it.
            del inv["export"]
            renamed = raw_path.with_name("canonical-aborted-raw.json")
            raw_path.rename(renamed); raw_ref["local_path"] = str(renamed)
            path.write_text(json.dumps(inv)); sdk, _ = clients()
            self.assertFalse(validate_teardown(path, sdk)["successful"])
            inv["retired_publication_pointers"].append({"run_pk": "RUN#completed-aborted-run", "manifest_id": "d" * 64})
            path.write_text(json.dumps(inv)); self.assertTrue(validate_teardown(path, sdk)["successful"])

    def test_read_call_parameters_match_installed_official_sdk_models(self):
        try:
            import botocore.session
            from botocore.validate import validate_parameters
        except ImportError:
            self.skipTest("optional-official-SDK-models-unavailable")
        with tempfile.TemporaryDirectory() as temp:
            path, _ = fixture(Path(temp))
            sdk, calls = clients()
            self.assertTrue(validate_teardown(path, sdk)["successful"])
            session = botocore.session.get_session()
            for service, operation, arguments in calls:
                model = session.get_service_model(service)
                name = "".join(part.capitalize() for part in operation.split("_"))
                validate_parameters(arguments, model.operation_model(name).input_shape)


if __name__ == "__main__":
    unittest.main()
