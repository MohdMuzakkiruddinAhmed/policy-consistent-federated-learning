"""Reviewable bounded AWS campaign stages; default is a zero-API local plan.

Mutation requires --apply and a hash-bound, explicitly approved campaign budget.
No secret payload, registry password or dataset row is printed or put in TF state.
"""
import argparse
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_CACHE_ROOT = Path.home() / ".pcfl/campaign-terraform"
sys.path.insert(0, str(ROOT / "scripts"))
from cloud_io import (bound_task_request, export_owned_versions, file_sha256, publish_image, registry_config_matches,
                      purge_recorded_versions, short_object_path, task_evidence, upload_version, validate_probe_evidence, validate_upload)

SCOPE = "remaining-phases-cloud-campaign-including-replication"
STAGES = ("plan", "bootstrap", "publish-inputs", "register-runtime", "run", "resume", "probe", "collect", "status", "teardown")


@contextmanager
def exclusive_file(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0)
        if not stream.read(1):
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    for attempt in range(6):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * 2 ** attempt)


def bound_json(binding):
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"} or not re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]):
        raise ValueError("hash_bound_json_file_required")
    if file_sha256(binding["path"]) != binding["sha256"]:
        raise ValueError("bound_file_digest_mismatch")
    return json.loads(Path(binding["path"]).read_text(encoding="utf-8"))


def load_request(path):
    request = json.loads(Path(path).read_text(encoding="utf-8"))
    for name in ("account_id", "region", "project_id", "campaign_id", "namespace", "foundation_vars", "runtime_vars", "local_image_tag"):
        if not isinstance(request.get(name), str) or not request[name].strip():
            raise ValueError("missing_request_" + name)
    if (not re.fullmatch(r"[0-9]{12}", request["account_id"]) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", request["region"])
            or not re.fullmatch(r"[a-z][a-z0-9-]{2,25}", request["project_id"])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", request["campaign_id"])):
        raise ValueError("invalid_explicit_campaign_target")
    application_id = request.get("application_campaign_id", request["campaign_id"])
    if not isinstance(application_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,80}", application_id):
        raise ValueError("invalid_application_campaign_identity")
    request.setdefault("schema_version", "0.1")
    if request["schema_version"] not in {"0.1", "0.1.0"}:
        raise ValueError("unsupported_campaign_request_version")
    for spec in request.get("data_uploads", []):
        validate_upload(spec)
    from cloud_faults import validate_restarts
    validate_restarts(request.get("host_restarts", []))
    if len({spec["key"] for spec in request.get("data_uploads", [])}) != len(request.get("data_uploads", [])):
        raise ValueError("duplicate_upload_keys")
    return request


def validate_authorization(request):
    approval = bound_json(request["authorization"])
    if approval.get("kind") == "campaign-authorization-amendment":
        if request.get("campaign_budget_kind") != "campaign-authorization-amendment":
            raise ValueError("amendment_requires_explicit_new_typed_request")
        from campaign_budget import validate_amendment
        validate_amendment(request, approval, root=ROOT)
        return approval
    if request.get("campaign_budget_kind") == "campaign-authorization-amendment":
        raise ValueError("typed_amendment_request_approval_kind_mismatch")
    numeric = ("approved_total_usd", "max_cumulative_fleet_hours", "max_vcpu", "max_memory_gib", "per_deployment_max_hours")
    if any(type(approval.get(name)) not in (int, float) or not math.isfinite(approval[name]) or approval[name] <= 0 for name in numeric):
        raise ValueError("concrete_finite_campaign_limits_required")
    if (approval.get("approved") is not True or approval.get("source") != "user-conversation"
            or approval.get("authorization_scope") != SCOPE or approval.get("account_id") != request["account_id"]
            or approval.get("region") != request["region"] or approval["approved_total_usd"] > 20
            or approval["max_cumulative_fleet_hours"] > 32 or approval["max_vcpu"] > 4
            or approval["max_memory_gib"] > 14 or approval["per_deployment_max_hours"] > 24):
        raise ValueError("new_scoped_campaign_authorization_required")
    return approval


def error_summary(error):
    result = {"error_type": type(error).__name__}
    code = getattr(error, "response", {}).get("Error", {}).get("Code")
    if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", code):
        result["aws_error_code"] = code
    if isinstance(error, RuntimeError) and re.fullmatch(r"[A-Za-z0-9_,:.-]{1,256}", str(error)):
        result["reason_code"] = str(error)
    return result


def transient_read_error(error):
    import socket
    if isinstance(error, (ConnectionError, TimeoutError, socket.gaierror)):
        return True
    try:
        from botocore.exceptions import EndpointConnectionError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError
        if isinstance(error, (EndpointConnectionError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError)):
            return True
    except ImportError:
        pass
    return getattr(error, "response", {}).get("Error", {}).get("Code") in {
        "Throttling", "ThrottlingException", "ThrottledException", "RequestLimitExceeded", "TooManyRequestsException",
        "RequestTimeout", "RequestTimeoutException", "ServiceUnavailable", "ServiceUnavailableException",
        "InternalError", "InternalFailure", "InternalServerError"}


class ReadRetryClient:
    """Retry reads only. Mutation methods and SDK waiters pass through intact."""
    def __init__(self, client, service, retry):
        self.client, self.service, self.retry = client, service, retry

    def __getattr__(self, name):
        value = getattr(self.client, name)
        if name != "get_waiter" and name.startswith(("get_", "describe_", "list_", "head_", "batch_get_")) and callable(value):
            return lambda *args, **kwargs: self.retry(self.service, name, value, *args, **kwargs)
        return value


class CampaignRunner:
    def __init__(self, request, *, apply=False, clients=None, run=subprocess.run, sleep=time.sleep):
        if apply and ("cost_scope_snapshot" in request or request.get("kind") == "frozen-campaign-cost-request"):
            raise ValueError("frozen_cost_snapshot_request_is_read_only")
        self.request, self.apply, self.run_command, self.sleep = request, apply, run, sleep
        self.directory = ROOT / "results/aws" / request["campaign_id"]
        self.inventory_path = self.directory / "inventory.json"
        self.inventory = json.loads(self.inventory_path.read_text(encoding="utf-8")) if self.inventory_path.exists() else {
            "schema_version": "0.1", "campaign_id": request["campaign_id"], "account_id": request["account_id"],
            "region": request["region"], "project_id": request["project_id"], "task_arns": [], "uploads": [], "secret_versions": {}, "fleet_ledger": {}}
        if any(self.inventory[key] != request[key] for key in ("campaign_id", "account_id", "region", "project_id")):
            raise ValueError("campaign_inventory_target_rebound")
        self.clients = clients
        self.approval = None
        self.terraform = shutil.which("terraform") or str(ROOT / ".tools/terraform/terraform.exe")
        self.budget_ledger_path = ROOT / "results/aws" / ("budget-ledger-" + request.get("authorization", {}).get("sha256", "unapproved") + ".json")

    def save(self):
        write_json(self.inventory_path, self.inventory)

    def application_id(self):
        return self.request.get("application_campaign_id", self.request["campaign_id"])

    def generation(self):
        result = self.expected_generation()
        self.inventory["application_campaign_id"] = self.application_id()
        self.inventory["runtime_generation"] = result
        return result

    def expected_generation(self):
        value = {"task_definitions": self.inventory["runtime_contract"].get("task_definition_arns", {}),
            "secret_versions": {name: {key: row[key] for key in ("version_id", "sha256")}
                                for name, row in self.inventory.get("secret_versions", {}).items()},
            "preparation_stage": self.request.get("preparation_stage"), "application_campaign_id": self.application_id()}
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def _retry_read(self, service, operation, function, *args, **kwargs):
        for attempt in range(6):
            try:
                return function(*args, **kwargs)
            except Exception as error:
                if not transient_read_error(error):
                    raise
                events = self.inventory.setdefault("transient_read_failures", [])
                if len(events) < 5000:
                    events.append({"service": service, "operation": operation, "attempt": attempt + 1,
                        "error_type": type(error).__name__, "retry_planned": attempt < 5,
                        "at_utc": datetime.now(timezone.utc).isoformat()})
                else:
                    self.inventory["transient_read_failures_dropped"] = self.inventory.get("transient_read_failures_dropped", 0) + 1
                try:
                    self.save()
                except Exception:
                    pass
                if attempt == 5:
                    raise
                self.sleep(min(16, 2 ** attempt))

    def _with_shutdown(self, action, *, stage):
        primary = None
        try:
            self.inventory["shutdown_confirmation"] = {"confirmed": False,
                "reason": "workflow-starting-or-attached", "stage": stage, "at_utc": datetime.now(timezone.utc).isoformat()}
            self.save()
            return action()
        except BaseException as error:
            primary = error
            raise
        finally:
            # A previous invocation's successful confirmation is never reused
            # when WAN/STS fails before this shutdown can even begin.
            self.inventory["shutdown_confirmation"] = {"confirmed": False,
                "reason": "shutdown-attempt-not-yet-confirmed", "at_utc": datetime.now(timezone.utc).isoformat()}
            try:
                self.stop_recorded()
            except BaseException as shutdown:
                self.inventory["shutdown_confirmation"]["confirmed"] = False
                self.inventory["shutdown_confirmation"]["observation_error_type"] = type(shutdown).__name__
                self.inventory.setdefault("host_lifecycle_failures", []).append({"stage": stage,
                    "primary_error": error_summary(primary) if primary else None,
                    "shutdown_error": error_summary(shutdown), "shutdown_confirmed": False,
                    "at_utc": datetime.now(timezone.utc).isoformat()})
                try:
                    self.save()
                except BaseException as persistence:
                    if primary:
                        primary.add_note("Local lifecycle error retention also failed: " + type(persistence).__name__)
                    else:
                        shutdown.add_note("Local lifecycle error retention also failed: " + type(persistence).__name__)
                if primary:
                    primary.shutdown_error = shutdown
                    primary.add_note("Owned task shutdown remains unconfirmed: " + type(shutdown).__name__)
                else:
                    raise
            else:
                if primary:
                    self.inventory.setdefault("host_lifecycle_failures", []).append({"stage": stage,
                        "primary_error": error_summary(primary), "shutdown_error": None,
                        "shutdown_confirmed": self.inventory.get("shutdown_confirmation", {}).get("confirmed") is True,
                        "at_utc": datetime.now(timezone.utc).isoformat()})
                    try:
                        self.save()
                    except BaseException as persistence:
                        primary.add_note("Local lifecycle error retention failed: " + type(persistence).__name__)

    def _watch_campaign(self, coordinator):
        from validate_cloud_placement import capture_placement, validate_snapshot
        clients = self.sdk()
        def captured(generation):
            for item in self.inventory.get("learning_placement_snapshots", []):
                try:
                    if item.get("runtime_generation") == generation and all(validate_snapshot(item).values()):
                        return True
                except (KeyError, TypeError, ValueError):
                    continue
            return False
        while True:
            observed = self.budget_check()
            generation = self.inventory.get("runtime_generation")
            if not captured(generation):
                clients_live = [item for item in observed if item["last_status"] == "RUNNING" and ["client"] in item.get("effective_commands", {}).values()]
                if len(clients_live) == 8:
                    try:
                        snapshot = capture_placement(self.inventory, self.request, clients)
                        self.inventory.setdefault("learning_placement_snapshots", []).append(snapshot)
                        self.save()
                    except Exception as error:
                        self.inventory.setdefault("placement_capture_errors", []).append({"kind": type(error).__name__, "at_utc": datetime.now(timezone.utc).isoformat()})
                        self.save()
            if self.request.get("host_restarts"):
                from cloud_faults import handle_client_restarts
                handle_client_restarts(self, observed)
            matches = [item for item in observed if item["task_arn"] == coordinator]
            if len(matches) != 1:
                raise RuntimeError("coordinator_state_unconfirmed_evidence_collection_required")
            task = matches[0]
            if task["last_status"] == "STOPPED":
                if task["container_exit_codes"] != [0]:
                    raise RuntimeError("coordinator_job_failed_evidence_collection_required")
                if any(not self.inventory.get("client_restart_events", {}).get(spec["request_id"], {}).get("control_acknowledged")
                       for spec in self.request.get("host_restarts", [])):
                    raise RuntimeError("requested_client_restart_not_completed")
                return {"campaign_job_completed": True, "coordinator_task_arn": coordinator}
            self.sleep(10)

    def _resume_guard(self, coordinator):
        from validate_cloud_placement import effective_commands, image_relation
        clients, contract = self.sdk(), self.inventory["runtime_contract"]
        account, region, project = (self.request[name] for name in ("account_id", "region", "project_id"))
        cluster = f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime"
        prefix = cluster.replace(":cluster/", ":task/") + "/"
        generation = self.expected_generation()
        if (contract["cluster_arn"] != cluster or not isinstance(coordinator, str) or not coordinator.startswith(prefix)
                or not re.fullmatch(r"[0-9a-f]{32}", coordinator[len(prefix):])
                or coordinator not in self.inventory["task_arns"]
                or self.inventory.get("application_campaign_id") != self.application_id()
                or self.inventory.get("runtime_generation") != generation):
            raise ValueError("resume_requires_exact_recorded_campaign_task_and_generation")
        definition_arn = contract["task_definition_arns"]["coordinator"]
        recorded = self.inventory.get("task_definition_history", {}).get(definition_arn)
        image = self.inventory["image"]["reference"]
        repository = image.split("@", 1)[0]
        if (not re.fullmatch(rf"{account}\.dkr\.ecr\.{re.escape(region)}\.amazonaws\.com/{re.escape(project)}/[a-z0-9._/-]+@sha256:[0-9a-f]{{64}}", image)
                or repository not in set(self.inventory["foundation"]["image_repositories"].values())
                or not re.fullmatch(rf"arn:aws:ecs:{re.escape(region)}:{account}:task-definition/{re.escape(project)}-[A-Za-z0-9_-]+:[1-9][0-9]*", definition_arn)
                or recorded is None or recorded.get("name") != "coordinator"):
            raise ValueError("resume_owned_current_definition_and_image_required")
        definition = clients["ecs"].describe_task_definition(taskDefinition=definition_arn)["taskDefinition"]
        containers = definition.get("containerDefinitions", [])
        role = contract["task_role_arns"]["coordinator"]
        if (definition.get("taskDefinitionArn") != definition_arn or definition.get("taskRoleArn") != role
                or role != f"arn:aws:iam::{account}:role/{project}-coordinator"
                or recorded.get("task_role_arn") != role or recorded.get("containers") != [{"name": "coordinator", "image": image}]
                or len(containers) != 1 or containers[0].get("name") != "coordinator" or containers[0].get("image") != image):
            raise ValueError("resume_actual_definition_role_or_image_mismatch")
        response = clients["ecs"].describe_tasks(cluster=cluster, tasks=[coordinator], include=["TAGS"])
        if response.get("failures") or len(response.get("tasks", [])) != 1:
            raise ValueError("resume_exact_coordinator_state_unconfirmed")
        raw = response["tasks"][0]
        tags = {row["key"]: row["value"] for row in raw.get("tags", [])}
        expected_tags = {"Project": project, "Stage": "runtime", "Campaign": self.request["campaign_id"],
                         "ApplicationCampaign": self.application_id(), "RuntimeGeneration": generation}
        actual_containers = raw.get("containers", [])
        if (raw.get("taskArn") != coordinator or raw.get("clusterArn") != cluster or raw.get("taskDefinitionArn") != definition_arn
                or raw.get("launchType") != "FARGATE" or raw.get("lastStatus") not in {"PROVISIONING", "PENDING", "ACTIVATING", "RUNNING", "DEACTIVATING", "STOPPING", "DEPROVISIONING", "STOPPED"}
                or any(tags.get(key) != value for key, value in expected_tags.items())
                or effective_commands(definition, raw) != {"coordinator": ["coordinator"]}
                or raw.get("overrides", {}).get("taskRoleArn", role) != role
                or len(actual_containers) != 1 or actual_containers[0].get("name") != "coordinator"
                or actual_containers[0].get("image") != image):
            raise ValueError("resume_actual_coordinator_identity_or_application_mismatch")
        platform = definition.get("runtimePlatform", {})
        relation = image_relation(clients["ecr"], image, actual_containers[0].get("imageDigest"),
            architecture=platform.get("cpuArchitecture"), operating_system_family=platform.get("operatingSystemFamily"))
        if not relation["verified"]:
            raise ValueError("resume_actual_coordinator_image_digest_unverified")
        task = task_evidence(raw, account, region, cluster)
        if raw["lastStatus"] != "STOPPED":
            discovery = {"ServiceId": contract["discovery_service_ids"]["coordinator"],
                "InstanceId": "campaign-" + hashlib.sha256(self.application_id().encode()).hexdigest()[:24]}
            if self.inventory.get("discovery_instance") != discovery:
                raise ValueError("resume_existing_discovery_binding_required")
            instance = clients["servicediscovery"].get_instance(**discovery)["Instance"]
            if (instance.get("Id") != discovery["InstanceId"] or not task["private_ip"]
                    or instance.get("Attributes", {}).get("AWS_INSTANCE_IPV4") != task["private_ip"]
                    or instance.get("Attributes", {}).get("AWS_INSTANCE_PORT") != "9092"):
                raise ValueError("resume_actual_discovery_private_ip_mismatch")
        return {"coordinator_task_arn": coordinator, "task_definition_arn": definition_arn,
            "application_campaign_id": self.application_id(), "runtime_generation": generation,
            "image_reference": image, "image_relation": relation, "actual_status": raw["lastStatus"],
            "at_utc": datetime.now(timezone.utc).isoformat()}

    def resume_campaign(self, coordinator):
        # Guard failures do not adopt a task, start a fleet, or stop another
        # invocation. Once bound, the same watch/budget/restart/shutdown path is
        # used as the original launch, with no service scaling or initial RunTask.
        guard = self._resume_guard(coordinator)
        self.inventory.setdefault("host_resume_sessions", []).append(guard)
        self.save()
        return self._with_shutdown(lambda: self._watch_campaign(coordinator), stage="resume")

    def _assert_active_budget_authorization(self):
        from campaign_budget import RetiredAuthorization, assert_authorization_not_retired
        try:
            actual_approval = bound_json(self.request["authorization"])
            if (actual_approval.get("kind") == "campaign-authorization-amendment"
                    or self.request.get("campaign_budget_kind") == "campaign-authorization-amendment"):
                # Classification follows the bound bytes, not a marker which
                # could be omitted from an otherwise B request.
                self.approval = validate_authorization(self.request)
            assert_authorization_not_retired(self.request, root=ROOT)
        except RetiredAuthorization:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            self._budget_ledger_fault = {"error_type": type(error).__name__,
                "reason": str(error)[:160], "at_utc": datetime.now(timezone.utc).isoformat()}
            self.inventory["budget_ledger_recovery_required"] = deepcopy(self._budget_ledger_fault)
            raise

    def _guard_amended_ledger(self, shared):
        if self.approval is None and self.request.get("campaign_budget_kind") == "campaign-authorization-amendment":
            self.approval = validate_authorization(self.request)
        if not self.approval or self.approval.get("kind") != "campaign-authorization-amendment":
            return
        from campaign_budget import campaign_inventories, require_successor_registration, validate_ledger_lineage
        require_successor_registration(self.request, root=ROOT)
        inventories = campaign_inventories(self.request, shared, root=ROOT, current_inventory=self.inventory)
        validate_ledger_lineage(self.request, shared, root=ROOT, campaign_inventories=inventories)

    def _read_budget_ledger(self, default):
        self._assert_active_budget_authorization()
        if self.approval is None and self.request.get("campaign_budget_kind") == "campaign-authorization-amendment":
            self.approval = validate_authorization(self.request)
        if self.approval and self.approval.get("kind") == "campaign-authorization-amendment":
            try:
                if not self.budget_ledger_path.is_file():
                    raise ValueError("amended_budget_requires_validated_initialized_successor_ledger")
                shared = json.loads(self.budget_ledger_path.read_text(encoding="utf-8"))
                self._guard_amended_ledger(shared)
                return shared
            except (OSError, ValueError, KeyError, TypeError) as error:
                self._budget_ledger_fault = {"error_type": type(error).__name__,
                    "reason": str(error)[:160], "at_utc": datetime.now(timezone.utc).isoformat()}
                self.inventory["budget_ledger_recovery_required"] = deepcopy(self._budget_ledger_fault)
                raise
        return json.loads(self.budget_ledger_path.read_text(encoding="utf-8")) if self.budget_ledger_path.exists() else default

    def deployment_clock(self, *, finished=False):
        """Count charged endpoint lifetime across all deployments/approval IDs."""
        with exclusive_file(self.budget_ledger_path.with_suffix(".lock")):
            shared = self._read_budget_ledger({
                "authorization_sha256": self.request["authorization"]["sha256"], "tasks": {}, "deployments": {}})
            deployments = shared.setdefault("deployments", {})
            key = self.inventory.get("endpoint_deployment_key")
            if key is None or (not finished and deployments.get(key, {}).get("finished_at")):
                if finished:
                    return
                key = self.request["campaign_id"] + "-" + str(len(deployments))
                deployments[key] = {"started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
                                    "project_id": self.request["project_id"], "campaign_id": self.request["campaign_id"]}
                self.inventory["endpoint_deployment_key"] = key
            if finished:
                deployments[key]["finished_at"] = datetime.now(timezone.utc).isoformat()
            now = datetime.now(timezone.utc)
            elapsed = sum(max(0, ((datetime.fromisoformat(item["finished_at"]) if item["finished_at"] else now)
                - datetime.fromisoformat(item["started_at"])).total_seconds()) / 3600 for item in deployments.values())
            self.inventory["cumulative_endpoint_deployment_hours"] = elapsed
            self._guard_amended_ledger(shared)
            write_json(self.budget_ledger_path, shared)
        self.save()
        if not finished and elapsed >= self.approval["max_cumulative_fleet_hours"]:
            raise RuntimeError("cumulative_endpoint_deployment_budget_exhausted")

    def authorize(self, *, cleanup=False):
        self.approval = validate_authorization(self.request)
        if self.approval.get("kind") == "campaign-authorization-amendment":
            try:
                self._read_budget_ledger({})
            except (OSError, ValueError, KeyError, TypeError):
                if not (cleanup and getattr(self, "_allow_ledger_fault_cleanup", False)):
                    raise
        if self.approval.get("kind") != "campaign-authorization-amendment":
            self._assert_active_budget_authorization()
        if cleanup:
            for stack, value in self.inventory.get("state_paths", {}).items():
                if stack not in {"foundation", "runtime"} or Path(value).resolve() != (self.directory / "state" / (stack + ".tfstate")).resolve():
                    raise ValueError("cleanup_state_path_outside_owned_campaign")
            foundation = self.inventory.get("foundation", {})
            expected_bucket = f"{self.request['project_id']}-{self.request['account_id']}-{self.request['region']}"
            if foundation.get("bucket_name", expected_bucket) != expected_bucket:
                raise ValueError("cleanup_bucket_outside_owned_campaign")
            expected_cluster = f"arn:aws:ecs:{self.request['region']}:{self.request['account_id']}:cluster/{self.request['project_id']}-runtime"
            if self.inventory.get("runtime_contract", {}).get("cluster_arn", expected_cluster) != expected_cluster:
                raise ValueError("cleanup_cluster_outside_owned_campaign")
            for value in self.inventory.get("state_paths", {}).values():
                path = Path(value)
                if not path.is_file():
                    continue
                state = json.loads(path.read_text(encoding="utf-8"))
                for resource in state.get("resources", []):
                    for instance in resource.get("instances", []):
                        attributes = instance.get("attributes", {})
                        tags = attributes.get("tags_all", attributes.get("tags", {})) or {}
                        if "Project" in tags and tags["Project"] != self.request["project_id"]:
                            raise ValueError("cleanup_state_contains_other_project_resources")
                        arn = attributes.get("arn", "")
                        match = re.match(r"arn:aws:[^:]+:[^:]*:([0-9]{12}):", arn)
                        if match and match[1] != self.request["account_id"]:
                            raise ValueError("cleanup_state_contains_other_account_resources")
            return self.approval
        reports = self.request.get("source_reports", {})
        if not {"infrastructure", "container", "services"}.issubset(reports):
            raise ValueError("three_bound_successful_source_reports_required")
        checked = {}
        for name, binding in reports.items():
            report = bound_json(binding)
            if report.get("successful") is not True:
                raise ValueError("source_validation_not_successful")
            recorded = report.get("source_sha256", report.get("verification", {}).get("source_manifest", {}).get("files_sha256", {}))
            if any(not (ROOT / path).is_file() or file_sha256(ROOT / path) != value for path, value in recorded.items()):
                raise ValueError("source_validation_is_stale")
            checked[name] = report
        if (checked["container"].get("kind") != "local-linux-cpu-container-build"
                or checked["container"].get("source_matches_worktree_at_verification") is not True
                or not checked["container"].get("verification", {}).get("source_manifest", {}).get("files_sha256")
                or checked["services"].get("local_image_id") != checked["container"].get("local_image_id")
                or not all(checked["services"].get("checks", {}).get(key) is True for key in
                    ("native_mtls_16_fixtures", "missing_client_certificate_rejected", "wrong_client_identity_rejected", "policy_write_rejected", "broad_data_read_rejected"))
                or checked["infrastructure"].get("kind") != "runtime-infrastructure-local-validation"
                or not checked["infrastructure"].get("source_sha256")
                or not all(value.get("successful") is True for value in checked["infrastructure"].get("checks", {}).values())):
            raise ValueError("actual_bound_build_service_and_infrastructure_evidence_required")
        return self.approval

    def sdk(self):
        if "cost_scope_snapshot" in self.request or self.request.get("kind") == "frozen-campaign-cost-request":
            raise ValueError("frozen_cost_snapshot_request_is_read_only")
        if self.clients is None:
            import boto3
            from botocore.config import Config
            common = {"region_name": self.request["region"], "config": Config(ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=30, retries={"max_attempts": 2})}
            self.clients = {name: boto3.client(name, **common) for name in ("sts", "s3", "dynamodb", "ecr", "ecs", "ec2", "servicediscovery", "secretsmanager", "logs")}
        identity = tuple(sorted((name, id(client)) for name, client in self.clients.items()))
        if getattr(self, "_read_clients_identity", None) != identity:
            self._read_clients = {name: ReadRetryClient(client, name, self._retry_read) for name, client in self.clients.items()}
            self._read_clients_identity = identity
        if self._read_clients["sts"].get_caller_identity()["Account"] != self.request["account_id"]:
            raise ValueError("aws_account_mismatch")
        return self._read_clients

    def local_plan(self, stage):
        limits = {"total_usd_max": 20, "cumulative_fleet_hours_max": 32, "vcpu_max": 4, "memory_gib_max": 14, "deployment_hours_max": 24}
        if self.request.get("campaign_budget_kind") == "campaign-authorization-amendment":
            approved = validate_authorization(self.request)
            limits.update(total_usd_max=approved["approved_total_usd"],
                cumulative_fleet_hours_max=approved["max_cumulative_fleet_hours"])
        return {"stage": stage, "campaign_id": self.request["campaign_id"], "account_id": self.request["account_id"],
            "application_campaign_id": self.application_id(),
            "region": self.request["region"], "aws_api_calls": False, "mutations_enabled": False,
            "authorization_file_present": Path(self.request.get("authorization", {}).get("path", "__missing__")).is_file(),
            "upload_count": len(self.request.get("data_uploads", [])), "secret_payload_count": len(self.request.get("secrets", [])),
            "stages": list(STAGES), "required_limits": limits}

    def terraform_step(self, stack, variables, *, destroy=False):
        directory = ROOT / "infra/terraform" / ("runtime" if stack == "runtime" else "")
        self.directory.mkdir(parents=True, exist_ok=True)
        state_path = self.directory / "state" / (stack + ".tfstate")
        state_path.parent.mkdir(parents=True, exist_ok=True)
        data_dir = RUNTIME_CACHE_ROOT / hashlib.sha256((self.request["account_id"] + self.request["region"] + self.request["campaign_id"]).encode()).hexdigest()[:12] / stack
        data_dir.mkdir(parents=True, exist_ok=True)
        cache = RUNTIME_CACHE_ROOT / "providers"
        cache.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "TF_DATA_DIR": str(data_dir), "TF_PLUGIN_CACHE_DIR": str(cache),
                       "TF_IN_AUTOMATION": "true", "AWS_STS_REGIONAL_ENDPOINTS": "regional"}
        self.inventory.setdefault("state_paths", {})[stack] = str(state_path)
        self.save()
        vars_path = self.directory / (stack + "-campaign.auto.tfvars.json")
        write_json(vars_path, variables)
        plan = self.directory / (stack + ("-destroy" if destroy else "") + ".tfplan")
        commands = [[self.terraform, "-chdir=" + str(directory), "init", "-input=false", "-reconfigure", "-backend-config=path=" + str(state_path)],
            [self.terraform, "-chdir=" + str(directory), "validate", "-no-color"],
            [self.terraform, "-chdir=" + str(directory), "plan", "-input=false", "-no-color", "-var-file=" + str(vars_path), "-out=" + str(plan), *(["-destroy"] if destroy else [])],
            [self.terraform, "-chdir=" + str(directory), "apply", "-input=false", "-no-color", str(plan)]]
        for index, command in enumerate(commands):
            result = self.run_command(command, cwd=ROOT, env=environment, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200, check=False)
            (self.directory / f"{stack}-{'destroy' if destroy else 'apply'}-{index}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            if result.returncode:
                raise RuntimeError("terraform_stage_failed:" + stack + ":" + str(index))
        if destroy:
            return {}
        result = self.run_command([self.terraform, "-chdir=" + str(directory), "output", "-state=" + str(state_path), "-json"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError("terraform_output_unavailable")
        return {name: value["value"] for name, value in json.loads(result.stdout).items()}

    def variables(self, name):
        value = json.loads(Path(self.request[name + "_vars"]).read_text(encoding="utf-8"))
        if value.get("expected_account_id") != self.request["account_id"] or value.get("aws_region") != self.request["region"] or value.get("project_id", "pcfl-research") != self.request["project_id"]:
            raise ValueError("terraform_target_mismatch")
        value["resource_creation_enabled"] = True
        return value

    def check_bootstrap_containment(self):
        from budget_containment import check_bootstrap_window
        approved = self.approval or validate_authorization(self.request)
        variables = self.variables("runtime")
        for component in (self.budget_ledger_path, *self.budget_ledger_path.parents):
            if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
                raise ValueError("linked_bootstrap_budget_ledger_forbidden")
            if component == ROOT:
                break
        default = {"authorization_sha256": self.request["authorization"]["sha256"], "tasks": {}, "deployments": {}}
        with exclusive_file(self.budget_ledger_path.with_suffix(".lock")):
            if hasattr(self, "_read_budget_ledger"):
                ledger = self._read_budget_ledger(default)
            else:
                ledger = json.loads(self.budget_ledger_path.read_text(encoding="utf-8")) if self.budget_ledger_path.exists() else default
            receipt = check_bootstrap_window(self.request, approved, ledger, variables,
                now=datetime.now(timezone.utc), current_deployment_key=self.inventory.get("endpoint_deployment_key"),
                recorded_expiry_utc=self.inventory.get("runtime_variables", {}).get("hard_expiry_utc"))
        self.inventory["bootstrap_cumulative_expiry_containment"] = receipt
        self.save()
        return receipt

    def bootstrap(self):
        self.check_bootstrap_containment()
        ownership_path = ROOT / "results/aws/project-ownership.json"
        ownership = json.loads(ownership_path.read_text(encoding="utf-8")) if ownership_path.exists() else {}
        target = ":".join(self.request[key] for key in ("account_id", "region", "project_id"))
        if target in ownership and ownership[target] != self.request["campaign_id"]:
            raise ValueError("project_resources_belong_to_different_retained_campaign")
        state_path = self.directory / "state/foundation.tfstate"
        owned_bucket_state = False
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            expected_bucket = f"{self.request['project_id']}-{self.request['account_id']}-{self.request['region']}"
            owned_bucket_state = any(instance.get("attributes", {}).get("id") == expected_bucket
                and instance.get("attributes", {}).get("tags_all", {}).get("Project") == self.request["project_id"]
                for resource in state.get("resources", []) if resource.get("type") == "aws_s3_bucket" for instance in resource.get("instances", []))
        if "foundation" not in self.inventory and not owned_bucket_state:
            try:
                self.sdk()["s3"].head_bucket(Bucket=f"{self.request['project_id']}-{self.request['account_id']}-{self.request['region']}", ExpectedBucketOwner=self.request["account_id"])
            except Exception as error:
                code = getattr(error, "response", {}).get("Error", {}).get("Code")
                if code not in {"404", "NoSuchBucket", "NotFound"}:
                    raise RuntimeError("cannot_establish_foundation_bucket_absence") from None
            else:
                raise ValueError("refusing_to_adopt_preexisting_bucket_into_new_campaign_state")
        ownership[target] = self.request["campaign_id"]
        write_json(ownership_path, ownership)
        foundation_vars = self.variables("foundation")
        if foundation_vars.get("budget_usd") != self.approval["approved_total_usd"]:
            raise ValueError("foundation_budget_must_match_new_approval")
        foundation = self.terraform_step("foundation", foundation_vars)
        self.inventory.update(foundation=foundation, foundation_variables=foundation_vars)
        self.save()
        runtime = self.variables("runtime")
        if (runtime["budget"]["approved_total_usd"] != self.approval["approved_total_usd"]
                or runtime["budget"]["authorization_scope"] != SCOPE):
            raise ValueError("runtime_budget_scope_mismatch")
        runtime.update(foundation={key: foundation[key] for key in ("bucket_name", "state_table_name", "client_task_role_arns", "service_task_role_arns", "image_repositories")},
            task_plan_file=None, service_desired_counts={name: 0 for name in ("coordinator", "governance", "opa", "evaluation")})
        expiry = datetime.fromisoformat(runtime["hard_expiry_utc"].replace("Z", "+00:00"))
        if not 0 < (expiry - datetime.now(timezone.utc)).total_seconds() <= self.approval["per_deployment_max_hours"] * 3600:
            raise ValueError("expiry_outside_approved_deployment_window")
        self.inventory["runtime_variables"] = runtime
        self.save()
        self.deployment_clock()
        output = self.terraform_step("runtime", runtime)
        self.inventory.update(runtime_contract=output["runtime_contract"], runtime_variables=runtime,
                              deployment_started_at=datetime.now(timezone.utc).isoformat())
        self.save()
        return {"bootstrap_complete": True, "application_tasks_started": 0}

    def publish_inputs(self):
        clients = self.sdk()
        foundation = self.inventory["foundation"]
        bucket = foundation["bucket_name"]
        for spec in self.request.get("data_uploads", []):
            prior = next((item for item in self.inventory["uploads"] if item["key"] == spec["key"] and item["sha256"] == spec["sha256"]), None)
            if prior is None:
                reference = upload_version(clients["s3"], bucket=bucket, account=self.request["account_id"], spec=spec)
                self.inventory["uploads"].append(reference)
                self.save()
        report = bound_json(self.request["source_reports"]["container"])
        inspect = self.run_command(["docker", "image", "inspect", self.request["local_image_tag"], "--format", "{{.Id}}"], capture_output=True, text=True, timeout=60, check=False)
        if inspect.returncode or inspect.stdout.strip() != report.get("local_image_id"):
            raise ValueError("local_image_does_not_match_verified_build")
        history = self.inventory.setdefault("image_history", [])
        previous = self.inventory.get("image")
        if previous and previous not in history:
            history.append(dict(previous))
        reuse = False
        if previous and previous.get("local_image_id") == report["local_image_id"]:
            repository, digest = previous["reference"].split("@")
            images = clients["ecr"].batch_get_image(repositoryName=repository.split("/", 1)[1], imageIds=[{"imageDigest": digest}]).get("images", [])
            reuse = (len(images) == 1 and images[0]["imageId"]["imageDigest"] == digest
                and registry_config_matches(clients["ecr"], repository.split("/", 1)[1], images[0]["imageManifest"], report["local_image_id"]))
            if not reuse:
                raise ValueError("recorded_image_no_longer_matches_verified_build")
        if not reuse:
            published = publish_image(clients["ecr"], account=self.request["account_id"], region=self.request["region"],
                repository=foundation["image_repositories"].get(self.request.get("image_repository_key", "coordinator")),
                local_tag=self.request["local_image_tag"], campaign_id=self.request["campaign_id"],
                source_hash=self.request["source_reports"]["container"]["sha256"], expected_local_image_id=report["local_image_id"], run=self.run_command)
            self.inventory["image"] = {**published, "local_image_id": report["local_image_id"],
                "container_report_sha256": self.request["source_reports"]["container"]["sha256"]}
            if self.inventory["image"] not in history:
                history.append(dict(self.inventory["image"]))
        self.save()
        return {"versioned_inputs": len(self.inventory["uploads"]), "image_reference": self.inventory["image"]["reference"]}

    def register_runtime(self):
        clients = self.sdk()
        contract = self.inventory["runtime_contract"]
        for spec in self.request.get("secrets", []):
            if set(spec) != {"logical_name", "payload_path"} or spec["logical_name"] not in contract["secret_arns"]:
                raise ValueError("secret_not_in_recorded_runtime_inventory")
            body = Path(spec["payload_path"]).read_text(encoding="utf-8")
            if not body or len(body.encode()) > 65536:
                raise ValueError("secret_payload_outside_service_limit")
            result = clients["secretsmanager"].put_secret_value(SecretId=contract["secret_arns"][spec["logical_name"]], SecretString=body,
                ClientRequestToken=hashlib.sha256(body.encode()).hexdigest())
            self.inventory["secret_versions"][spec["logical_name"]] = {"arn": result["ARN"], "version_id": result["VersionId"], "sha256": hashlib.sha256(body.encode()).hexdigest()}
            self.save()
        sys.path.insert(0, str(ROOT / "infra/runtime"))
        from generate import build_plan
        config = json.loads(Path(self.request["runtime_input"]).read_text(encoding="utf-8"))
        foundation = {**self.inventory["foundation"], "service_task_role_arns": {**self.inventory["foundation"]["service_task_role_arns"], **contract["task_role_arns"]}}
        plan = build_plan(config, foundation)
        if not plan["deployment_preflight_ready"]:
            raise ValueError("runtime_preflight_failed:" + ",".join(plan["blockers"]))
        if any(task["containerDefinitions"][0]["image"] != self.inventory["image"]["reference"] for task in plan["task_definitions"].values()):
            raise ValueError("runtime_image_not_published_by_this_campaign")
        plan_path = self.directory / "runtime-plan.json"
        write_json(plan_path, plan)
        variables = {**self.inventory["runtime_variables"], "task_plan_file": str(plan_path)}
        result = self.terraform_step("runtime", variables)
        self.inventory.update(runtime_contract=result["runtime_contract"], runtime_variables=variables, runtime_plan=plan)
        history = self.inventory.setdefault("task_definition_history", {})
        for name, arn in self.inventory["runtime_contract"]["task_definition_arns"].items():
            actual = clients["ecs"].describe_task_definition(taskDefinition=arn)["taskDefinition"]
            expected_role = self.inventory["runtime_contract"]["task_role_arns"][name]
            if actual["taskRoleArn"] != expected_role or any(item["image"] != self.inventory["image"]["reference"] for item in actual["containerDefinitions"]):
                raise ValueError("registered_task_role_or_image_mismatch")
            history[arn] = {"name": name, "task_role_arn": actual["taskRoleArn"], "cpu": actual["cpu"], "memory": actual["memory"],
                "containers": [{"name": item["name"], "image": item["image"]} for item in actual["containerDefinitions"]],
                "container_commands": {item["name"]: item.get("command", []) for item in actual["containerDefinitions"]},
                "source": "AWS_DescribeTaskDefinition", "recorded_at_utc": datetime.now(timezone.utc).isoformat()}
        self.save()
        return {"registered_tasks": len(plan["task_definitions"]), "cloud_validation_complete": False}

    @staticmethod
    def _ecs_error_code(error):
        from botocore.exceptions import ClientError
        return error.response.get("Error", {}).get("Code") if isinstance(error, ClientError) else None

    def _confirmed_removed_cluster(self, ecs):
        cluster = self.inventory["runtime_contract"]["cluster_arn"]
        expected = f"arn:aws:ecs:{self.request['region']}:{self.request['account_id']}:cluster/{self.request['project_id']}-runtime"
        if cluster != expected:
            raise ValueError("removed_cluster_confirmation_outside_owned_scope")
        response = ecs.describe_clusters(clusters=[cluster])
        clusters, failures = response.get("clusters"), response.get("failures", [])
        missing = clusters == [] and len(failures) == 1 and failures[0].get("arn") == cluster and failures[0].get("reason") == "MISSING"
        inactive = (isinstance(clusters, list) and len(clusters) == 1 and not failures
            and clusters[0].get("clusterArn") == cluster and clusters[0].get("status") == "INACTIVE"
            and all(type(clusters[0].get(key)) is int and clusters[0][key] == 0 for key in
                ("runningTasksCount", "pendingTasksCount", "activeServicesCount", "registeredContainerInstancesCount")))
        if missing or inactive:
            self.inventory["removed_runtime_cluster_confirmation"] = {"cluster_arn": cluster,
                "source": "AWS_DescribeClusters", "status": "MISSING" if missing else "INACTIVE",
                "at_utc": datetime.now(timezone.utc).isoformat()}
            return True
        return False

    def _confirmed_removed_service(self, ecs, service, error):
        code = self._ecs_error_code(error)
        if code == "ClusterNotFoundException":
            return self._confirmed_removed_cluster(ecs)
        if code != "ServiceNotFoundException":
            return False
        cluster = self.inventory["runtime_contract"]["cluster_arn"]
        try:
            response = ecs.describe_services(cluster=cluster, services=[service])
        except Exception as confirmation_error:
            if self._ecs_error_code(confirmation_error) == "ClusterNotFoundException":
                return self._confirmed_removed_cluster(ecs)
            raise
        service_arn = cluster.replace(":cluster/", ":service/") + "/" + service if not service.startswith("arn:") else service
        failures = response.get("failures", [])
        return (response.get("services") == [] and len(failures) == 1
            and failures[0].get("arn") in {service, service_arn} and failures[0].get("reason") == "MISSING")

    def observed_tasks(self):
        if not getattr(self, "_emergency_stop_observation_only", False):
            self._assert_active_budget_authorization()
        clients, contract = self.sdk(), self.inventory["runtime_contract"]
        history = self.inventory.setdefault("task_observation_history", {})
        for previous in [*self.inventory.get("observed_tasks", []), *self.inventory.get("client_probe_tasks", [])]:
            history.setdefault(previous["task_arn"], deepcopy(previous))
        arns = set(self.inventory["task_arns"])
        listed_running = set()
        removed_cluster = False
        try:
            for status in ("RUNNING", "STOPPED"):
                token = None
                for _ in range(100):
                    request = {"cluster": contract["cluster_arn"], "desiredStatus": status, "maxResults": 100}
                    if token:
                        request["nextToken"] = token
                    response = clients["ecs"].list_tasks(**request)
                    arns.update(response["taskArns"])
                    if status == "RUNNING":
                        listed_running.update(response["taskArns"])
                    token = response.get("nextToken")
                    if not token:
                        break
                else:
                    raise RuntimeError("recorded_cluster_inventory_pagination_exhausted")
        except Exception as error:
            if self._ecs_error_code(error) != "ClusterNotFoundException" or not self._confirmed_removed_cluster(clients["ecs"]):
                raise
            removed_cluster = True
        tasks, raw_tasks, missing = [], {}, set()
        ordered = sorted(arns)
        for start in range(0, 0 if removed_cluster else len(ordered), 100):
            try:
                response = clients["ecs"].describe_tasks(cluster=contract["cluster_arn"], tasks=ordered[start:start + 100], include=["TAGS"])
            except Exception as error:
                if self._ecs_error_code(error) != "ClusterNotFoundException" or not self._confirmed_removed_cluster(clients["ecs"]):
                    raise
                removed_cluster = True
                break
            for failure in response.get("failures", []):
                if failure.get("arn") not in arns or failure.get("reason") != "MISSING":
                    raise RuntimeError("recorded_task_description_failed")
                missing.add(failure["arn"])
            raw_tasks.update({item["taskArn"]: item for item in response["tasks"]})
            tasks.extend(task_evidence(task, self.request["account_id"], self.request["region"], contract["cluster_arn"]) for task in response["tasks"])
        if removed_cluster:
            # Deleted-cluster absence never supplies a missing task's final
            # status. Only actual previously observed STOPPED rows survive.
            if (listed_running or any(history.get(arn, {}).get("last_status") != "STOPPED" for arn in arns)
                    or any(row.get("state") == "issuing" for row in self.inventory.get("launch_intents", {}).values())):
                raise RuntimeError("removed_cluster_has_unconfirmed_recorded_tasks")
            tasks, raw_tasks, missing = [], {}, set(arns)
        for task in tasks:
            captured = self.inventory.get("task_definition_history", {}).get(task["task_definition_arn"])
            if captured is None and task["task_definition_arn"] not in set(contract["task_definition_arns"].values()):
                raise ValueError("refusing_unregistered_task_definition_in_campaign_cluster")
            task["task_role_arn"] = captured["task_role_arn"] if captured else clients["ecs"].describe_task_definition(taskDefinition=task["task_definition_arn"])["taskDefinition"]["taskRoleArn"]
            command_map = captured.get("container_commands") if captured else None
            if command_map is None:
                actual = clients["ecs"].describe_task_definition(taskDefinition=task["task_definition_arn"])["taskDefinition"]
                command_map = {item["name"]: item.get("command", []) for item in actual.get("containerDefinitions", [])}
                if captured is not None:
                    captured["container_commands"] = command_map
            raw = raw_tasks[task["task_arn"]]
            overrides = {item["name"]: item for item in raw.get("overrides", {}).get("containerOverrides", [])}
            task["effective_commands"] = {name: overrides.get(name, {}).get("command", command) for name, command in command_map.items()}
            task["launch_type"], task["platform_version"] = raw.get("launchType"), raw.get("platformVersion")
            if task.get("task_role_override") and task["task_role_override"] != task["task_role_arn"]:
                raise ValueError("unapproved_task_role_override")
            if task.get("launch_token") in self.inventory.get("launch_intents", {}):
                intent = self.inventory["launch_intents"][task["launch_token"]]
                intent.update(state="accepted", task_arn=task["task_arn"])
            if task["last_status"] == "STOPPED":
                self.inventory.setdefault("reservations", {}).pop(task["task_arn"], None)
            history[task["task_arn"]] = deepcopy(task)
        # ECS eventually expires stopped-task descriptions. Preserve their
        # actual final timestamps/exit/image data without inventing new times.
        returned = set(raw_tasks)
        tasks.extend({**deepcopy(previous), "historical_only": True}
                     for arn, previous in history.items() if arn in arns and arn not in returned and previous["last_status"] == "STOPPED")
        self.inventory["listed_desired_running_task_arns"] = sorted(listed_running)
        self.inventory["describe_missing_task_arns"] = sorted(missing)
        self.inventory["task_arns"] = sorted(arns)
        now = datetime.now(timezone.utc)
        for task in tasks:
            if task["billing_started_at"]:
                end = datetime.fromisoformat(task["stopped_at"]) if task["stopped_at"] else now
                elapsed = max(0, (end - datetime.fromisoformat(task["billing_started_at"])).total_seconds())
                billed = max(60, elapsed) if task["last_status"] == "STOPPED" else elapsed
                hours = billed / 3600
                self.inventory["fleet_ledger"][task["task_arn"]] = {"vcpu_hours": hours * task["cpu"] / 1024, "gib_hours": hours * task["memory_mib"] / 1024,
                    "actual_elapsed_seconds": elapsed, "billed_duration_lower_bound_seconds": billed}
        self.inventory["observed_tasks"] = tasks
        if getattr(self, "_emergency_stop_observation_only", False):
            # Preserve actual SDK observations locally. Never repair/reset or
            # write the untrusted shared ledger during an emergency stop.
            self.inventory["emergency_stop_observations_without_shared_ledger"] = True
            self.save()
            return tasks
        with exclusive_file(self.budget_ledger_path.with_suffix(".lock")):
            shared = self._read_budget_ledger({"authorization_sha256": self.request["authorization"]["sha256"], "tasks": {}})
            for arn, measurement in self.inventory["fleet_ledger"].items():
                previous = shared["tasks"].get(arn, {"vcpu_hours": 0, "gib_hours": 0})
                record = next((item for item in tasks if item["task_arn"] == arn), None)
                shared["tasks"][arn] = {**previous, **{key: max(previous[key], measurement[key]) for key in ("vcpu_hours", "gib_hours")},
                    **({"cpu": record["cpu"], "memory_mib": record["memory_mib"], "last_status": record["last_status"], "campaign_id": self.request["campaign_id"]} if record else {})}
            self._guard_amended_ledger(shared)
            write_json(self.budget_ledger_path, shared)
            self.inventory["shared_fleet_ledger"] = shared["tasks"]
            self.save()
            return tasks

    def budget_check(self, *, extra_cpu=0, extra_memory=0):
        tasks = self.observed_tasks()
        global_rows = self.inventory.get("shared_fleet_ledger", {})
        live = [task for task in tasks if task["last_status"] != "STOPPED"]
        live += [task for arn, task in global_rows.items() if arn not in {item["task_arn"] for item in tasks} and task.get("last_status", "STOPPED") != "STOPPED"]
        seen = {task["task_arn"] for task in tasks}
        live += [value for arn, value in self.inventory.get("reservations", {}).items() if arn not in seen]
        live += [value for value in self.inventory.get("launch_intents", {}).values() if value.get("state") == "issuing"]
        cpu = sum(task["cpu"] / 1024 for task in live) + extra_cpu
        memory = sum(task["memory_mib"] / 1024 for task in live) + extra_memory
        ledger = list(self.inventory.get("shared_fleet_ledger", self.inventory["fleet_ledger"]).values())
        fleet_hours = max(sum(item["vcpu_hours"] for item in ledger) / 4, sum(item["gib_hours"] for item in ledger) / 14)
        if self.inventory.get("endpoint_deployment_key"):
            self.deployment_clock()
            fleet_hours = max(fleet_hours, self.inventory["cumulative_endpoint_deployment_hours"])
        deadline = datetime.fromisoformat(self.inventory["runtime_variables"]["hard_expiry_utc"].replace("Z", "+00:00"))
        if cpu > self.approval["max_vcpu"] or memory > self.approval["max_memory_gib"] or fleet_hours >= self.approval["max_cumulative_fleet_hours"] or datetime.now(timezone.utc) >= deadline:
            raise RuntimeError("campaign_resource_or_duration_budget_exhausted")
        self.inventory["cumulative_fleet_hours"] = fleet_hours
        self.save()
        return tasks

    def start_task(self, name, *, overrides=None, launch_intent=None):
        definition = self.inventory["runtime_plan"]["task_definitions"][name]
        self.budget_check(extra_cpu=int(definition["cpu"]) / 1024, extra_memory=int(definition["memory"]) / 1024)
        request = bound_task_request(self.inventory["runtime_contract"], name, self.request["campaign_id"], overrides=overrides)
        generation = self.generation()
        token = hashlib.sha256(json.dumps({"generation": generation, "request": request, "launch_intent": launch_intent}, sort_keys=True).encode()).hexdigest()
        self.inventory.setdefault("launch_intents", {})[token] = {"state": "issuing", "cpu": int(definition["cpu"]), "memory_mib": int(definition["memory"])}
        self.save()
        response = self.sdk()["ecs"].run_task(**request, clientToken=token, tags=[{"key": "Project", "value": self.request["project_id"]},
            {"key": "Stage", "value": "runtime"}, {"key": "Campaign", "value": self.request["campaign_id"]},
            {"key": "ApplicationCampaign", "value": self.application_id()},
            {"key": "RuntimeGeneration", "value": generation}, {"key": "LaunchToken", "value": token}])
        if response.get("failures") or len(response.get("tasks", [])) != 1:
            if not response.get("tasks"):
                self.inventory["launch_intents"][token]["state"] = "rejected"
                self.save()
            raise RuntimeError("single_task_launch_failed")
        arn = response["tasks"][0]["taskArn"]
        self.inventory["launch_intents"][token].update(state="accepted", task_arn=arn)
        self.inventory.setdefault("reservations", {})[arn] = {"cpu": int(definition["cpu"]), "memory_mib": int(definition["memory"])}
        self.inventory["task_arns"].append(arn)
        self.save()
        return arn

    def stop_recorded(self):
        previous = getattr(self, "_emergency_stop_observation_only", False)
        self._emergency_stop_observation_only = bool(getattr(self, "_budget_ledger_fault", None))
        try:
            return self._stop_recorded()
        finally:
            self._emergency_stop_observation_only = previous

    def _stop_recorded(self):
        clients, contract = self.sdk(), self.inventory["runtime_contract"]
        failures = []
        for name, service in contract["service_names"].items():
            try:
                clients["ecs"].update_service(cluster=contract["cluster_arn"], service=service, desiredCount=0)
            except Exception as error:
                try:
                    removed = self._confirmed_removed_service(clients["ecs"], service, error)
                except Exception:
                    removed = False
                if not removed:
                    failures.append("service:" + name)
        requested, unresolved = set(), set(self.inventory["task_arns"])
        uncertain = [token for token, row in self.inventory.get("launch_intents", {}).items() if row.get("state") == "issuing"]
        confirmation_error, polls = None, 0
        try:
            for attempt in range(60):
                polls = attempt + 1
                observed = self.observed_tasks()
                stopped = {row["task_arn"] for row in observed if row["last_status"] == "STOPPED"}
                stopped.update(arn for arn, row in self.inventory.get("shared_fleet_ledger", {}).items() if row.get("last_status") == "STOPPED")
                live = {row["task_arn"] for row in observed if row["last_status"] != "STOPPED"}
                # Fresh desired-RUNNING inventory includes PENDING/PROVISIONING.
                # MISSING alone never proves that a new accepted launch stopped.
                unresolved = (set(self.inventory["task_arns"]) - stopped) | live | set(self.inventory.get("listed_desired_running_task_arns", []))
                uncertain = [token for token, row in self.inventory.get("launch_intents", {}).items() if row.get("state") == "issuing"]
                for arn in sorted(live - requested):
                    try:
                        clients["ecs"].stop_task(cluster=contract["cluster_arn"], task=arn, reason="PCFL campaign bounded shutdown")
                        requested.add(arn)
                    except Exception:
                        # A subsequent exact STOPPED observation can resolve an
                        # ambiguous StopTask response; otherwise confirmation fails.
                        pass
                if not unresolved and not uncertain:
                    break
                if attempt < 59:
                    self.sleep(5)
            else:
                failures.append("task_stop_confirmation")
        except Exception as error:
            confirmation_error = error
            failures.append("task_stop_confirmation")
        self.inventory["shutdown_confirmation"] = {"confirmed": not failures and not unresolved and not uncertain,
            "unresolved_task_arns": sorted(unresolved), "uncertain_launch_tokens": uncertain,
            "requested_stop_task_arns": sorted(requested), "polls": polls,
            "observation_error_type": type(confirmation_error).__name__ if confirmation_error else None,
            "at_utc": datetime.now(timezone.utc).isoformat()}
        if self.inventory.get("discovery_instance"):
            clients["servicediscovery"].deregister_instance(**self.inventory["discovery_instance"])
            self.inventory.pop("discovery_instance")
        self.save()
        if failures:
            raise RuntimeError("recorded_shutdown_incomplete:" + ",".join(failures)) from confirmation_error

    def run_campaign(self):
        def launch():
            clients, contract = self.sdk(), self.inventory["runtime_contract"]
            for name in ("governance", "opa", "evaluation"):
                self.budget_check(extra_cpu=0.25, extra_memory=1)
                clients["ecs"].update_service(cluster=contract["cluster_arn"], service=contract["service_names"][name], desiredCount=1)
            clients["ecs"].get_waiter("services_stable").wait(cluster=contract["cluster_arn"], services=[contract["service_names"][name] for name in ("governance", "opa", "evaluation")], WaiterConfig={"Delay": 10, "MaxAttempts": 60})
            coordinator = self.start_task("coordinator")
            clients["ecs"].get_waiter("tasks_running").wait(cluster=contract["cluster_arn"], tasks=[coordinator], WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            task = next(item for item in self.observed_tasks() if item["task_arn"] == coordinator)
            if not task["private_ip"]:
                raise RuntimeError("coordinator_private_ip_missing")
            discovery = {"ServiceId": contract["discovery_service_ids"]["coordinator"], "InstanceId": "campaign-" + hashlib.sha256(self.application_id().encode()).hexdigest()[:24]}
            clients["servicediscovery"].register_instance(**discovery, Attributes={"AWS_INSTANCE_IPV4": task["private_ip"], "AWS_INSTANCE_PORT": "9092", "AWS_INIT_HEALTH_STATUS": "HEALTHY"})
            self.inventory["discovery_instance"] = discovery
            self.save()
            for number in range(1, 9):
                self.start_task(f"org_{number:02d}")
            return self._watch_campaign(coordinator)
        return self._with_shutdown(launch, stage="run")

    def _cleanup_failed_probes(self, clients, launched, stopped):
        """Bound cleanup to this invocation's accepted task ARNs."""
        pending = sorted(set(launched) - stopped)
        errors = []
        requested = []
        for arn in pending:
            try:
                clients["ecs"].stop_task(cluster=self.inventory["runtime_contract"]["cluster_arn"], task=arn,
                    reason="PCFL failed isolation-probe bounded cleanup")
                requested.append(arn)
            except Exception as error:
                errors.append({"stage": "stop", "task_arn": arn, "error_type": type(error).__name__})
        if pending:
            try:
                clients["ecs"].get_waiter("tasks_stopped").wait(cluster=self.inventory["runtime_contract"]["cluster_arn"],
                    tasks=pending, WaiterConfig={"Delay": 5, "MaxAttempts": 12})
            except Exception as error:
                errors.append({"stage": "wait", "error_type": type(error).__name__})
        try:
            observed = self.observed_tasks()
            stopped.update(row["task_arn"] for row in observed if row["task_arn"] in launched and row["last_status"] == "STOPPED")
        except Exception as error:
            errors.append({"stage": "observe", "error_type": type(error).__name__})
        self.inventory["probe_failure_cleanup"] = {"task_arns": list(launched), "stop_requested_task_arns": requested,
            "stopped_confirmed_task_arns": sorted(stopped), "complete": set(launched) <= stopped, "errors": errors}
        self.save()

    def probe(self):
        clients, contract = self.sdk(), self.inventory["runtime_contract"]
        completed, launched, stopped = [], [], set()
        templates = list(self.inventory["runtime_plan"]["client_access_probe_templates"])
        if self.inventory["runtime_plan"].get("coordinator_access_probe_template"):
            templates.append(self.inventory["runtime_plan"]["coordinator_access_probe_template"])
        history = self.inventory.setdefault("client_probe_task_history", [])
        for previous in self.inventory.get("client_probe_tasks", []):
            if previous not in history:
                history.append(deepcopy(previous))
        self.inventory["client_probe_tasks"] = []
        self.save()
        try:
            # These launches are sequential: start_task accounts for every
            # pending reservation before allowing the next launch. The finite
            # probes then execute concurrently without orchestration threads.
            for template in templates:
                launched.append(self.start_task(template["task_definition_name"], overrides=template["overrides"]))
            if len(set(launched)) != len(launched):
                raise RuntimeError("isolation_probe_launches_must_be_distinct")
            for template, arn in zip(templates, launched):
                clients["ecs"].get_waiter("tasks_stopped").wait(cluster=contract["cluster_arn"], tasks=[arn],
                    WaiterConfig={"Delay": 5, "MaxAttempts": 60})
                task = next(item for item in self.budget_check() if item["task_arn"] == arn)
                if task["last_status"] != "STOPPED":
                    raise RuntimeError("isolation_probe_stop_not_observed")
                stopped.add(arn)
                if task["container_exit_codes"] != [0]:
                    raise RuntimeError("actual_client_isolation_probe_failed")
                config = json.loads(template["overrides"]["containerOverrides"][0]["environment"][0]["value"])
                name = template["task_definition_name"]
                log_group = contract["log_groups"][name]
                stream = "runtime/" + name + "/" + arn.rsplit("/", 1)[1]
                confirmed = None
                for _ in range(30):
                    token, messages = None, []
                    try:
                        for _page in range(100):
                            response = clients["logs"].get_log_events(logGroupName=log_group, logStreamName=stream,
                                startFromHead=True, **({"nextToken": token} if token else {}))
                            messages.extend(item["message"] for item in response.get("events", []))
                            next_token = response.get("nextForwardToken")
                            if next_token == token or not next_token:
                                break
                            token = next_token
                        candidates = []
                        for message in messages:
                            try:
                                value = json.loads(message)
                                if isinstance(value, dict) and value.get("role", "").endswith("-isolation-probe"):
                                    candidates.append(validate_probe_evidence(value, config))
                            except json.JSONDecodeError:
                                continue
                        if len(candidates) == 1:
                            confirmed = candidates[0]
                            break
                    except Exception as error:
                        if getattr(error, "response", {}).get("Error", {}).get("Code") != "ResourceNotFoundException":
                            raise
                    self.sleep(2)
                if confirmed is None:
                    raise RuntimeError("probe_task_exited_without_attributable_denial_logs")
                task["probe_response"] = confirmed
                task["probe_log_reference"] = {"log_group": log_group, "log_stream": stream,
                    "response_sha256": hashlib.sha256(json.dumps(confirmed, sort_keys=True).encode()).hexdigest()}
                completed.append(task)
                self.inventory["client_probe_tasks"] = deepcopy(completed)
                self.save()
        except BaseException:
            # Cleanup failures are additional evidence. The original denial,
            # capacity, API or interruption exception remains the raised cause.
            try:
                self._cleanup_failed_probes(clients, launched, stopped)
            except BaseException:
                pass
            raise
        return {"actual_probe_tasks_completed": len(completed), "cloud_validation_complete": False}


    def collect(self):
        clients = self.sdk()
        bucket = self.inventory["foundation"]["bucket_name"]
        application_id = self.application_id()
        prefix = "evidence/campaigns/" + application_id + "/"
        response = clients["s3"].get_object(Bucket=bucket, Key=prefix + "campaign_result.json", ExpectedBucketOwner=self.request["account_id"])
        try:
            body = response["Body"].read(32 * 1024 * 1024 + 1)
        finally:
            response["Body"].close()
        if len(body) > 32 * 1024 * 1024 or not response.get("VersionId") or response["VersionId"] == "null":
            raise RuntimeError("versioned_campaign_index_required")
        report = json.loads(body)
        if report["campaign_id"] != application_id:
            raise ValueError("campaign_index_identity_mismatch")
        export = self.directory / "r"
        if application_id != self.request["campaign_id"]:
            export /= hashlib.sha256(application_id.encode()).hexdigest()[:8]
        export.mkdir(parents=True, exist_ok=True)
        application_marker = export / "application.json"
        if application_marker.exists() and json.loads(application_marker.read_text(encoding="utf-8"))["application_campaign_id"] != application_id:
            raise ValueError("short_application_directory_collision")
        index_path = export / "campaign_result.json"
        if index_path.exists() and index_path.read_bytes() != body:
            raise ValueError("immutable_application_index_changed")
        history = self.inventory.setdefault("exports_by_application", {})
        previous = self.inventory.get("export")
        if previous:
            previous_id = previous.get("application_campaign_id", self.request["campaign_id"])
            history.setdefault(previous_id, {**previous, "application_campaign_id": previous_id,
                "export_root": previous.get("export_root", str(self.directory / "r"))})
        prior_application = history.get(application_id)
        if prior_application and (prior_application["index_sha256"] != hashlib.sha256(body).hexdigest()
                                  or prior_application["index_version_id"] != response["VersionId"]):
            raise ValueError("immutable_application_index_version_changed")
        write_json(application_marker, {"application_campaign_id": application_id})
        index_path.write_bytes(body)
        case_directories = {}
        for case in report["cases"]:
            cell_id = case.get("cell_id", hashlib.sha256(json.dumps(case, sort_keys=True).encode()).hexdigest())
            case_directory = export / hashlib.sha256(cell_id.encode()).hexdigest()[:8]
            case_directories[cell_id] = str(case_directory)
            cell_marker = case_directory / "cell.json"
            if cell_marker.exists() and json.loads(cell_marker.read_text(encoding="utf-8"))["cell_id"] != cell_id:
                raise ValueError("short_case_directory_collision")
            write_json(cell_marker, {"cell_id": cell_id})
            artifact_paths, retained = {}, []
            for artifact in case["artifacts"]:
                relative = artifact["key"].removeprefix(prefix)
                if artifact["bucket"] != bucket or not artifact["key"].startswith(prefix) or any(part in {"..", ".", ""} for part in relative.split("/")):
                    raise ValueError("export_reference_outside_campaign")
                item = clients["s3"].get_object(Bucket=bucket, Key=artifact["key"], VersionId=artifact["version_id"], ExpectedBucketOwner=self.request["account_id"])
                destination = short_object_path(case_directory, artifact["key"], artifact["version_id"],
                    filename="runtime_result.json" if Path(relative).name == "runtime_result.json" else None)
                hasher = hashlib.sha256()
                try:
                    with destination.open("wb") as stream:
                        for block in iter(lambda: item["Body"].read(1024 * 1024), b""):
                            hasher.update(block)
                            stream.write(block)
                finally:
                    item["Body"].close()
                if hasher.hexdigest() != artifact["sha256"] or destination.stat().st_size != artifact["size_bytes"]:
                    destination.unlink(missing_ok=True)
                    raise RuntimeError("export_artifact_digest_mismatch")
                retained.append({**artifact, "local_path": str(destination)})
                if destination.suffix == ".npz":
                    artifact_paths[artifact["sha256"]] = destination.name
            write_json(case_directory / "artifact_paths.json", artifact_paths)
            write_json(case_directory / "artifacts.json", retained)
        exported = {"application_campaign_id": application_id, "export_root": str(export),
            "index_key": prefix + "campaign_result.json", "index_version_id": response["VersionId"],
            "index_sha256": hashlib.sha256(body).hexdigest(), "cases": len(report["cases"]), "successful": report["successful"]}
        newly_retained = export_owned_versions(clients["s3"], bucket=bucket,
            account=self.request["account_id"], destination=export / "v",
            prior_records=self.inventory.get("retained_artifact_versions", []), cache_root=self.directory,
            metadata_references=self.inventory.get("uploads", []),
            protected_anchors=[*self.inventory.get("protected_operator_witnesses", []),
                *self.inventory.get("operator_probe_sentinels", [])],
            anchor_prefix="anchors/" + self.request["campaign_id"] + "/")
        retained_by_version = {(item["key"], item["version_id"]): item for item in self.inventory.get("retained_artifact_versions", [])}
        for item in newly_retained:
            identity = item["key"], item["version_id"]
            if identity in retained_by_version and any(retained_by_version[identity][key] != item[key] for key in ("bucket", "sha256", "size_bytes")):
                raise ValueError("retained_immutable_version_changed")
            retained_by_version.setdefault(identity, item)
        self.inventory["retained_artifact_versions"] = list(retained_by_version.values())
        canonical = {(item["key"], item["version_id"]): item for item in self.inventory["retained_artifact_versions"]}
        def s3_references(value):
            if isinstance(value, dict):
                if value.get("backend") == "s3" and {"key", "version_id", "sha256", "bucket"}.issubset(value):
                    yield value
                for nested in value.values():
                    yield from s3_references(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from s3_references(nested)
        for directory in map(Path, case_directories.values()):
            result_path = directory / "runtime_result.json"
            if not result_path.is_file():
                continue
            artifacts = json.loads((directory / "artifact_paths.json").read_text(encoding="utf-8"))
            for reference in s3_references(json.loads(result_path.read_text(encoding="utf-8"))):
                original = canonical.get((reference["key"], reference["version_id"]))
                if original is None or reference["bucket"] != bucket or original["sha256"] != reference["sha256"]:
                    raise ValueError("case_s3_reference_has_no_exact_retained_version")
                destination = short_object_path(directory, reference["key"], reference["version_id"])
                shutil.copyfile(original["local_path"], destination)
                artifacts[reference["sha256"]] = destination.name
            write_json(directory / "artifact_paths.json", artifacts)
        write_json(export / "immutable_versions.json", self.inventory["retained_artifact_versions"])
        discovery = {"bucket": bucket, "prefixes": ["evidence/", "models/candidates/"],
            "observed_versions": [{key: item[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
                                  for item in newly_retained if item["key"].startswith(("evidence/", "models/candidates/"))],
            "at_utc": datetime.now(timezone.utc).isoformat()}
        receipt_digest = hashlib.sha256(json.dumps(discovery, sort_keys=True).encode()).hexdigest()
        receipt_path = export / ("d" + receipt_digest[:16] + ".json")
        if receipt_path.exists() and json.loads(receipt_path.read_text(encoding="utf-8")) != discovery:
            raise ValueError("owned_prefix_discovery_receipt_collision")
        write_json(receipt_path, discovery)
        discovery_reference = {"path": str(receipt_path), "sha256": file_sha256(receipt_path)}
        self.inventory["last_full_owned_prefix_discovery"] = discovery_reference
        for recovery in self.inventory.get("operator_recoveries", []):
            if recovery.get("orphan_discovery_complete") is not True:
                recovery.update(orphan_discovery_complete=True, orphan_discovery_status="completed-by-full-owned-prefix-scan",
                                orphan_discovery_receipt=discovery_reference)
        exported["case_directories"] = case_directories
        history[application_id] = exported
        self.inventory["export"] = exported
        self.inventory["application_campaign_id"] = application_id
        self.save()
        return self.inventory["export"]

    def retain_pre_teardown_states(self):
        """Keep exact private resource inventories before the first destroy."""
        snapshots = self.inventory.setdefault("pre_teardown_state_snapshots", {})
        def resources(document):
            return {(row["type"], str(instance.get("attributes", {}).get("id", instance.get("attributes", {}).get("arn", ""))))
                    for row in document.get("resources", []) if row.get("mode", "managed") == "managed"
                    for instance in row.get("instances", [])}
        for stack, name in self.inventory.get("state_paths", {}).items():
            expected = (self.directory / "state" / (stack + ".tfstate")).resolve()
            if (stack not in {"foundation", "runtime"} or Path(name).resolve() != expected
                    or not expected.is_relative_to(self.directory.resolve())):
                raise ValueError("teardown_state_snapshot_outside_owned_campaign")
            body = expected.read_bytes()
            current = json.loads(body)
            if stack in snapshots:
                prior = snapshots[stack]
                path = Path(prior["path"])
                if path.resolve() != (self.directory / "state" / (stack + "-before-destroy.json")).resolve() or file_sha256(path) != prior["sha256"]:
                    raise ValueError("pre_teardown_snapshot_missing_or_changed")
                original = json.loads(path.read_text(encoding="utf-8"))
                if not resources(current) <= resources(original):
                    raise ValueError("new_resources_after_immutable_teardown_snapshot")
                continue
            if not resources(current):
                continue
            path = self.directory / "state" / (stack + "-before-destroy.json")
            if path.exists():
                if path.read_bytes() != body:
                    raise ValueError("unbound_pre_teardown_snapshot_collision")
            else:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(body)
            snapshots[stack] = {"path": str(path), "sha256": hashlib.sha256(body).hexdigest()}
        self.save()

    def retirement_pointer_bindings(self):
        """Read producer exports and separately typed operator observations."""
        pointers = {}
        def add(pk, manifest, order):
            if not isinstance(pk, str) or not pk.startswith("RUN#") or type(order) is not int or order < 0:
                raise ValueError("invalid_retained_pointer_binding")
            previous = pointers.get(pk)
            if previous and previous["order"] == order and previous["manifest_id"] != manifest:
                raise ValueError("conflicting_retained_pointer_snapshots")
            if previous is None or order > previous["order"]:
                pointers[pk] = {"manifest_id": manifest, "order": order}
        def producer_pointers(evidence):
            durable = evidence.get("durable_evidence", {})
            matches = [record for record in durable.get("run_records", []) if record.get("SK") == "POINTER"]
            run_id = evidence.get("persistent_run_id")
            if len(matches) > 1 or any(record.get("PK") != "RUN#" + str(run_id) for record in matches):
                raise ValueError("producer_pointer_run_binding_mismatch")
            if matches:
                record = matches[0]
                add(record["PK"], record.get("manifest_id"), durable.get("sequence", {}).get("order", record.get("commit_order", 0)))
            elif isinstance(run_id, str) and run_id and "sequence" in durable:
                add("RUN#" + run_id, None, durable["sequence"]["order"])
        def retained_json(reference):
            identity = tuple(reference.get(name) for name in ("bucket", "key", "version_id"))
            if (reference.get("bucket") != self.inventory["foundation"]["bucket_name"]
                    or reference.get("version_id") in {None, "", "null"}):
                raise ValueError("recovered_pointer_exact_version_missing")
            matches = [row for row in self.inventory.get("retained_artifact_versions", [])
                       if tuple(row.get(name) for name in ("bucket", "key", "version_id")) == identity]
            if len(matches) != 1 or any(matches[0].get(name) != reference.get(name) for name in ("sha256", "size_bytes")):
                raise ValueError("recovered_pointer_exact_version_missing")
            row = matches[0]
            path = Path(row["local_path"])
            lexical_root, resolved_root = self.directory.absolute(), self.directory.resolve()
            if (not path.absolute().is_relative_to(lexical_root) or not path.resolve().is_relative_to(resolved_root)
                    or any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
                           for parent in (path, *path.parents) if parent.absolute().is_relative_to(lexical_root))
                    or path.suffix != ".json" or type(row["size_bytes"]) is not int or not 0 <= row["size_bytes"] <= 32 * 1024 * 1024
                    or path.stat().st_size != row["size_bytes"] or file_sha256(path) != row["sha256"]):
                raise ValueError("recovered_pointer_retained_bytes_changed_or_outside_campaign")
            return json.loads(path.read_text(encoding="utf-8"))
        for path in (self.directory / "r").rglob("runtime_result.json"):
            if not path.resolve().is_relative_to(self.directory.resolve()) or path.is_symlink():
                raise ValueError("retained_runtime_pointer_outside_campaign")
            evidence = json.loads(path.read_text(encoding="utf-8"))
            producer_pointers(evidence)
        for recovery in self.inventory.get("operator_recoveries", []):
            if recovery.get("kind") == "registered-operator-partial-cloud-recovery" or "source_index" in recovery:
                application, reference = recovery["application_campaign_id"], recovery["source_index"]
                if (not isinstance(application, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,80}", application)
                        or not re.fullmatch(r"evidence/campaigns/" + re.escape(application)
                                            + r"/(?:index-[0-9]{4,}|campaign_result)\.json", reference.get("key", ""))):
                    raise ValueError("recovered_pointer_index_scope_mismatch")
                index = retained_json(reference)
                cases = index.get("cases")
                if (index.get("campaign_id") != application or not isinstance(cases, list)
                        or len({case.get("cell_id") for case in cases}) != len(cases)):
                    raise ValueError("recovered_pointer_index_application_or_case_mismatch")
                for case in cases:
                    cell = case.get("cell_id")
                    if not isinstance(cell, str) or not cell or "/" in cell or cell in {".", ".."}:
                        raise ValueError("recovered_pointer_index_case_scope_mismatch")
                    key = f"evidence/campaigns/{application}/{cell}/runtime_result.json"
                    raw_refs = [row for row in case.get("artifacts", []) if row.get("key") == key]
                    if len(raw_refs) != 1:
                        raise ValueError("recovered_pointer_original_raw_result_missing")
                    producer_pointers(retained_json(raw_refs[0]))
            for observation in recovery.get("operator_observations", []):
                path = Path(observation["path"])
                if (not path.resolve().is_relative_to(self.directory.resolve()) or path.is_symlink()
                        or file_sha256(path) != observation["sha256"]):
                    raise ValueError("operator_pointer_snapshot_missing_or_changed")
                body = json.loads(path.read_text(encoding="utf-8"))
                pk, rows, pointer = "RUN#" + observation["run_id"], body.get("run_records"), body.get("model_pointer")
                order = observation["authority_order"]
                if (body.get("kind") != "operator-observed-partial-persistent-state" or body.get("snapshot_coherent") is not True
                        or body.get("run_id") != observation["run_id"] or body.get("table_name") != self.inventory["foundation"]["state_table_name"]
                        or body.get("authority_order") != order or body.get("sequence", {}).get("order") != {"N": str(order)}
                        or not isinstance(rows, list) or any(row.get("PK") != {"S": pk} for row in rows)):
                    raise ValueError("operator_pointer_snapshot_binding_mismatch")
                matches = [row for row in rows if row.get("SK") == {"S": "POINTER"}]
                if matches != ([] if pointer is None else [pointer]):
                    raise ValueError("operator_pointer_not_original_typed_run_record")
                manifest = pointer.get("manifest_id") if pointer else None
                if manifest is not None and (not isinstance(manifest, dict) or set(manifest) != {"S"}):
                    raise ValueError("operator_pointer_manifest_type_mismatch")
                add(pk, manifest["S"] if manifest else None, order)
        return pointers

    def teardown(self):
        self.stop_recorded()
        if getattr(self, "_budget_ledger_fault", None):
            self.inventory["teardown_complete"] = False
            self.inventory["compute_stop_with_budget_ledger_fault"] = {
                "shutdown_confirmation": deepcopy(self.inventory.get("shutdown_confirmation")),
                "shared_ledger_rewritten": False, "accounting_complete": False,
                "foundation_retained": True, "runtime_resource_deletion_attempted": False,
                "at_utc": datetime.now(timezone.utc).isoformat()}
            self.save()
            raise RuntimeError("owned_compute_stop_attempted_but_budget_ledger_recovery_required")
        self.retain_pre_teardown_states()
        if any(row.get("orphan_discovery_complete") is not True for row in self.inventory.get("operator_recoveries", [])):
            self.terraform_step("runtime", self.inventory["runtime_variables"], destroy=True)
            self.deployment_clock(finished=True)
            raise RuntimeError("runtime_removed_but_foundation_retained_until_complete_orphan_discovery")
        if self.inventory.get("task_arns") and "export" not in self.inventory:
            # Remove paid compute/endpoints while retaining all data for later
            # recovery. This is incomplete teardown, never a successful purge.
            self.terraform_step("runtime", self.inventory["runtime_variables"], destroy=True)
            self.deployment_clock(finished=True)
            raise RuntimeError("runtime_removed_but_foundation_retained_until_evidence_export")
        clients = self.sdk()
        self.terraform_step("runtime", self.inventory["runtime_variables"], destroy=True)
        self.deployment_clock(finished=True)
        from ecr_manifest_cleanup import retain_image_graph
        graph_binding = retain_image_graph(clients["ecr"], self.inventory, directory=self.directory,
            prior_graph=self.inventory.get("ecr_manifest_graph"))
        self.inventory["ecr_manifest_graph"] = graph_binding
        self.save()
        for reference in self.inventory.get("retained_artifact_versions", []):
            if file_sha256(reference["local_path"]) != reference["sha256"]:
                raise ValueError("retained_artifact_changed_before_cleanup")
        for spec in self.request.get("data_uploads", []):
            validate_upload(spec)
        retired = list(self.inventory.get("retired_publication_pointers", []))
        for pk, expected in self.retirement_pointer_bindings().items():
            key = {"PK": {"S": pk}, "SK": {"S": "POINTER"}}
            current = clients["dynamodb"].get_item(TableName=self.inventory["foundation"]["state_table_name"], Key=key, ConsistentRead=True).get("Item", {})
            if not current.get("manifest_id"):
                continue
            if current["manifest_id"] != {"S": expected["manifest_id"]}:
                raise ValueError("refusing_unexported_publication_pointer_retirement")
            clients["dynamodb"].update_item(TableName=self.inventory["foundation"]["state_table_name"], Key=key,
                UpdateExpression="SET #retired = :true REMOVE #manifest", ConditionExpression="#manifest = :manifest",
                ExpressionAttributeNames={"#retired": "retired_by_campaign_cleanup", "#manifest": "manifest_id"},
                ExpressionAttributeValues={":true": {"BOOL": True}, ":manifest": {"S": expected["manifest_id"]}})
            entry = {"run_pk": pk, "manifest_id": expected["manifest_id"]}
            if entry not in retired:
                retired.append(entry)
        self.inventory["retired_publication_pointers"] = retired
        self.save()
        from generated_secret_cleanup import cleanup_generated_secrets, retain_cleanup_receipt
        secret_result = cleanup_generated_secrets(clients, self.request, self.inventory,
            directory=self.directory, root=ROOT, sleep=self.sleep)
        secret_receipt = retain_cleanup_receipt(secret_result, directory=self.directory)
        attempts = self.inventory.setdefault("generated_secret_cleanup_attempts", [])
        if secret_receipt not in attempts:
            attempts.append(secret_receipt)
        self.inventory["generated_secret_cleanup"] = secret_receipt
        self.save()
        if secret_result.get("successful") is not True:
            raise RuntimeError("generated_secret_cleanup_incomplete_before_storage_purge")
        from probe_anchor import sentinel_references
        probe_sentinels = sentinel_references(self.inventory, self.directory)
        removed = purge_recorded_versions(clients["s3"], bucket=self.inventory["foundation"]["bucket_name"],
            account=self.request["account_id"], project=self.request["project_id"],
            references=[*self.inventory["uploads"], *self.inventory.get("retained_artifact_versions", [])])
        self.inventory["removed_recorded_s3_versions"] = removed
        self.inventory["removed_operator_probe_sentinel_versions"] = probe_sentinels
        image_references = {item["reference"] for item in self.inventory.get("image_history", [])}
        if self.inventory.get("image"):
            image_references.add(self.inventory["image"]["reference"])
        from ecr_manifest_cleanup import delete_image_graph
        self.inventory["ecr_manifest_cleanup"] = delete_image_graph(clients["ecr"], self.inventory,
            graph_binding=graph_binding, directory=self.directory)
        self.inventory["removed_owned_image_references"] = sorted(image_references)
        self.save()
        clients["dynamodb"].update_table(TableName=self.inventory["foundation"]["state_table_name"], DeletionProtectionEnabled=False)
        clients["dynamodb"].get_waiter("table_exists").wait(TableName=self.inventory["foundation"]["state_table_name"], WaiterConfig={"Delay": 5, "MaxAttempts": 30})
        self.terraform_step("foundation", self.inventory["foundation_variables"], destroy=True)
        self.inventory["teardown_complete"] = True
        self.save()
        ownership_path = ROOT / "results/aws/project-ownership.json"
        ownership = json.loads(ownership_path.read_text(encoding="utf-8"))
        target = ":".join(self.request[key] for key in ("account_id", "region", "project_id"))
        if ownership.get(target) == self.request["campaign_id"]:
            del ownership[target]
            write_json(ownership_path, ownership)
        return {"teardown_complete": True, "cost_reconciliation_still_required": True}

    def execute(self, stage, *, coordinator_task_arn=None):
        if ("cost_scope_snapshot" in self.request or self.request.get("kind") == "frozen-campaign-cost-request") and (self.apply or stage in {"status", "collect"}):
            raise ValueError("frozen_cost_snapshot_request_is_read_only")
        if stage == "plan" or (not self.apply and stage not in {"status", "collect"}):
            return self.local_plan(stage)
        if stage not in {"status", "collect"}:
            self._allow_ledger_fault_cleanup = stage == "teardown"
            self.authorize(cleanup=stage in {"teardown", "resume"})
        if stage in {"status", "collect"}:
            self._assert_active_budget_authorization()
        if stage in {"status", "collect"} and self.request.get("campaign_budget_kind") == "campaign-authorization-amendment":
            self.approval = validate_authorization(self.request)
            self._read_budget_ledger({})
        if stage == "status":
            return {"tasks": self.observed_tasks(), "cloud_validation_complete": False}
        if stage == "bootstrap":
            self.check_bootstrap_containment()
        self.sdk()
        operation = {"bootstrap": self.bootstrap, "publish-inputs": self.publish_inputs, "register-runtime": self.register_runtime,
                     "run": self.run_campaign, "resume": lambda: self.resume_campaign(coordinator_task_arn), "probe": self.probe, "collect": self.collect, "teardown": self.teardown}[stage]
        with exclusive_file(ROOT / "results/aws/campaign-operation.lock"):
            # Authorization may have retired while this process waited for
            # the global lock. Recheck before any mutation, including collect.
            from campaign_budget import RetiredAuthorization
            try:
                self._assert_active_budget_authorization()
                if self.approval and self.approval.get("kind") == "campaign-authorization-amendment":
                    self._read_budget_ledger({})
            except RetiredAuthorization:
                raise
            except (OSError, ValueError, KeyError, TypeError):
                if not (stage == "teardown" and getattr(self, "_allow_ledger_fault_cleanup", False)
                        and getattr(self, "_budget_ledger_fault", None)):
                    raise
                # This reaches only teardown's owned-compute stop path.
                # It cannot rewrite a bad ledger or delete retained resources.
            if stage == "teardown" and getattr(self, "_budget_ledger_fault", None):
                return CampaignRunner.teardown(self)
            return operation()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--stage", choices=STAGES, default="plan")
    parser.add_argument("--coordinator-task-arn", help="Exact recorded existing coordinator ARN; required with --stage resume --apply")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    if args.coordinator_task_arn and args.stage != "resume":
        parser.error("--coordinator-task-arn is only valid with --stage resume")
    if args.stage == "resume" and args.apply and not args.coordinator_task_arn:
        parser.error("--stage resume --apply requires --coordinator-task-arn")
    runner = CampaignRunner(load_request(args.request), apply=args.apply)
    result = runner.local_plan(args.stage) if args.plan else runner.execute(args.stage, coordinator_task_arn=args.coordinator_task_arn)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
