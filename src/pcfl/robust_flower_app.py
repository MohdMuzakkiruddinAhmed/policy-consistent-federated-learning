"""Flower deployment-mode applications and local policy-aware aggregation pilot.

Flower carries messages between authenticated SuperNode IDs. The authority here
is an in-memory executable prototype, not the DynamoDB/OPA production adapter.
"""

from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

from .contracts import ACTIONS, ORGANIZATIONS, canonical, digest
from . import learning
from .robustness import adapter_source_digest, selected_orgs, validate_descriptor
from .reference import evaluate_history
from .runtime_observer import RuntimeObserver, observed_call, timed_stage


def arrays_digest(arrays):
    """Bind exact dtype, shape and C-order parameter bytes without pickle."""
    return digest([{"dtype": array.dtype.str, "shape": list(array.shape),
                    "sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest()}
                   for array in arrays])


def validate_arrays(arrays, template):
    if not isinstance(arrays, (list, tuple)) or len(arrays) != len(template):
        raise ValueError("parameter_count_mismatch")
    for value, expected in zip(arrays, template, strict=True):
        if (not isinstance(value, np.ndarray) or value.shape != expected.shape
                or value.dtype != expected.dtype or value.dtype != np.dtype("float32")
                or not np.isfinite(value).all()):
            raise ValueError("parameter_shape_dtype_or_finiteness_mismatch")


def weighted_average(updates, template):
    if not updates:
        raise ValueError("empty_aggregation")
    total = sum(update["sample_count"] for update in updates)
    if any(type(update["sample_count"]) is not int or update["sample_count"] < 1 for update in updates):
        raise ValueError("invalid_sample_count")
    result = [np.zeros_like(value, dtype=np.float64) for value in template]
    for update in sorted(updates, key=lambda item: (item.get("org_id", ""), item.get("update_id", ""))):
        validate_arrays(update["arrays"], template)
        for target, value in zip(result, update["arrays"], strict=True):
            target += value.astype(np.float64) * (update["sample_count"] / total)
    arrays = [value.astype(np.float32) for value in result]
    validate_arrays(arrays, template)
    return arrays


class RuntimeAuthority:
    """Local interval authority shared by the four identically trained comparators."""

    def __init__(self, baseline_id, template, model_schema_hash, *, max_examples=256):
        if baseline_id not in {"B1", "B2", "B3", "P1"}:
            raise ValueError("unknown_baseline")
        if type(max_examples) is not int or max_examples < 1:
            raise ValueError("invalid_example_budget")
        validate_arrays(template, template)
        self.baseline = baseline_id
        self.template = [value.copy() for value in template]
        self.schema_hash = model_schema_hash
        self.max_examples = max_examples
        self.lock = threading.RLock()
        self.order = 0
        self.epochs, self.tasks, self.updates, self.decisions = {}, {}, {}, {}
        self.histories, self.manifests, self.audit, self.selection = [], [], [], []
        self.round_generation = {}
        self.closed_rounds = set()
        self._published_arrays = [value.copy() for value in template]
        self._model_digest = arrays_digest(template)
        for org in ORGANIZATIONS:
            self.mutate(org, "GRANT")
        self.admission = {org: self._valid(org, "readmission", self.order, self.order) for org in ORGANIZATIONS}

    def _tick(self):
        self.order += 1
        return self.order

    def mutate(self, org, kind):
        if org not in ORGANIZATIONS or kind not in {"GRANT", "REVOKE", "EXPIRE"}:
            raise ValueError("invalid_policy_transition")
        with self.lock:
            event = {"event_id": f"policy-{self.order + 1}", "org_id": org, "order": self._tick(),
                     "epoch": self.epochs.get(org, 0) + 1, "kind": kind,
                     "rules": [{"purpose": "readmission", "action": action, "effect": "allow"}
                               for action in ACTIONS] if kind == "GRANT" else []}
            self.epochs[org] = event["epoch"]
            self.histories.append(event)
            return deepcopy(event)

    def _valid(self, org, purpose, start, end):
        return evaluate_history(self.histories, {"org_id": org, "purpose": purpose,
            "start_order": start, "commit_order": end, "actions": list(ACTIONS)})["valid"]

    def issue(self, org, node_id, round_id):
        with self.lock:
            if org not in ORGANIZATIONS or type(node_id) is not int or node_id < 1:
                raise ValueError("invalid_registered_identity")
            if not isinstance(round_id, str) or not round_id.strip() or round_id in self.closed_rounds:
                raise ValueError("invalid_or_closed_round")
            allow = (self.baseline == "B1" or (self.baseline == "B2" and self.admission[org])
                     or (self.baseline in {"B3", "P1"} and self._valid(org, "readmission", self.order, self.order)))
            self.selection.append({"org_id": org, "round_id": round_id, "selected": allow, "order": self.order})
            if not allow:
                return None
            task_id = f"{round_id}-{org}"
            if task_id in self.tasks:
                raise ValueError("duplicate_task_assignment")
            latest = next(event for event in reversed(self.histories) if event["org_id"] == org)
            task = {"task_id": task_id, "update_id": f"update-{task_id}", "org_id": org,
                    "node_id": node_id, "round_id": round_id, "purpose": "readmission",
                    "issue_order": self._tick(), "start_order": None, "policy_epoch": latest["epoch"],
                    "policy_hash": digest(latest), "model_schema_hash": self.schema_hash,
                    "nonce": secrets.token_hex(16)}
            self.tasks[task_id] = task
            return deepcopy(task)

    def acknowledge(self, task_id, source_node, echoed_task):
        with self.lock:
            task = self.tasks[task_id]
            if task["node_id"] != source_node or task != echoed_task or task["start_order"] is not None:
                raise ValueError("authorization_acknowledgment_mismatch")
            if self.baseline in {"B3", "P1"} and (
                    self.epochs[task["org_id"]] != task["policy_epoch"]
                    or not self._valid(task["org_id"], task["purpose"], self.order, self.order)):
                raise ValueError("authorization_changed_before_acknowledgment")
            task["start_order"] = self._tick()
            return deepcopy(task)

    def _finalize(self, task, outcome, reason, *, manifest_id=None, evaluation_order=None):
        uid = task["update_id"]
        if uid in self.decisions:
            raise ValueError("update_already_final")
        decision = {"update_id": uid, "task_id": task["task_id"], "org_id": task["org_id"],
                    "round_id": task["round_id"], "purpose": task["purpose"], "start_order": task["start_order"],
                    "outcome": outcome, "reason": reason,
                    "evaluation_order": evaluation_order if evaluation_order is not None else self._tick(),
                    "observed_epoch": self.epochs[task["org_id"]], "history_digest": digest(self.histories),
                    "manifest_ref": manifest_id}
        body = {"sequence": len(self.audit) + 1,
                "prev_hash": self.audit[-1]["event_hash"] if self.audit else "0" * 64,
                "payload": decision}
        self.audit.append({**body, "event_hash": digest(body)})
        self.decisions[uid] = decision

    def fail(self, task_id, reason):
        with self.lock:
            task = self.tasks[task_id]
            if task["update_id"] not in self.decisions:
                self._finalize(task, "error", reason)

    def receive(self, task_id, source_node, metadata, arrays):
        with self.lock:
            task = self.tasks[task_id]
            uid = task["update_id"]
            if task["start_order"] is None or source_node != task["node_id"]:
                raise ValueError("unauthenticated_or_unacknowledged_update")
            for key in ("task_id", "update_id", "org_id", "round_id", "purpose", "start_order", "model_schema_hash", "nonce"):
                if metadata.get(key) != task[key]:
                    raise ValueError("update_task_binding_mismatch")
            validate_arrays(arrays, self.template)
            if metadata.get("weights_digest") != arrays_digest(arrays):
                raise ValueError("update_payload_digest_mismatch")
            count = metadata.get("sample_count")
            if type(count) is not int or not 1 <= count <= self.max_examples:
                raise ValueError("invalid_sample_count")
            if uid in self.updates:
                if (self.updates[uid]["weights_digest"] != metadata["weights_digest"]
                        or self.updates[uid]["sample_count"] != count):
                    raise ValueError("update_id_rebound")
                return self.decisions.get(uid, {}).get("outcome", "pending")
            if uid in self.decisions:
                # An already finalized timeout/error cannot be resurrected by a
                # later valid payload. Structural identity checks still run first.
                return self.decisions[uid]["outcome"]
            update = {"update_id": uid, "task_id": task_id, "org_id": task["org_id"],
                      "round_id": task["round_id"], "purpose": task["purpose"], "node_id": source_node,
                      "start_order": task["start_order"], "received_order": self._tick(),
                      "weights_digest": metadata["weights_digest"], "model_schema_hash": self.schema_hash,
                      "sample_count": count, "arrays": [value.copy() for value in arrays]}
            self.updates[uid] = update
            self.round_generation[task["round_id"]] = self.round_generation.get(task["round_id"], 0) + 1
            if task["round_id"] in self.closed_rounds:
                self._finalize(task, "rejected", "round_already_closed")
                return "rejected"
            if self.baseline == "P1" and not self._valid(task["org_id"], task["purpose"], task["start_order"], self.order):
                self._finalize(task, "rejected", "authorization_interrupted")
                return "rejected"
            return "pending"

    def publish(self, round_id, *, stage=None, before_commit=None):
        """Snapshot → compute/stage → epoch/membership guard → atomic local pointer."""
        for attempt in range(3):
            with self.lock:
                if round_id in self.closed_rounds:
                    raise ValueError("round_already_published")
                pending = [update for uid, update in self.updates.items()
                           if update["round_id"] == round_id and uid not in self.decisions]
                eligible = []
                for update in pending:
                    task = self.tasks[update["task_id"]]
                    if self.baseline == "P1" and not self._valid(task["org_id"], task["purpose"], task["start_order"], self.order):
                        self._finalize(task, "rejected", "authorization_interrupted")
                    else:
                        eligible.append(deepcopy(update))
                if not eligible:
                    self.closed_rounds.add(round_id)
                    return None
                epochs = {update["org_id"]: self.epochs[update["org_id"]] for update in eligible}
                generation = self.round_generation[round_id]
                parent = self.manifests[-1]["manifest_id"] if self.manifests else None
            arrays = weighted_average(eligible, self.template)
            model_digest = arrays_digest(arrays)
            stage_input = [value.copy() for value in arrays]
            artifact = deepcopy(stage(stage_input, model_digest)) if stage else {
                "backend": "immutable_memory", "model_digest": model_digest}
            validate_arrays(stage_input, self.template)
            if (arrays_digest(stage_input) != model_digest or not isinstance(artifact, dict)
                    or artifact.get("model_digest") != model_digest):
                raise ValueError("staged_candidate_binding_mismatch")
            if before_commit:
                before_commit(attempt)
            with self.lock:
                if (generation != self.round_generation[round_id]
                        or parent != (self.manifests[-1]["manifest_id"] if self.manifests else None)
                        or any(update["update_id"] in self.decisions for update in eligible)):
                    continue
                if self.baseline == "P1" and any(self.epochs[org] != epoch for org, epoch in epochs.items()):
                    continue
                order = self._tick()
                content = {"round_id": round_id, "parent_manifest_id": parent,
                           "model_digest": model_digest, "model_schema_hash": self.schema_hash,
                           "included_update_ids": sorted(update["update_id"] for update in eligible),
                           "policy_epochs": epochs, "commit_order": order, "artifact": artifact,
                           "guarded_policy_publication": self.baseline == "P1"}
                manifest_id = digest(content)
                manifest = {**content, "manifest_id": manifest_id}
                # No user callback or fallible I/O occurs inside this atomic boundary.
                for update in eligible:
                    self._finalize(self.tasks[update["task_id"]], "accepted",
                                   "continuous_authorization" if self.baseline == "P1" else "baseline_acceptance",
                                   manifest_id=manifest_id, evaluation_order=order)
                self.manifests.append(manifest)
                self.closed_rounds.add(round_id)
                self._published_arrays = [value.copy() for value in arrays]
                self._model_digest = model_digest
                return deepcopy(manifest)
        raise RuntimeError("publication_conflict_retry_exhausted")

    def parameters(self):
        with self.lock:
            return [value.copy() for value in self._published_arrays]

    def record_update_artifact(self, update_id, artifact):
        with self.lock:
            if artifact.get("model_digest") != self.updates[update_id]["weights_digest"]:
                raise ValueError("retained_update_digest_mismatch")
            self.updates[update_id]["artifact"] = deepcopy(artifact)

    def evidence(self):
        with self.lock:
            tasks = []
            for task in self.tasks.values():
                record = {key: value for key, value in task.items() if key != "nonce"}
                record["nonce_digest"] = digest(task["nonce"])
                tasks.append(record)
            return deepcopy({"policy_events": self.histories, "tasks": tasks,
                "updates": [{key: value for key, value in update.items() if key != "arrays"} for update in self.updates.values()],
                "decisions": self.decisions, "published_manifests": self.manifests, "selection": self.selection,
                "current_model_digest": self._model_digest, "model_schema_hash": self.schema_hash,
                "closed_rounds": sorted(self.closed_rounds),
                "audit": self.audit, "anchor": {"count": len(self.audit),
                    "head": self.audit[-1]["event_hash"] if self.audit else "0" * 64}})


# Compatibility aliases; generated FABs load the lightweight client module directly.
from .robust_flower_client import client_app, acknowledge_task, train_task, _task_from_message
server_app = ServerApp()


def _collect(grid, message_ids, timeout):
    pending = set(message_ids)
    result = []
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        replies = list(grid.pull_messages(pending))
        for reply in replies:
            reference = reply.metadata.reply_to_message_id
            if reference not in pending:
                raise ValueError("duplicate_or_unknown_message_reply")
            pending.remove(reference)
            result.append(reply)
        if pending:
            time.sleep(0.05)
    return result


def _json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def run_server(grid, config):
    robust = validate_descriptor(config.get("robustness"), seed=config.get("seed", 296))
    if (robust["adapter_source_sha256"] != adapter_source_digest() or "final_holdout" in config
            or "ablation_id" in config or config.get("baseline_id", "P1") != "P1"
            or config.get("authority_backend") != "dynamodb-s3-opa" or config.get("scenario_control") is not True
            or config.get("scenario_id") != "robustness" or config.get("scripted_fault") is not None
            or config.get("experiment_binding", {}).get("family") != "exploratory"):
        raise ValueError("separate_validation_only_exploratory_app_required")
    observer = RuntimeObserver(config.get("persistent_run_id", "local-runtime"))
    registry = {int(node): org for node, org in config["node_registry"].items()}
    if len(registry) != 8 or set(registry.values()) != set(ORGANIZATIONS):
        raise ValueError("exactly_eight_unique_registered_organizations_required")
    if set(grid.get_node_ids()) != set(registry):
        raise ValueError("registered_online_node_set_mismatch")
    baseline = config.get("baseline_id", "P1")
    scenario = {"S0": "stable", "S1": "between_round", "S2": "mid_round", "S3": "delayed", "S4": "revoke_regrant", "S5": "expiry", "S6": "near_commit", "S7": "duplicate_restart", "S8": "transport_fault"}.get(
        config.get("scenario_id", "stable"), config.get("scenario_id", "stable"))
    if scenario not in {"stable", "mid_round", "delayed", "revoke_regrant", "purpose_change", "expiry", "near_commit", "between_round", "duplicate_restart", "transport_fault", "robustness"}:
        raise ValueError("unknown_policy_scenario")
    target_org = config.get("scenario_target_org", "org_01")
    if target_org not in ORGANIZATIONS:
        raise ValueError("unknown_scenario_organization")
    rounds = config.get("rounds", 1)
    if type(rounds) is not int or not 1 <= rounds <= 100:
        raise ValueError("invalid_pilot_round_count")
    seed = int(config.get("seed", 296))
    max_examples = config.get("max_examples_per_client", 256)
    ablation = config.get("authority_backend") == "dynamodb-s3-ablation"
    ablation_id = config.get("ablation_id")
    if ablation:
        from .ablations import VARIANTS
        if baseline != "P1" or ablation_id not in VARIANTS or config.get("full_protocol", False) is not False:
            raise ValueError("explicit_partial_protocol_ablation_binding_required")
    elif "ablation_id" in config or config.get("full_protocol", True) is not True:
        raise ValueError("ablation_cannot_be_labeled_full_protocol")
    persistent = config.get("authority_backend") in {"dynamodb-s3-opa", "dynamodb-s3-comparator", "dynamodb-s3-ablation"}
    comparator = config.get("authority_backend") == "dynamodb-s3-comparator"
    from .runtime_faults import AuditTransportGate, host_restart_barrier, validate_host_restart
    restart = validate_host_restart(config["host_restart"], config.get("persistent_run_id"), scenario=scenario, rounds=rounds) if "host_restart" in config else None
    scripted_fault = config.get("scripted_fault")
    if (restart and not persistent) or (scenario == "duplicate_restart" and (not restart or restart["phase"] != "between-rounds")):
        raise ValueError("S7_requires_explicit_persistent_host_restart")
    if (scenario == "transport_fault") != (scripted_fault is not None) or (scripted_fault is not None and
            (not persistent or rounds < 2 or scripted_fault not in {"opa_transport_unavailable", "audit_transport_unavailable"}
             or (scripted_fault == "opa_transport_unavailable" and baseline == "B1"))):
        raise ValueError("explicit_S8_transport_fault_and_two_rounds_required")
    fault_trace, audit_gate, fault_armed, original_opa_endpoint = [], None, False, None
    scope_metadata = {}
    if "plan_digest" in config:
        for name in ("plan_digest", "equivalence_hash"):
            if not isinstance(config.get(name), str) or not re.fullmatch(r"[0-9a-f]{64}", config[name]):
                raise ValueError("registered_plan_and_equivalence_hashes_required")
        for name in ("cell_id", "match_id"):
            if not isinstance(config.get(name), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", config[name]):
                raise ValueError("registered_cell_and_match_ids_required")
        if config.get("distribution") not in {"iid", "non_iid"}:
            raise ValueError("registered_distribution_required")
        scope_metadata = {name: config[name] for name in ("plan_digest", "equivalence_hash", "cell_id", "match_id", "distribution")}
        binding = config.get("experiment_binding")
        if (not isinstance(binding, dict) or set(binding) != {"plan_digest", "cell_id", "equivalence_hash", "family", "policy_schedule_hash", "source_sha256"}
                or any(binding.get(name) != scope_metadata[name] for name in ("plan_digest", "cell_id", "equivalence_hash"))
                or binding.get("family") not in {"primary", "targeted", "ablation", "replication", "exploratory"}
                or (binding["family"] == "ablation") != ablation
                or any(not isinstance(binding.get(name), str) or not re.fullmatch(r"[0-9a-f]{64}", binding[name])
                       for name in ("policy_schedule_hash", "source_sha256"))):
            raise ValueError("explicit_experiment_binding_required")
        scope_metadata["experiment_binding"] = deepcopy(binding)
    elif any(name in config for name in ("equivalence_hash", "cell_id", "match_id")):
        raise ValueError("registered_scope_requires_plan_digest")
    final_holdout = config.get("final_holdout")
    if final_holdout is not None:
        from .holdout import validate_expectation
        final_holdout = validate_expectation(final_holdout)
        if not persistent or ablation or scripted_fault or restart:
            raise ValueError("final_holdout_requires_persistent_committed_runtime")
        if config.get("distribution") not in {"iid", "non_iid"}:
            raise ValueError("final_holdout_requires_registered_distribution")
        if (scope_metadata.get("plan_digest") != final_holdout["plan_digest"]
                or scope_metadata.get("cell_id") != final_holdout["cell_id"]):
            raise ValueError("final_holdout_requires_registered_plan_cell_bindings")
    policy_rpc_metrics = []
    if persistent:
        from .evaluation import create_model_from_metadata, EvaluationClient, request_from_manifest, validate_test_response
        from .governance_service import PolicyClient
        from .opa import OpaClient
        from .persistent import PersistentAuthority
        from .service_io import sdk_clients
        if ((not comparator and baseline != "P1") or (comparator and baseline not in {"B1", "B2", "B3"})
                or any(key in config for key in ("data_dir", "preprocessor_path", "validation_path"))):
            raise ValueError("persistent_coordinator_requires_public_metadata_and_P1")
        if "benchmark_policy_writer" in config and config["storage"].get("local_emulation") is not True:
            raise ValueError("benchmark_policy_injection_requires_explicit_local_emulation")
        model = create_model_from_metadata(config["model_metadata"], seed_override=seed)
        ddb, s3 = sdk_clients(config["storage"])
        if scripted_fault == "audit_transport_unavailable":
            audit_gate = AuditTransportGate(ddb)
            ddb = audit_gate
        opa = OpaClient(**config["opa"]) if baseline != "B1" else None
        def policy_call(events, query):
            started = time.perf_counter()
            try:
                return opa.evaluate(events, query)
            finally:
                policy_rpc_metrics.append({"duration_ms": (time.perf_counter()-started)*1000,
                    "org_id": query["org_id"], "start_order": query["start_order"], "commit_order": query["commit_order"],
                    "history_event_count": len(events),
                    "scientific_payload_bytes": len(canonical({"events": events, "query": query})),
                    "payload_scope": "canonical events/query only; excludes OPA binding/provenance envelope"})
        policy_mutator = None
        if "benchmark_policy_writer" in config:
            policy_mutator = PolicyClient(**config["benchmark_policy_writer"]).mutate
        evaluator = (EvaluationClient(**config["evaluator"], expected_holdout=final_holdout)
                     if final_holdout is not None else EvaluationClient(**config["evaluator"]))
        authority_type, extra = PersistentAuthority, {}
        if comparator:
            from .persistent_baselines import PersistentBaselineAuthority
            authority_type, extra = PersistentBaselineAuthority, {"baseline_id": baseline}
        elif ablation:
            from .ablations import PersistentAblationAuthority
            authority_type, extra = PersistentAblationAuthority, {"ablation_id": ablation_id}
        authority = authority_type(ddb, s3, table_name=config["table_name"], bucket=config["bucket"],
            run_id=config["persistent_run_id"], template=learning.get_parameters(model), model_schema_hash=model.schema_hash,
            policy_evaluator=policy_call if opa else None, rule_hash=opa.rule_hash if opa else config["opa"]["expected_rule_hash"], max_examples=max_examples,
            policy_mutator=policy_mutator, local_emulation=config["storage"].get("local_emulation", False),
            expected_bucket_owner=config["storage"].get("expected_account_id"), initialize=True, **extra)
    else:
        model = learning.create_model(config["preprocessor_path"], seed=seed)
        authority = RuntimeAuthority(baseline, learning.get_parameters(model), model.schema_hash, max_examples=max_examples)
    output = Path(config["output_dir"])
    timeout = float(config.get("message_timeout_seconds", 300))
    training = config.get("training", learning.DEFAULT_TRAINING)
    client_training, rounds_report = [], []
    scenario_control = None
    if persistent and config.get("scenario_control"):
        from .robust_policy import RobustScenarioSignal as ScenarioSignal
        scenario_control = ScenarioSignal(ddb, config["table_name"], config["persistent_run_id"], scenario, target_org=target_org,
                                          policy_action=config.get("scenario_policy_action", "EXPIRE"), observer=observer, value=robust["factors"], seed=seed, rounds=rounds)

    def describe_issue(task):
        return {"outcome": "issued" if task else "denied", "task_id": task["task_id"] if task else None,
            "update_id": task["update_id"] if task else None,
            "observation_order": task["issue_order"] if task else authority.selection[-1]["order"]}

    def fail_task(task, reason):
        return observed_call(observer, "fail", lambda: authority.fail(task["task_id"], reason),
            round_id=task["round_id"], org_id=task["org_id"], task_id=task["task_id"], update_id=task["update_id"])

    def persist(arrays, model_digest, subdirectory, filename):
        directory = output / subdirectory
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{filename}.npz"
        if not path.exists():
            with path.open("xb") as stream:
                np.savez(stream, *arrays)
        with np.load(path, allow_pickle=False) as archive:
            persisted = [archive[f"arr_{index}"] for index in range(len(arrays))]
        if arrays_digest(persisted) != model_digest:
            raise ValueError("staged_checkpoint_digest_mismatch")
        return {"backend": "local_immutable_checkpoint", "path": str(path),
                "model_digest": model_digest, "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def stage(arrays, model_digest):
        return persist(arrays, model_digest, "model_candidates", model_digest)

    observer.stage("run_initialization", 0.0)
    try:
        for number in range(1, rounds + 1):
            round_started = time.perf_counter()
            round_id = f"round-{number}"
            if restart and restart["phase"] == "between-rounds" and round_id == restart["round_id"]:
                trace = host_restart_barrier(ddb, config["table_name"], restart, timeout=min(300, timeout))
                ready_deadline = time.monotonic() + min(300, timeout)
                while True:
                    online_nodes = set(grid.get_node_ids())
                    if online_nodes - set(registry):
                        raise RuntimeError("authenticated_node_registry_changed_after_restart")
                    if online_nodes == set(registry):
                        break
                    if time.monotonic() >= ready_deadline:
                        raise TimeoutError("authenticated_client_restart_readiness_timeout")
                    time.sleep(min(.2, max(0, ready_deadline - time.monotonic())))
                fault_trace.append({"phase": "between-rounds", "kind": "host_client_restart", "authenticated_registry_unchanged": True, **trace})
            if scenario_control:
                scenario_control.reach("before_round", round_id)
            elif scenario == "between_round" and number == 2:
                authority.mutate(target_org, "REVOKE")
            issued = {}
            messages = []
            phase_started = observer.now()
            for node, org in sorted(registry.items(), key=lambda item: item[1]):
                if org not in selected_orgs(seed, number, robust["factors"]["participation_fraction"]):
                    continue
                task = observed_call(observer, "issue", lambda: authority.issue(org, node, round_id),
                    round_id=round_id, org_id=org, describe=describe_issue)
                if task:
                    issued[node] = task
                    messages.append(grid.create_message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task)})}),
                                    "query.ack", node, round_id, ttl=timeout))
            observer.stage("issue_dispatch", phase_started, round_id=round_id)
            with timed_stage(observer, "ack_wait", round_id=round_id):
                acknowledgments = list(grid.send_and_receive(messages, timeout=timeout))
            phase_started = observer.now()
            acknowledged = {}
            for reply in acknowledgments:
                node = reply.metadata.src_node_id
                if node not in issued or node in acknowledged or reply.has_error():
                    raise ValueError("authorization_ack_failed")
                task = authority.acknowledge(issued[node]["task_id"], node, json.loads(reply.content["config"]["task_json"]))
                acknowledged[node] = task
            if set(acknowledged) != set(issued):
                raise RuntimeError("missing_authorization_ack")
            observer.stage("ack_authorization", phase_started, round_id=round_id)
            phase_started = observer.now()
            messages = [grid.create_message(RecordDict({"arrays": ArrayRecord(numpy_ndarrays=authority.parameters()),
                "config": ConfigRecord({"task_json": json.dumps(task), "training_json": json.dumps(training),
                    "seed": seed + number * 100 + ORGANIZATIONS.index(task["org_id"]), "max_examples": max_examples,
                    "hidden_dims_json": json.dumps(config["model_metadata"]["hidden_dims"]),
                    "artificial_latency_ms": robust["factors"]["artificial_latency_ms"],
                    "client_clock_skew_ms": robust["factors"]["client_clock_skew_ms"],
                    "reply_delay_seconds": float(config.get("delayed_reply_seconds", 1.0))
                        if scenario == "delayed" and number == 1 and task["org_id"] == target_org else 0.0})}),
                "train", node, round_id, ttl=timeout) for node, task in acknowledged.items()]
            message_ids = list(grid.push_messages(messages))
            observer.stage("train_dispatch", phase_started, round_id=round_id)
            phase_started = observer.now()
            if scenario_control:
                scenario_control.reach("after_dispatch", round_id)
            elif scenario in {"mid_round", "delayed", "revoke_regrant"} and number == 1:
                authority.mutate(target_org, "REVOKE")
                if scenario == "revoke_regrant":
                    authority.mutate(target_org, "GRANT")
            observer.stage("policy_barrier", phase_started, round_id=round_id)
            with timed_stage(observer, "train_wait", round_id=round_id):
                replies = _collect(grid, message_ids, timeout)
            if scenario == "duplicate_restart":
                replies = list(reversed(replies))
                original = next((reply for reply in replies if registry[reply.metadata.src_node_id] == target_org), None)
                if original is None:
                    raise RuntimeError("S7_target_reply_missing_before_replay")
                replies.append(original)
                fault_trace.append({"phase": "reply_delivery", "round_id": round_id, "kind": "duplicate_and_reverse_delivery",
                    "scope": "coordinator transport-consumption interface using actual received payload", "replayed_org_id": target_org})
            replied = set()
            round_errors = []
            round_receipts = {}
            phase_started = observer.now()
            for reply in replies:
                node = reply.metadata.src_node_id
                if node not in acknowledged or (node in replied and scenario != "duplicate_restart"):
                    raise ValueError("unknown_or_duplicate_training_sender")
                duplicate = node in replied
                replied.add(node)
                task = acknowledged[node]
                try:
                    if reply.has_error():
                        raise ValueError("client_execution_error")
                    metadata = json.loads(reply.content["config"]["metadata_json"])
                    arrays = reply.content["arrays"].to_numpy_ndarrays()
                    round_receipts[task["update_id"]] = observed_call(observer, "receive",
                        lambda: authority.receive(task["task_id"], node, metadata, arrays),
                        round_id=round_id, org_id=task["org_id"], task_id=task["task_id"], update_id=task["update_id"])
                    if duplicate:
                        fault_trace.append({"phase": "reply_delivery", "round_id": round_id, "kind": "duplicate_idempotent_receipt",
                            "org_id": task["org_id"], "update_id": task["update_id"]})
                        continue
                    artifact = persist(arrays, metadata["weights_digest"], "updates", task["update_id"])
                    authority.record_update_artifact(task["update_id"], artifact)
                    client_training.append({"org_id": task["org_id"], "round_id": round_id,
                                            **json.loads(reply.content["config"]["training_json"])})
                except (KeyError, TypeError, ValueError) as error:
                    fail_task(task, str(error))
                    round_errors.append({"org_id": task["org_id"], "reason": str(error)})
            for node in set(acknowledged) - replied:
                fail_task(acknowledged[node], "missing_client_reply")
                round_errors.append({"org_id": acknowledged[node]["org_id"], "reason": "missing_client_reply"})
            if round_errors:
                for node in acknowledged:
                    fail_task(acknowledged[node], "round_aborted_due_to_client_failure")
                raise RuntimeError("round_failed_closed")
            observer.stage("receipt", phase_started, round_id=round_id)
            def before_commit(attempt):
                if scenario_control and attempt == 0:
                    scenario_control.reach("before_commit", round_id)
                elif scenario == "near_commit" and number == 1 and attempt == 0:
                    authority.mutate(target_org, "REVOKE")
            publication_started = time.perf_counter()
            if scripted_fault and number == 2:
                before = authority.evidence()
                fault_trace.append({"phase": "fault_armed", "round_id": round_id, "kind": scripted_fault,
                    "scope": "OPA HTTP connection attempt to closed loopback port" if audit_gate is None else "audit SDK transport dispatch blocked before provider call",
                    "provider_service_stopped": False, "model_digest_before": before["current_model_digest"], "anchor_before": before["anchor"]})
                fault_trace[-1]["published_models_before"] = len(before["published_manifests"])
                if audit_gate is not None:
                    audit_gate.armed = True
                else:
                    original_opa_endpoint, opa.endpoint = opa.endpoint, "https://127.0.0.1:1"
                fault_armed = True
            def describe_publication(published):
                included = published["included_update_ids"] if published else []
                return {"outcome": "published" if published else "empty",
                    "manifest_id": published["manifest_id"] if published else None,
                    "observation_order": published["commit_order"] if published else None,
                    "included_update_ids": list(included),
                    "excluded_update_ids": sorted(set(round_receipts) - set(included)),
                    "pending_update_ids": sorted(uid for uid, outcome in round_receipts.items() if outcome == "pending")}
            with timed_stage(observer, "publication", round_id=round_id):
                manifest = observed_call(observer, "publish",
                    lambda: authority.publish(round_id, stage=stage, before_commit=before_commit),
                    round_id=round_id, describe=describe_publication)
            if fault_armed:
                if audit_gate is not None:
                    audit_gate.armed = False
                if original_opa_endpoint:
                    opa.endpoint = original_opa_endpoint
                fault_trace.append({"phase": "fault_not_triggered", "kind": scripted_fault,
                    "blocked_calls": audit_gate.blocked_calls if audit_gate else 0, "publication_occurred": manifest is not None})
                fault_armed = False
            publication_seconds = time.perf_counter()-publication_started
            if manifest:
                _json_file(output / "published_model.json", manifest)
            rounds_report.append({"round_id": round_id, "selected_clients": len(issued),
                                  "received_updates": len(replies), "published": manifest is not None,
                                  "accepted_updates": len(manifest["included_update_ids"]) if manifest else 0,
                                  "publication_seconds": publication_seconds,
                                  "duration_seconds": time.perf_counter()-round_started})
        evaluation = None
        with timed_stage(observer, "evaluation"):
            if persistent:
                if manifest:
                    evaluation_request = request_from_manifest(manifest, config["persistent_run_id"])
                    evaluation = evaluator.evaluate(evaluation_request)
                    metrics = evaluation["metrics"]
                else:
                    metrics = None  # Declared zero-contributor outcome; no invented utility.
            else:
                learning.set_parameters(model, authority.parameters())
                validation = learning.load_partition(Path(config["data_dir"]) / "validation.csv", config["preprocessor_path"],
                    max_examples=int(config.get("validation_max_examples", 256)), seed=seed)
                metrics = learning.evaluate(model, validation, threshold=0.5)
        observer.close(status="complete")
        result = {"schema_version": "0.1.0", "successful": True, "kind": "exploratory_robustness_validation", "robustness": robust, "registered_primary_case": False,
                  "baseline_id": baseline, "scenario_id": scenario, "seed": seed,
                  **scope_metadata,
                  "measurement_manifest": {"schema_version": "0.1.0", "tamper_scope": "this-runtime-invocation", "tamper_mode": "none_declared", "tamper_results": []},
                  **({"fault_trace": fault_trace, "scripted_fault": scripted_fault} if fault_trace or scripted_fault else {}),
                  "node_registry": {str(node): org for node, org in registry.items()}, "rounds": rounds_report,
                  "client_training": client_training,
                  **({"test_metrics": metrics} if final_holdout is not None else {"validation_metrics": metrics}),
                  "hypothesis_results": False, "test_holdout_evaluated": final_holdout is not None,
                  **({"accepted_plan_digest": final_holdout["plan_digest"], "plan_digest": final_holdout["plan_digest"],
                      "holdout_authorization_digest": final_holdout["authorization_digest"],
                      "test_source_sha256": final_holdout["test_sha256"], "cell_id": final_holdout["cell_id"],
                      "distribution": config["distribution"],
                      "model_metadata_digest": config["model_metadata"]["metadata_digest"]} if final_holdout is not None else {}),
                  "authority_backend": "dynamodb-s3-opa" if persistent else "in_memory_lock", "opa_used": persistent,
                  "evaluation_service_response": evaluation,
                  "benchmark_policy_injection": "benchmark_policy_writer" in config,
                  "policy_rpc_metrics": policy_rpc_metrics,
                  "runtime_observations": observer.export(),
                  "aws_used": persistent and not config["storage"].get("local_emulation", False), **authority.evidence()}
        _json_file(output / "runtime_result.json", result)
        return result
    except Exception as error:
        if fault_armed:
            before_recovery = authority.evidence()
            if audit_gate is not None:
                audit_gate.armed = False
            if original_opa_endpoint:
                opa.endpoint = original_opa_endpoint
            final_ids = set(before_recovery["decisions"]) | {record["update_id"] for record in before_recovery.get("attempt_failures", [])}
            pending = [task for task in before_recovery["tasks"] if task["update_id"] not in final_ids]
            recovery_errors = []
            for task in pending:
                try:
                    fail_task(task, "scripted_transport_fault_round_aborted")
                except Exception as recovery_error:
                    recovery_errors.append(type(recovery_error).__name__)
            after_recovery = authority.evidence()
            armed_trace = next(record for record in reversed(fault_trace) if record.get("phase") == "fault_armed")
            publications_during_fault = len(before_recovery["published_manifests"]) - armed_trace["published_models_before"]
            fault_trace.append({"phase": "fault_failed_closed", "kind": scripted_fault,
                "blocked_calls": audit_gate.blocked_calls if audit_gate else 0,
                "indeterminate_tasks_before_recovery": len(pending), "recovery_errors": recovery_errors,
                "final_update_decisions_after_recovery": len(after_recovery["decisions"]),
                "final_operational_errors_after_recovery": len(after_recovery.get("attempt_failures", [])),
                "published_models_during_fault": publications_during_fault,
                "pointer_unchanged": publications_during_fault == 0 and armed_trace["model_digest_before"] == before_recovery["current_model_digest"] == after_recovery["current_model_digest"],
                "anchor_before_recovery": before_recovery["anchor"], "anchor_after_recovery": after_recovery["anchor"]})
        observer.close(status="error")
        _json_file(output / "runtime_result.json", {"successful": False, "error": type(error).__name__,
            "reason": str(error), "baseline_id": baseline, "scenario_id": scenario, "seed": seed,
            "robustness": robust, "registered_primary_case": False,
            "measurement_manifest": {"schema_version": "0.1.0", "tamper_scope": "this-runtime-invocation", "tamper_mode": "none_declared", "tamper_results": []},
            "runtime_observations": observer.export(),
            **({"fault_trace": fault_trace, "scripted_fault": scripted_fault} if fault_trace or scripted_fault else {}),
            **scope_metadata, **authority.evidence()})
        raise


@server_app.main()
def server_main(grid: Grid, context: Context) -> None:
    path = os.environ.get("PCFL_RUNTIME_CONFIG") or context.run_config.get("runtime-config")
    if not path:
        raise ValueError("PCFL_RUNTIME_CONFIG_required")
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    run_server(grid, config)
