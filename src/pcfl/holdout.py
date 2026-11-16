"""Final-holdout authorization from separately trusted, immutable operator inputs.

This module validates objects; it issues no approvals and reads no datasets.
The packaged evaluator must obtain both objects through pinned, read-only
evaluation/accepted/ references, rather than accepting them in HTTP requests.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import json
import re

from .experiments import digest, validate_plan

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
AUTHORIZATION_FIELDS = {"schema_version", "kind", "authorization_id", "status", "scope", "issued_by", "issued_at_utc",
    "plan_digest", "test_sha256", "model_schema_hash", "runs", "authorization_digest"}
EXPECTATION_FIELDS = {"plan_digest", "authorization_digest", "test_sha256", "cell_id"}


def strict_json(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_authorization_json_key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite_authorization_json")
    return json.loads(content, object_pairs_hook=unique, parse_constant=invalid)


def _hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def validate_expectation(value):
    """Response bindings for a coordinator; this grants no evaluator permission."""
    if (not isinstance(value, dict) or set(value) != EXPECTATION_FIELDS
            or any(not _hash(value[name]) for name in ("plan_digest", "authorization_digest", "test_sha256"))
            or not isinstance(value["cell_id"], str) or not _ID.fullmatch(value["cell_id"])):
        raise ValueError("explicit_final_holdout_response_bindings_required")
    return deepcopy(value)


@dataclass(frozen=True)
class HoldoutScope:
    plan_digest: str
    authorization_id: str
    authorization_digest: str
    test_sha256: str
    model_schema_hash: str
    runs: tuple

    def cell_for(self, run_id, round_id):
        for allowed_run, cell_id, final_round in self.runs:
            if allowed_run == run_id:
                if round_id != final_round:
                    raise ValueError("holdout_requires_final_registered_round")
                return cell_id
        raise ValueError("run_not_authorized_for_final_holdout")


def validate_authorization(accepted_plan, authorization, *, model_schema_hash):
    """Freeze a valid scope before any test file/model byte access is allowed."""
    if not isinstance(accepted_plan, dict) or not isinstance(authorization, dict):
        raise ValueError("accepted_plan_and_separate_operator_authorization_required")
    plan, authorization = deepcopy(accepted_plan), deepcopy(authorization)
    validate_plan(plan)
    training = plan.get("training_candidate", {})
    provenance = plan.get("provenance", {})
    images = provenance.get("image_digests", {})
    sources = provenance.get("source_files_sha256", {})
    if (plan.get("status") != "accepted_frozen" or plan.get("confirmatory_execution_enabled") is not True
            or training.get("confirmatory_frozen") is not True or training.get("pilot_only") is not False
            or training.get("final_test_access_permitted") is not False
            or type(training.get("num_rounds")) is not int or not 2 <= training["num_rounds"] <= 100
            or training.get("classification_threshold") != 0.5
            or not sources or any(not _hash(value) for value in sources.values())
            or provenance.get("source_sha256") != digest(sources) or not images
            or any(not isinstance(value, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value) for value in images.values())):
        raise ValueError("accepted_frozen_training_source_and_images_required")
    if (set(authorization) != AUTHORIZATION_FIELDS or authorization.get("schema_version") != "0.1.0"
            or authorization.get("kind") != "pcfl-final-holdout-authorization" or authorization.get("status") != "authorized"
            or authorization.get("scope") != "final-committed-model-only"
            or any(not isinstance(authorization.get(name), str) or not _ID.fullmatch(authorization[name])
                   for name in ("authorization_id", "issued_by"))
            or any(not _hash(authorization.get(name)) for name in ("plan_digest", "test_sha256", "model_schema_hash", "authorization_digest"))
            or authorization["authorization_digest"] != digest({key: value for key, value in authorization.items() if key != "authorization_digest"})
            or authorization["plan_digest"] != plan["plan_digest"] or authorization["model_schema_hash"] != model_schema_hash):
        raise ValueError("operator_holdout_authorization_binding_mismatch")
    try:
        issued = datetime.fromisoformat(authorization["issued_at_utc"].replace("Z", "+00:00"))
        if issued.tzinfo is None:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("operator_holdout_authorization_timestamp_required") from None
    runs = authorization.get("runs")
    if (not isinstance(runs, dict) or not 1 <= len(runs) <= 300
            or any(not isinstance(run_id, str) or not _ID.fullmatch(run_id) for run_id in runs)
            or any(not isinstance(cell_id, str) or not _ID.fullmatch(cell_id) for cell_id in runs.values())
            or len(set(runs.values())) != len(runs)):
        raise ValueError("unique_explicit_holdout_run_cell_mapping_required")
    all_cells = sum((plan[name] for name in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells")), [])
    cells = {cell["cell_id"]: cell for cell in all_cells}
    expected_training = {key: value for key, value in training.items() if key not in {"seed", "pilot_only", "confirmatory_frozen", "acceptance_status"}}
    expected_source = {key: value for key, value in provenance.items() if key != "git_commit"}
    for cell in all_cells:
        shared = cell["shared_config"]
        if (shared.get("test_holdout_sha256") != authorization["test_sha256"]
                or shared.get("source") != expected_source or shared.get("training") != expected_training
                or shared.get("data_manifest_digest") != plan["data_manifest_digest"]):
            raise ValueError("registered_holdout_training_source_or_dataset_binding_mismatch")
    normalized = []
    for run_id, cell_id in sorted(runs.items()):
        if (cell_id not in cells or cells[cell_id].get("unsafe_comparator") is True
                or cells[cell_id].get("family") == "ablation"):
            raise ValueError("holdout_cell_not_eligible_registered_run")
        normalized.append((run_id, cell_id, "round-" + str(cells[cell_id]["shared_config"]["training"]["num_rounds"])))
    return HoldoutScope(plan["plan_digest"], authorization["authorization_id"], authorization["authorization_digest"],
                        authorization["test_sha256"], model_schema_hash, tuple(normalized))
