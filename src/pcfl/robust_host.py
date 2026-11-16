"""Pure future host-input binding; no SDK, secret creation, deployment or row reads."""
from copy import deepcopy
import hashlib
import json

from .contracts import ORGANIZATIONS, digest
from .robustness import adapter_source_digest, validate_descriptor, validate_registry
from .service_runtime import validate_pinned_reference


def document_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def public_documents(registry, group):
    validate_registry(registry)
    application = "robust-" + registry["registry_digest"][:12] + "-" + group["group_id"].removeprefix("group-")
    expected = {case["case_id"]: case for case in registry["cases"] if case["deployment_group"] == group["group_id"]}
    if not expected or {case["cell_id"] for case in group["cases"]} != set(expected) or len(group["cases"]) != len(expected):
        raise ValueError("complete_registered_exploratory_group_required")
    for case in group["cases"]:
        registered, runtime = expected[case["cell_id"]], case["runtime"]
        robust = validate_descriptor(runtime.get("robustness"), seed=runtime.get("seed"))
        if (robust != registered["robustness"] or robust["adapter_source_sha256"] != adapter_source_digest()
                or runtime.get("model_metadata") != registered["architecture"]["model_metadata"]
                or runtime.get("equivalence_hash") != registered["equivalence_hash"]
                or runtime.get("experiment_binding", {}).get("family") != "exploratory"
                or any(name in runtime for name in ("final_holdout", "data_dir", "preprocessor_path", "validation_path", "benchmark_policy_writer"))):
            raise ValueError("exploratory_runtime_not_bound_to_registered_group")
        shared = registered["shared_config"]
        expected_runtime = {"plan_digest": registry["registry_digest"], "cell_id": registered["case_id"],
            "seed": 296, "rounds": 5, "max_examples_per_client": shared["training"]["max_examples_per_client"],
            "validation_source_sha256": shared["validation_sha256"], "distribution": registered["distribution"],
            "scenario_id": "robustness", "scenario_control": True, "baseline_id": "P1", "authority_backend": "dynamodb-s3-opa",
            "training": {key: shared["training"][key] for key in ("optimizer", "learning_rate", "local_epochs", "batch_size", "cpu_threads")}}
        binding = {"plan_digest": registry["registry_digest"], "cell_id": registered["case_id"],
            "equivalence_hash": registered["equivalence_hash"], "family": "exploratory",
            "policy_schedule_hash": digest(registered["schedule"]), "source_sha256": robust["adapter_source_sha256"]}
        if any(runtime.get(key) != value for key, value in expected_runtime.items()) or runtime.get("experiment_binding") != binding:
            raise ValueError("exploratory_registered_training_and_schedule_binding_required")
    return {"application_campaign_id": application,
        "campaign_key": f"metadata/{application}/campaign.json", "policy_key": f"policies/{application}/campaign.json",
        "model_key": f"metadata/{application}/model.json",
        "campaign": {"campaign_id": application, "plan_digest": registry["registry_digest"], "cases": deepcopy(group["cases"]),
            "task_deadline_seconds": 12*3600, "stop_on_failure": False},
        "policy": deepcopy(group["policy_campaign"]), "model": deepcopy(group["evaluation_override"]["model_metadata"])}


def bind_group(registry, group, runtime_input, role_configs, uploads, *, validation_reports):
    """Bind already uploaded immutable versions to a separately deployed actor generation.

    Private role configurations stay private. Existing IAM, network, role secret
    references and read-only task settings remain subject to the normal renderer.
    This return value does not authorize or launch anything.
    """
    docs = public_documents(registry, group)
    image = group["cases"][0]["runtime"]["robustness"]["adapter_image"]
    owner, bucket = runtime_input.get("account_id"), role_configs.get("coordinator", {}).get("bucket")
    if (set(role_configs) != {"coordinator", "governance", "evaluation", "opa"}
            or any(case["runtime"]["robustness"]["adapter_image"] != image for case in group["cases"])
            or set(validation_reports) != {"infrastructure", "container"}
            or set(runtime_input.get("images", {})) != {"client", "coordinator"}
            or set(runtime_input.get("services", {})) != {"governance", "opa", "evaluation"}):
        raise ValueError("separate_adapter_roles_and_validation_reports_required")
    evaluator = role_configs["evaluation"]
    if evaluator.get("dataset_role", "validation") != "validation" or any(
            name in evaluator for name in ("accepted_plan_object", "authorization_object", "test_object")):
        raise ValueError("exploratory_host_cannot_receive_holdout_authorization")
    if not isinstance(uploads, list): raise ValueError("actual_versioned_upload_inventory_required")
    def reference(key, sha):
        matches = [item for item in uploads if item.get("key") == key and item.get("sha256") == sha]
        if len(matches) != 1: raise ValueError("unique_exact_uploaded_group_input_required")
        result = {name: matches[0][name] for name in ("bucket", "key", "version_id", "sha256")}
        validate_pinned_reference(result, expected_owner=owner)
        if result["bucket"] != bucket: raise ValueError("group_input_bucket_rebound")
        return result
    public_refs = {kind: reference(docs[kind + "_key"], hashlib.sha256(document_bytes(docs[kind])).hexdigest())
        for kind in ("campaign", "policy", "model")}
    result = deepcopy(runtime_input); private = deepcopy(role_configs)
    clients = result.get("clients", [])
    if len(clients) != 8 or {client.get("org_id") for client in clients} != set(ORGANIZATIONS):
        raise ValueError("eight_distinct_scoped_client_roles_required")
    expected_case = next(case for case in registry["cases"] if case["case_id"] == group["cases"][0]["cell_id"])
    shared = expected_case["shared_config"]
    for client in clients:
        org = client["org_id"]
        for label, key, sha in (("partition", f"partitions/{group['distribution']}/{org}/train.csv", group["partition_hashes"][org]),
                ("preprocessor", f"partitions/{group['distribution']}/{org}/preprocessor.json", shared["preprocessor_sha256"])):
            ref = reference(key, sha)
            client[label] = {field: ref[field] for field in ("key", "version_id", "sha256")}
        client["registered_node_id"] = None
    validation = reference("evaluation/frozen/validation.csv", shared["validation_sha256"])
    private["coordinator"].update(campaign_id=docs["application_campaign_id"], campaign_object=public_refs["campaign"],
        task_deadline_seconds=docs["campaign"]["task_deadline_seconds"])
    private["governance"].update(campaign_object=public_refs["policy"])
    private["evaluation"].update(dataset_role="validation", model_metadata=docs["model"], validation_object=validation,
        max_examples=group["evaluation_override"]["max_examples"])
    for name in ("cases", "plan_digest"):
        private["coordinator"].pop(name, None)  # The exact protected public object supplies these.
    result.update(distribution=group["distribution"], images={"client": image, "coordinator": image}, validation_reports=deepcopy(validation_reports))
    for service in result["services"].values(): service["image"] = image
    result["model_metadata_object"] = {key: public_refs["model"][key] for key in ("key", "version_id", "sha256")}
    result["evaluation_objects"]["validation"] = {key: validation[key] for key in ("key", "version_id", "sha256")}
    return {"runtime_input": result, "private_role_configs": private, "application_campaign_id": docs["application_campaign_id"],
        "execution_authorized": False, "actual_aws_calls": False,
        "requires": ["fresh validation of adapter image/source and standard renderer", "separate stopped-old-fleet/new-eight-client-generation",
                     "role-private secret payload update by authorized operator", "bounded remaining cost approval"]}
