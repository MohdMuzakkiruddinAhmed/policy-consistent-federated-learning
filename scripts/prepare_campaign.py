"""Prepare private, reviewable cloud inputs without calling AWS or unlocking test evaluation."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from pcfl.contracts import ORGANIZATIONS
from pcfl.evaluation import build_model_metadata
from pcfl.opa import policy_hash
from pcfl.service_io import service_identities
from run_flower import create_identity_files


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value, *, json_content=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n" if json_content else value
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(body)
    return str(path.resolve())


def binding(path):
    return {"path": str(Path(path).resolve()), "sha256": sha(path)}


def retained_report(path, directory):
    """Keep the exact validation report used by a deployment, despite later reruns."""
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    destination = Path(directory) / "v" / (digest[:16] + ".json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != raw:
            raise ValueError("validation_report_archive_collision")
    else:
        with destination.open("xb") as stream:
            stream.write(raw)
    return {"path": str(destination.resolve()), "sha256": digest}


def initial_request(directory=None, *, deployment_hours=12, campaign_authorization=None):
    approval_path = Path(campaign_authorization) if campaign_authorization else ROOT / "configs/aws_campaign_authorization.json"
    approval = json.loads(approval_path.read_text())
    amended = approval.get("kind") == "campaign-authorization-amendment"
    if amended:
        from campaign_budget import validate_amendment, bound
        stub = {"account_id": approval["account_id"], "region": approval["region"], "authorization": binding(approval_path)}
        validate_amendment(stub, approval, root=ROOT)
        quote = bound(ROOT, {"path": approval["proposal_path"], "sha256": approval["proposal_sha256"]})
    from campaign_budget import assert_authorization_not_retired
    assert_authorization_not_retired({"account_id": approval["account_id"], "region": approval["region"],
        "authorization": binding(approval_path)}, root=ROOT)
    total = approval["approved_total_usd"] if amended else 20
    estimate = quote["estimated_bounded_total_usd"] if amended else 15.2728
    if type(deployment_hours) is not int or not 1 <= deployment_hours <= 24:
        raise ValueError("deployment_expiry_must_be_within_authorized_twenty_four_hours")
    if not amended and (not approval.get("approved") or approval["approved_total_usd"] != 20):
        raise ValueError("approved_new_campaign_budget_required")
    suffix = uuid.uuid4().hex[:6]
    campaign_id = "campaign-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + suffix
    directory = Path(directory) if directory else ROOT / "results/aws" / campaign_id
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    project = "pcfl-r2-" + suffix
    foundation = {"expected_account_id": approval["account_id"], "aws_region": approval["region"], "project_id": project,
        "resource_creation_enabled": False, "budget_usd": total, "budget_time_unit": "MONTHLY", "log_retention_days": 7,
        "state_deletion_protection": False}
    namespace = "pcfl-" + suffix + ".internal"
    secret_names = ["root-ca", "flower-server-cert", "flower-server-key", "coordinator-config", "governance-config",
                    "opa-config", "evaluation-config", "operator-config", *["node-" + org for org in ORGANIZATIONS]]
    runtime = {"expected_account_id": approval["account_id"], "aws_region": approval["region"], "project_id": project,
        "resource_creation_enabled": False, "namespace": namespace,
        "private_subnets": {approval["region"] + "a": "10.73.1.0/24"},
        "hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=deployment_hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "budget": {"approved_total_usd": total, "estimated_total_usd": estimate,
            "authorization_scope": approval["authorization_scope"], "maximum_runtime_minutes": deployment_hours * 60},
        "secret_names": secret_names, "service_desired_counts": {name: 0 for name in ("coordinator", "governance", "opa", "evaluation")}}
    foundation_path = write(directory / "foundation-vars.json", foundation)
    runtime_path = write(directory / "runtime-vars.json", runtime)
    data = ROOT / "data/processed/uci296-v0.1.0-seed296"
    manifest = json.loads((ROOT / "data_manifests/dataset.json").read_text())
    frozen = manifest["private_artifacts_sha256"]
    uploads = []
    def add(relative, key, kind):
        source = data / relative
        if sha(source) != frozen[relative]:
            raise ValueError("frozen_dataset_artifact_mismatch")
        uploads.append({"source_path": str(source), "key": key, "sha256": frozen[relative], "kind": kind})
    for distribution in ("iid", "non_iid"):
        for org in ORGANIZATIONS:
            add(f"{distribution}/{org}.csv", f"partitions/{distribution}/{org}/train.csv", "partition")
            add("preprocessor.json", f"partitions/{distribution}/{org}/preprocessor.json", "preprocessor")
    for split in ("validation", "test"):
        add(split + ".csv", f"evaluation/frozen/{split}.csv", split)
    # These files are hashed/copied only. Final evaluation remains disabled;
    # only the evaluator's eventual separately accepted test mode may open rows.
    request = {"schema_version": "0.1.0", "account_id": approval["account_id"], "region": approval["region"],
        "project_id": project, "campaign_id": campaign_id, "namespace": namespace, "authorization": binding(approval_path),
        "foundation_vars": foundation_path, "runtime_vars": runtime_path, "local_image_tag": "pcfl-runtime:0.1.0",
        "source_reports": {"infrastructure": retained_report(ROOT / "reports/runtime_infrastructure_validation.json", directory),
            "container": retained_report(ROOT / "containers/build_validation.json", directory),
            "services": retained_report(ROOT / "reports/service_container_validation.json", directory)},
        "data_uploads": uploads, "secrets": [], "preparation_stage": "connectivity-pilot-inputs-only",
        "final_test_evaluation_permitted": False}
    if amended:
        request["campaign_budget_kind"] = "campaign-authorization-amendment"
    request_path = write(directory / "request.json", request)
    write(ROOT / "results/aws/latest-campaign.json", {"request": request_path})
    return request_path


def refresh_reports(request_path):
    request = json.loads(Path(request_path).read_text())
    for name, path in (("infrastructure", ROOT / "reports/runtime_infrastructure_validation.json"),
                       ("container", ROOT / "containers/build_validation.json"),
                       ("services", ROOT / "reports/service_container_validation.json")):
        report = json.loads(path.read_text())
        if report.get("successful") is not True:
            raise ValueError("successful_current_source_report_required")
        request["source_reports"][name] = retained_report(path, Path(request_path).parent)
    write(request_path, request)


def runtime_cases(request, foundation, contract, metadata, references, *, distribution, stage, plan=None, authorization=None):
    """Translate a pilot or accepted registered cells without opening any rows."""
    from pcfl.experiments import validate_plan
    from pcfl.holdout import validate_authorization
    accepted = stage in {"primary", "targeted", "ablation", "replication"}
    if accepted:
        validate_plan(plan)
        if plan["status"] != "accepted_frozen" or not plan["confirmatory_execution_enabled"]:
            raise ValueError("accepted_plan_required_before_registered_execution")
        cells = [cell for cell in plan[stage + "_cells"] if cell["distribution"] == distribution]
        if stage == "primary":
            # A prespecified Latin rotation balances method position over the
            # forty matched blocks while the append-only global history grows.
            method_order = ["B1", "B2", "B3", "P1"]
            seed_order = plan["configuration"]["seeds"]
            scenario_order = plan["configuration"]["primary_scenarios"]
            def execution_order(cell):
                scenario_index = scenario_order.index(cell["scenario_id"])
                seed_index = seed_order.index(cell["seed"])
                rotation = (seed_index + scenario_index + (distribution == "non_iid")) % 4
                return scenario_index, seed_index, (method_order.index(cell["baseline_id"]) - rotation) % 4
            cells.sort(key=execution_order)
        training = plan["training_candidate"]
        if authorization is not None and stage != "ablation":
            scope = validate_authorization(plan, authorization, model_schema_hash=metadata["model_schema_hash"])
        else:
            scope = None
    else:
        if stage not in {"connectivity", "training-pilot", "safety-pilot"}:
            raise ValueError("unknown_campaign_preparation_stage")
        training = json.loads((ROOT / ("configs/training.json" if stage == "connectivity" else "configs/experiments_training.json")).read_text())
        baselines = ["B1", "B2", "B3", "P1"] if stage == "training-pilot" else ["P1"]
        scenarios = {"connectivity": ["S0"], "training-pilot": ["S0", "S1", "S2", "S3"],
                     "safety-pilot": ["S4", "S5", "S6", "S7", "S8"]}[stage]
        cells = [{"cell_id": f"{stage}-{distribution}-{baseline}-{scenario}-296", "baseline_id": baseline,
                  "scenario_id": scenario, "seed": 296, "shared_config": {"policy_schedule": {"target_org": "org_01"}}, "variant": None}
                 for baseline in baselines for scenario in scenarios]
        if stage == "safety-pilot":
            # Seed593 selects the existing audit-transport S8 fault. Preserve
            # the original five seed296 cases and append this explicit pilot.
            cells.append({"cell_id": f"{stage}-{distribution}-P1-S8-593", "baseline_id": "P1",
                "scenario_id": "S8", "seed": 593, "shared_config": {"policy_schedule": {"target_org": "org_01"}}, "variant": None})
    cases = []
    application = request.get("application_campaign_id", request["campaign_id"])
    for cell in cells:
        baseline, scenario, seed, cell_id = (cell[name] for name in ("baseline_id", "scenario_id", "seed", "cell_id"))
        run_id = "run-" + hashlib.sha256((application + cell_id).encode()).hexdigest()[:24]
        runtime = {"authority_backend": "dynamodb-s3-opa" if baseline == "P1" else "dynamodb-s3-comparator",
            "baseline_id": baseline, "scenario_id": scenario, "scenario_control": True,
            "scenario_target_org": cell["shared_config"]["policy_schedule"]["target_org"],
            "persistent_run_id": run_id, "table_name": foundation["state_table_name"], "bucket": foundation["bucket_name"],
            "model_metadata": metadata, "training": training, "seed": seed, "distribution": distribution,
            "rounds": 1 if stage == "connectivity" else training["num_rounds"],
            "max_examples_per_client": 64 if stage == "connectivity" else training["max_examples_per_client"],
            "validation_max_examples": 128 if stage == "connectivity" else training["max_validation_examples"],
            "validation_source_sha256": references["evaluation/frozen/validation.csv"]["sha256"],
            "opa": {"endpoint": contract["service_endpoints"]["opa"], "expected_rule_hash": policy_hash()},
            "evaluator": {"endpoint": contract["service_endpoints"]["evaluation"]}, "message_timeout_seconds": 300}
        if cell.get("variant"):
            runtime.update(ablation_id=cell["variant"], authority_backend="dynamodb-s3-ablation")
        if scenario == "S8":
            runtime["scripted_fault"] = ("audit_transport_unavailable" if cell.get("variant") == "Abl-3" or seed in {593, 1181}
                                         else "opa_transport_unavailable")
        if scenario == "S7" or (stage == "training-pilot" and baseline == "P1" and scenario == "S0"):
            runtime["host_restart"] = {"request_id": "restart-" + hashlib.sha256((application + cell_id).encode()).hexdigest()[:24],
                "org_id": runtime["scenario_target_org"], "run_id": run_id,
                "phase": "between-rounds" if scenario == "S7" else "before-case",
                "round_id": "round-2" if scenario == "S7" else "initial"}
        if accepted:
            runtime.update(plan_digest=plan["plan_digest"], cell_id=cell_id, match_id=cell["match_id"],
                           equivalence_hash=cell["equivalence_hash"])
            runtime["experiment_binding"] = {"plan_digest": plan["plan_digest"], "cell_id": cell_id,
                "equivalence_hash": cell["equivalence_hash"], "family": cell["family"],
                "policy_schedule_hash": cell["shared_config"]["policy_schedule_hash"],
                "source_sha256": plan["provenance"]["source_sha256"]}
            # Unsafe ablations never open the clinical test holdout.
            if scope is not None and not cell.get("unsafe_comparator"):
                if scope.cell_for(run_id, "round-" + str(runtime["rounds"])) != cell_id:
                    raise ValueError("holdout_run_mapping_mismatch")
                runtime["final_holdout"] = {"plan_digest": plan["plan_digest"], "authorization_digest": authorization["authorization_digest"],
                    "test_sha256": authorization["test_sha256"], "cell_id": cell_id}
        cases.append({"cell_id": cell_id, "runtime": runtime,
                      **({key: runtime[key] for key in ("plan_digest", "match_id", "equivalence_hash", "distribution")} if accepted else {})})
    return cases


def prepare_runtime(request_path, *, distribution="iid", stage="connectivity", plan_path=None, authorization_path=None, attempt="1"):
    request_path = Path(request_path)
    request = json.loads(request_path.read_text())
    campaign_budget = {"approved_total_usd": 20, "estimated_total_usd": 15.2728,
        "authorization_scope": "remaining-phases-cloud-campaign-including-replication"}
    if request.get("campaign_budget_kind") == "campaign-authorization-amendment":
        from campaign_budget import bound as budget_bound, validate_amendment
        campaign_approval = budget_bound(ROOT, request["authorization"])
        validate_amendment(request, campaign_approval, root=ROOT)
        approved_quote = budget_bound(ROOT, {"path": campaign_approval["proposal_path"], "sha256": campaign_approval["proposal_sha256"]})
        campaign_budget.update(approved_total_usd=campaign_approval["approved_total_usd"],
            estimated_total_usd=approved_quote["estimated_bounded_total_usd"])
    proof_path = ROOT / "reports/container_campaign_validation.json"
    proof = json.loads(proof_path.read_text())
    if proof.get("successful") is not True:
        raise ValueError("current_private_container_campaign_validation_required")
    directory = request_path.parent
    if not attempt.isdecimal() or not 1 <= int(attempt) <= 999:
        raise ValueError("bounded_positive_attempt_required")
    application = (request["campaign_id"] if stage == "connectivity" and attempt == "1" else
                   request["campaign_id"] + "-" + stage + "-" + distribution + "-a" + attempt)
    request["application_campaign_id"] = application
    plan = json.loads(Path(plan_path).read_text()) if plan_path else None
    authorization = json.loads(Path(authorization_path).read_text()) if authorization_path else None
    inventory = json.loads((directory / "inventory.json").read_text())
    foundation, contract = inventory["foundation"], inventory["runtime_contract"]
    if foundation["bucket_name"].find(request["account_id"]) < 0 or contract["account_id"] != request["account_id"]:
        raise ValueError("actual_bootstrap_target_mismatch")
    references = {item["key"]: item for item in inventory["uploads"]}
    def object_ref(key):
        value = references[key]
        return {field: value[field] for field in ("bucket", "key", "version_id", "sha256")}
    identity_path = directory / "service-identities.json"
    if identity_path.exists():
        identity = json.loads(identity_path.read_text())
    else:
        namespace = request["namespace"]
        identity = service_identities(directory / "service-keys", additional_servers=("opa", "superlink"),
            dns_names={name: [name + "." + namespace] for name in ("governance", "evaluation", "opa", "superlink")})
        write(identity_path, identity)
    nodes_path = directory / "node-key-paths.json"
    if nodes_path.exists():
        nodes = json.loads(nodes_path.read_text())
    else:
        generated = create_identity_files(directory / "node-keys")
        nodes = {org: {name: str(value) for name, value in generated["nodes"][org].items() if name in {"private", "public"}}
                 for org in ORGANIZATIONS}
        write(nodes_path, nodes)
    read = lambda path: Path(path).read_text(encoding="utf-8")
    model_metadata = build_model_metadata(ROOT / "data/processed/uci296-v0.1.0-seed296/preprocessor.json")
    storage = {"region": request["region"], "expected_account_id": request["account_id"]}
    cases = runtime_cases(request, foundation, contract, model_metadata, references, distribution=distribution,
                          stage=stage, plan=plan, authorization=authorization)
    request["host_restarts"] = [case["runtime"]["host_restart"] for case in cases if "host_restart" in case["runtime"]]
    public = {"campaign_id": application, "cases": cases,
        "task_deadline_seconds": 3600 if stage == "connectivity" else 12*3600,
        "stop_on_failure": stage not in {"safety-pilot", "targeted", "ablation"},
        "dataset_manifest_sha256": sha(ROOT / "data_manifests/dataset.json")}
    if plan is not None:
        public["plan_digest"] = plan["plan_digest"]
    app_hash = hashlib.sha256(application.encode()).hexdigest()[:12]
    public_path = write(directory / (app_hash + "-campaign.json"), public)
    metadata_path = write(directory / "public-model-metadata.json", model_metadata)
    schedule = {"runs": [{"run_id": case["runtime"]["persistent_run_id"], "scenario_id": case["runtime"]["scenario_id"],
        "rounds": case["runtime"]["rounds"], "target_org": case["runtime"]["scenario_target_org"]} for case in cases]}
    schedule_path = write(directory / (app_hash + "-policies.json"), schedule)
    campaign_key = f"metadata/{application}/campaign.json" if application != request["campaign_id"] else f"metadata/{stage}-{distribution}-campaign.json"
    schedule_key = f"policies/{application}/campaign.json" if application != request["campaign_id"] else f"policies/{stage}-{distribution}-campaign.json"
    for path, key, kind in ((public_path, campaign_key, "campaign"),
                            (schedule_path, schedule_key, "policy_schedule"),
                            (metadata_path, "metadata/model.json", "model_metadata")):
        spec = {"source_path": path, "key": key, "sha256": sha(path), "kind": kind}
        request["data_uploads"] = [old for old in request["data_uploads"] if old["key"] != key] + [spec]
    accepted_keys = {}
    if authorization is not None and stage != "ablation":
        for path, label, semantic_digest in ((plan_path, "plan", plan["plan_digest"]),
                                            (authorization_path, "authorization", authorization["authorization_digest"])):
            key = f"evaluation/accepted/{semantic_digest}/{label}.json"
            accepted_keys[label] = key
            request["data_uploads"] = [old for old in request["data_uploads"] if old["key"] != key] + [
                {"source_path": str(Path(path).resolve()), "key": key, "sha256": sha(path), "kind": "accepted_" + label}]
    # The public campaign and schedule must be published before their exact
    # version references can be injected into role-private Secrets Manager data.
    needed = [campaign_key, schedule_key]
    expected_uploads = {needed[0]: public_path, needed[1]: schedule_path, "metadata/model.json": metadata_path}
    expected_uploads.update({key: plan_path if label == "plan" else authorization_path for label, key in accepted_keys.items()})
    if any(key not in references or references[key]["sha256"] != sha(path) for key, path in expected_uploads.items()):
        write(request_path, request)
        return {"publish_additional_inputs_required": True, "case_count": len(cases)}
    def server_tls(role):
        return {"ca_pem": read(identity["ca"]), "server_cert_pem": read(identity[role]["cert"]), "server_key_pem": read(identity[role]["key"])}
    private = {
        "root-ca": read(identity["ca"]), "flower-server-cert": read(identity["superlink"]["cert"]),
        "flower-server-key": read(identity["superlink"]["key"]),
        "coordinator-config": {"campaign_id": application, "storage": storage, "bucket": foundation["bucket_name"],
            "task_deadline_seconds": public["task_deadline_seconds"],
            "campaign_object": object_ref(needed[0]), "node_public_keys": {org: read(nodes[org]["public"]) for org in ORGANIZATIONS},
            "service_tls": {"ca_pem": read(identity["ca"]), "client_cert_pem": read(identity["coordinator"]["cert"]), "client_key_pem": read(identity["coordinator"]["key"])}},
        "governance-config": {"storage": storage, "table_name": foundation["state_table_name"], "tls": server_tls("governance"),
                              "campaign_object": object_ref(needed[1])},
        "opa-config": {"rule_hash": policy_hash(), "tls": server_tls("opa")},
        "evaluation-config": {"storage": storage, "table_name": foundation["state_table_name"], "bucket": foundation["bucket_name"],
            "model_metadata": model_metadata, "validation_object": object_ref("evaluation/frozen/validation.csv"),
            "max_examples": 128 if stage == "connectivity" else 100000, "tls": server_tls("evaluation"), "dataset_role": "validation"},
        "operator-config": {"operation": "probe-access", "placeholder": "probe overrides supply actual role-bound nonsecret inputs"},
        **{"node-" + org: read(nodes[org]["private"]) for org in ORGANIZATIONS}}
    if accepted_keys:
        private["evaluation-config"].update(dataset_role="test", accepted_plan_object=object_ref(accepted_keys["plan"]),
            authorization_object=object_ref(accepted_keys["authorization"]), test_object=object_ref("evaluation/frozen/test.csv"))
        request["final_test_evaluation_permitted"] = True
    else:
        request["final_test_evaluation_permitted"] = False
    request["secrets"] = []
    for name, value in private.items():
        path = write(directory / "secret-payloads" / (name + ".json"), value, json_content=isinstance(value, dict))
        request["secrets"].append({"logical_name": name, "payload_path": path})
    secrets = contract["secret_arns"]
    image = inventory["image"]["reference"]
    input_config = {"project_id": request["project_id"], "account_id": request["account_id"], "region": request["region"],
        "budget": campaign_budget,
        "superlink_hostname": "superlink." + request["namespace"], "governance_endpoint": contract["service_endpoints"]["governance"],
        "opa_endpoint": contract["service_endpoints"]["opa"], "evaluation_endpoint": contract["service_endpoints"]["evaluation"],
        "network": {"subnet_ids": contract["subnet_ids"], "security_group_ids": contract["security_group_ids"]},
        "images": {"client": image, "coordinator": image}, "distribution": distribution,
        "registration_mode": "coordinator-supervisor", "root_ca_secret_arn": secrets["root-ca"],
        "coordinator_secrets": {"PCFL_SERVER_CERT_PEM": secrets["flower-server-cert"], "PCFL_SERVER_KEY_PEM": secrets["flower-server-key"],
                                "PCFL_RUNTIME_CONFIG_JSON": secrets["coordinator-config"]},
        "clients": [{"org_id": org, "partition": {key: object_ref(f"partitions/{distribution}/{org}/train.csv")[key] for key in ("key", "version_id", "sha256")},
            "preprocessor": {key: object_ref(f"partitions/{distribution}/{org}/preprocessor.json")[key] for key in ("key", "version_id", "sha256")},
            "auth_secret_arn": secrets["node-" + org], "registered_node_id": None,
            "public_key_sha256": hashlib.sha256(Path(nodes[org]["public"]).read_bytes()).hexdigest()} for org in ORGANIZATIONS],
        "evaluation_objects": {split: {key: object_ref(f"evaluation/frozen/{split}.csv")[key] for key in ("key", "version_id", "sha256")}
                               for split in ("validation", "test")},
        "model_metadata_object": {key: object_ref("metadata/model.json")[key] for key in ("key", "version_id", "sha256")},
        "services": {name: {"image": image, "secrets": {"PCFL_" + name.upper() + "_CONFIG_JSON": secrets[name + "-config"]}}
                     for name in ("governance", "opa", "evaluation")},
        "validation_reports": {name: request["source_reports"][name] for name in ("infrastructure", "container")}}
    from probe_anchor import select_target
    target = select_target(inventory, directory)
    if target is not None:
        input_config["protected_anchor_object"] = target
    # Boolean statements alone do not satisfy the renderer: it separately hashes
    # current validated source artifacts and validates the actual inventory.
    sys.path.insert(0, str(ROOT / "infra/runtime"))
    from generate import build_plan
    preliminary = build_plan(input_config, {**foundation, "service_task_role_arns": {**foundation["service_task_role_arns"], **contract["task_role_arns"]}})
    input_config["readiness"] = {name: True for name in preliminary["required_readiness_checks"]}
    request["runtime_input"] = write(directory / "runtime-input.json", input_config)
    request["preparation_stage"] = stage + "-" + distribution
    write(request_path, request)
    return {"private_inputs_prepared": True, "case_count": len(cases),
            "application_campaign_id": application, "final_test_evaluation_permitted": bool(accepted_keys)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "refresh-reports", "runtime"))
    parser.add_argument("--request")
    parser.add_argument("--distribution", choices=("iid", "non_iid"), default="iid")
    parser.add_argument("--stage", choices=("connectivity", "training-pilot", "safety-pilot", "primary", "targeted", "ablation", "replication"), default="connectivity")
    parser.add_argument("--plan", help="Accepted, hash-bound registered plan for post-P8 trials")
    parser.add_argument("--holdout-authorization", help="Separate accepted final-holdout authorization")
    parser.add_argument("--attempt", default="1")
    parser.add_argument("--deployment-hours", type=int, default=12)
    parser.add_argument("--authorization", help="Explicit approved campaign authorization; legacy default is unchanged")
    args = parser.parse_args()
    if args.action == "init":
        print(json.dumps({"request": initial_request(deployment_hours=args.deployment_hours, campaign_authorization=args.authorization)}, indent=2))
    elif args.action == "refresh-reports":
        refresh_reports(args.request)
        print(json.dumps({"bound_reports_refreshed": True}))
    else:
        print(json.dumps(prepare_runtime(args.request, distribution=args.distribution, stage=args.stage, plan_path=args.plan,
                                        authorization_path=args.holdout_authorization, attempt=args.attempt), indent=2))


if __name__ == "__main__":
    main()
