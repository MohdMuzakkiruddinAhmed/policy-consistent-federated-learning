"""Reverify retained cloud bytes and append aggregate attempts; no AWS or rows."""

import argparse
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from pcfl.experiments import (COUNT_METRICS, append_attempt, canonical, derive_verified_metrics,
    digest, file_digest, load_attempts, registered_runtime_matches, validate_plan)
from pcfl.runtime_verify import verify_case
from validate_cloud_placement import validate_placement
from verify_cloud_campaign import scoped_artifact_cache
from cloud_assessment import derive_partial_metrics, verify_retained_witness


def retained_export_scope(inventory_path, inventory):
    inventory_path = Path(inventory_path).resolve()
    export = inventory["export"]
    application = export.get("application_campaign_id", inventory.get("application_campaign_id", inventory["campaign_id"]))
    directory = Path(export.get("export_root", inventory_path.parent / "r")).resolve()
    if not directory.is_relative_to(inventory_path.parent):
        raise ValueError("ingestion_export_root_outside_owned_inventory")
    if (inventory.get("application_campaign_id", application) != application
            or export.get("index_key") != f"evidence/campaigns/{application}/campaign_result.json"
            or export.get("index_version_id") in {None, "", "null"}):
        raise ValueError("ingestion_export_application_or_version_mismatch")
    return application, directory


def concurrent_client_ids(placement):
    """Use one independently accepted concurrent snapshot, including S7 runs."""
    if placement.get("successful") is not True:
        return []
    snapshot = placement.get("source_snapshot") or {}
    orgs = {f"org_{number:02d}" for number in range(1, 9)}
    clients = [row for row in snapshot.get("tasks", []) if row.get("name") in orgs
               and row.get("effective_commands", {}).get(row["name"]) == ["client"]]
    ids = sorted({row["task_arn"] for row in clients})
    return ids if len(clients) == len(ids) == 8 and {row["name"] for row in clients} == orgs else []


def case_window(raw, index):
    """Legacy development records retain their explicitly broader time scope."""
    from datetime import datetime
    values = raw.get("case_started_at_utc"), raw.get("case_finished_at_utc")
    if all(value is None for value in values):
        return index["started_at_utc"], index["finished_at_utc"], "campaign-start-and-finish-not-per-case-duration"
    try:
        start, end = (datetime.fromisoformat(value.replace("Z", "+00:00")) for value in values)
        elapsed = raw["elapsed_seconds"]
        if (start.tzinfo is None or end.tzinfo is None or end <= start or type(elapsed) not in (int, float)
                or not math.isfinite(elapsed) or elapsed <= 0
                or abs((end-start).total_seconds()-elapsed) > max(1, elapsed*.001)):
            raise ValueError("invalid_case_usage_window")
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid_case_usage_window") from error
    return values[0], values[1], "coordinator-case-wall-window;monotonic-duration-crosschecked;usage-only"


def immutable_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = canonical(value) + b"\n"
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError("existing_ingestion_artifact_differs_use_versioned_output")
    else:
        with path.open("xb") as stream:
            stream.write(content)


def ingest_cloud(plan, inventory_path, campaign_path, ledger, output, *, authorization=None,
                 witness_public_key=None, witness_public_key_sha256=None):
    if (witness_public_key is None) != (witness_public_key_sha256 is None):
        raise ValueError("external_operator_public_key_and_pin_required_together")
    validate_plan(plan)
    inventory_path, output = Path(inventory_path).resolve(), Path(output).resolve()
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    campaign = json.loads(Path(campaign_path).read_text(encoding="utf-8"))
    application, export_root = retained_export_scope(inventory_path, inventory)
    index_path = export_root / "campaign_result.json"
    if file_digest(index_path) != inventory["export"]["index_sha256"]:
        raise ValueError("retained_campaign_index_digest_mismatch")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index["campaign_id"] != application or campaign["campaign_id"] != application:
        raise ValueError("campaign_identity_mismatch")
    prepared = {case["cell_id"]: case["runtime"] for case in campaign["cases"]}
    if len(prepared) != len(campaign["cases"]) or len({case["cell_id"] for case in index["cases"]}) != len(index["cases"]):
        raise ValueError("duplicate_cloud_case_identity")
    placement = validate_placement(deepcopy(inventory), export_root=export_root)
    # The timestamp is an observation of this ingestion, not a scientific input.
    placement.pop("checked_at_utc", None)
    immutable_json(output / "placement.json", placement)
    cells = {cell["cell_id"]: cell for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells") for cell in plan[family]}
    definitions = inventory.get("runtime_contract", {}).get("task_definition_arns", {})
    client_ids = concurrent_client_ids(placement)
    existing = {row["attempt_id"]: row for row in load_attempts(ledger, plan)}
    observations = []
    for case in index["cases"]:
        cell_id = case["cell_id"]
        if cell_id not in prepared:
            raise ValueError("export_not_in_prepared_campaign")
        runtime = prepared[cell_id]
        directory = index_path.parent / hashlib.sha256(cell_id.encode()).hexdigest()[:8]
        if json.loads((directory / "cell.json").read_text()) != {"cell_id": cell_id}:
            raise ValueError("retained_case_directory_binding_mismatch")
        raw_path = directory / "runtime_result.json"
        raw_sha = file_digest(raw_path)
        refs = [ref for ref in case["artifacts"] if ref["key"] == f"evidence/campaigns/{application}/{cell_id}/runtime_result.json"]
        integrity = (len(refs) == 1 and refs[0]["sha256"] == raw_sha and refs[0]["size_bytes"] == raw_path.stat().st_size
                     and refs[0]["bucket"] == inventory["foundation"]["bucket_name"] and refs[0].get("version_id") not in {None, "", "null"})
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        try:
            started_at, finished_at, time_scope = case_window(raw, index)
        except ValueError:
            started_at, finished_at, time_scope = index["started_at_utc"], index["finished_at_utc"], "invalid-case-window"
        reasons, summary, metrics, sources = [], None, {}, {}
        is_partial = "ablation_id" in raw or raw.get("full_protocol", True) is not True or raw.get("successful") is not True
        protection, partial_qualified = {"protected_witness_verified": False}, False
        if not integrity:
            reasons.append("raw-result-integrity-failed")
        else:
            try:
                witness, public = None, None
                if witness_public_key is not None:
                    witness, public, protection = verify_retained_witness(inventory, application=application, cell_id=cell_id,
                        raw_path=raw_path, public_key_path=witness_public_key, public_key_pin=witness_public_key_sha256)
                with scoped_artifact_cache(directory):
                    if is_partial:
                        if witness is None:
                            raise ValueError("externally_pinned_partial_assessment_required")
                        from pcfl.ablation_verify import assess_case
                        summary = assess_case(raw_path, witness=witness, public_key_pem=public,
                            expected_public_key_sha256=witness_public_key_sha256)
                        metrics, sources, timing = derive_partial_metrics(raw, summary)
                        summary.update(timing)
                    else:
                        test_context = {"accepted_plan": plan, "authorization": authorization} if authorization is not None and raw.get("test_holdout_evaluated") is True else None
                        summary = verify_case(raw_path, expect_test_authorization=test_context)
                        metrics, sources = derive_verified_metrics(raw, summary)
                        if protection["protected_witness_verified"] is not True:
                            metrics["audit_record_sets_verified"] = 0
                            sources["audit_record_sets_verified"] = "local-chain-checked;external-protected-operator-witness-unverified"
            except (ValueError, KeyError, TypeError, OSError) as error:
                reasons.append("verifier-source-version-mismatch" if str(error) == "pinned_policy_rule_hash_mismatch" else "independent-verification-failed")
                verification_error = {"type": type(error).__name__, "code": str(error)[:256]}
        if raw.get("successful") is not True or case.get("successful") is not True:
            reasons.append("runtime-reported-failure")
        registered = cell_id in cells
        if not registered:
            reasons.append("development-not-registered")
        elif not registered_runtime_matches(plan, cells[cell_id], runtime, raw, inventory):
            reasons.append("scientific-runtime-binding-mismatch")
        if is_partial and summary is not None:
            cell = cells.get(cell_id, {})
            partial_qualified = (cell.get("family") == "ablation" and cell.get("variant") in {"Abl-1", "Abl-2", "Abl-3", "Abl-4"}
                and raw.get("ablation_id") == runtime.get("ablation_id") == cell["variant"]
                and raw.get("full_protocol") is False and runtime.get("full_protocol") is False
                and runtime.get("authority_backend") == "dynamodb-s3-ablation" and runtime.get("baseline_id") == "P1"
                and runtime.get("experiment_binding", {}).get("family") == "ablation"
                and summary.get("full_protocol_pass") is False and summary.get("protected_witness_verified") is True
                and summary.get("attempt_accounting_complete") is True and summary.get("indeterminate_count") == 0
                and summary.get("committed_validation_response_verified") is True
                and summary.get("runtime_observations_verified") is True and not summary.get("partial_metric_errors"))
            if raw.get("successful") is True and not partial_qualified:
                reasons.append("partial-evidence-not-qualified-registered-ablation")
        if protection["protected_witness_verified"] is not True:
            reasons.append("external-protected-operator-witness-unverified")
        if time_scope == "invalid-case-window" or (registered and time_scope.startswith("campaign-start")):
            reasons.append("per-case-usage-window-invalid-or-missing")
        if registered and plan["status"] != "accepted_frozen":
            reasons.append("scientific-plan-not-accepted")
        if registered and (summary is None or summary.get("runtime_observations_verified") is not True):
            reasons.append("runtime-timing-observations-unverified")
        if placement.get("successful") is not True:
            reasons.append("actual-fargate-placement-unverified")
        missing = sorted(COUNT_METRICS - set(metrics))
        if missing:
            reasons.append("required-instrumentation-missing")
        # A replay/tool/source mismatch is not an observed execution failure.
        # Only the retained execution/index outcome can establish that status.
        failed = "runtime-reported-failure" in reasons
        status = "failed" if failed else "excluded" if reasons else "successful"
        attempt_id = "cloud-" + digest([inventory["campaign_id"], application, cell_id, raw_sha, inventory["export"]["index_sha256"]])[:32]
        assessment = {"kind": "verified-cloud-attempt-ingestion", "successful": summary is not None and integrity,
            "verification_scope": "independent-partial-protocol" if is_partial else "independent-full-baseline-protocol",
            "full_protocol_pass": False if is_partial else None, "partial_qualified": partial_qualified,
            "protected_operator_witness": protection,
            "attempt_id": attempt_id, "source_cell_id": cell_id, "raw_result_sha256": raw_sha,
            "summary": summary, "status": status, "exclusion_reasons": reasons, "missing_required_metrics": missing,
            "execution_reported_success": raw.get("successful") is True and case.get("successful") is True,
            "measurement_sources": sources, "measurement_missing": sorted({"cost_usd", "resources", "revocation_response"} - set(metrics)),
            "time_window_scope": time_scope,
            "original_result_bytes_preserved": True, "test_rows_read": False}
        if any(reason in reasons for reason in ("independent-verification-failed", "verifier-source-version-mismatch")):
            assessment["verification_error"] = verification_error
        report_path = output / (attempt_id + ".json")
        immutable_json(report_path, assessment)
        evidence = {"raw_result_sha256": raw_sha, "ingestion_report_sha256": file_digest(report_path), "topology_report_sha256": file_digest(output / "placement.json")}
        if summary is not None:
            evidence.update(oracle_report_sha256=file_digest(report_path), audit_report_sha256=file_digest(report_path))
        row = {"attempt_id": attempt_id, "cell_id": cell_id, "plan_digest": plan["plan_digest"],
            "equivalence_hash": cells[cell_id]["equivalence_hash"] if registered else None,
            "status": status, "reason_code": reasons[0] if reasons else "partial-qualified-ablation" if is_partial else "independently-verified",
            "started_at_utc": started_at, "finished_at_utc": finished_at, "metrics": metrics,
            "evidence": evidence, "execution": {"deployment_id": inventory["campaign_id"],
                "task_definition_digest": digest(definitions), "client_task_ids": client_ids[:8],
                "eight_separate_fargate_clients": placement.get("successful") is True and len(client_ids) == 8,
                "final_holdout_authorized": summary is not None and summary.get("final_holdout_authorization_verified") is True},
            "observation": {"scope": "registered" if registered else "development", "baseline_id": runtime["baseline_id"],
                "source_cell_id": cell_id, "missing_metrics": missing, "exclusion_reasons": reasons, "measurement_sources": sources}}
        if runtime.get("persistent_run_id"):
            row["execution"]["namespace"] = runtime["persistent_run_id"]
        if row["attempt_id"] in existing:
            if existing[row["attempt_id"]] != row:
                raise ValueError("previously_ingested_attempt_changed")
        else:
            append_attempt(ledger, plan, row)
        observations.append({"attempt_id": attempt_id, "source_cell_id": cell_id, "status": status, "exclusion_reasons": reasons})
        if file_digest(raw_path) != raw_sha:
            raise ValueError("ingestion_modified_original_result")
    report = {"successful": True, "kind": "cloud-registry-ingestion", "plan_digest": plan["plan_digest"],
        "campaign_id": inventory["campaign_id"], "application_campaign_id": application, "observations": observations, "aws_calls": False, "test_rows_read": False}
    immutable_json(output / "ingestion.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("plan", "inventory", "campaign", "ledger", "output"):
        parser.add_argument("--" + argument, required=True)
    parser.add_argument("--authorization", help="Explicit separately retained final-holdout authorization JSON")
    parser.add_argument("--witness-public-key", help="External operator public PEM; never inferred from the retained witness")
    parser.add_argument("--witness-public-key-sha256", help="Trusted external DER public-key fingerprint")
    args = parser.parse_args()
    authorization = json.loads(Path(args.authorization).read_text()) if args.authorization else None
    report = ingest_cloud(json.loads(Path(args.plan).read_text()), args.inventory, args.campaign, args.ledger, args.output,
        authorization=authorization, witness_public_key=args.witness_public_key, witness_public_key_sha256=args.witness_public_key_sha256)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
