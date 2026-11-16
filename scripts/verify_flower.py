"""Independently verify localhost pilot results and retain all launch attempts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.runtime_verify import verify_case


def digest_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_manifest(path, *, allow_partial=False):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if (manifest.get("successful") is not True and not allow_partial) or manifest.get("all_launched_parents_stopped") is not True:
        raise ValueError("completed_and_stopped_launch_required")
    registry = manifest["node_registry"]
    if len(registry) != 8 or set(registry.values()) != {f"org_{i:02d}" for i in range(1, 9)}:
        raise ValueError("eight_unique_registered_organizations_required")
    if not all(manifest["security_checks"].get(key) is True for key in (
            "trusted_ca_tls_handshake", "unknown_ca_rejected", "unregistered_node_rejected")):
        raise ValueError("transport_and_authentication_evidence_incomplete")
    clients = [record for record in manifest["processes"] if record["role"] in registry.values()]
    if len(clients) != 8 or len({record["pid"] for record in clients}) != 8:
        raise ValueError("independent_client_process_evidence_missing")
    app = path.parent / "app"
    for relative, expected in manifest["source_files_sha256"].items():
        source = (app / relative).resolve()
        if not source.is_relative_to(app.resolve()) or digest_file(source) != expected:
            raise ValueError("retained_app_source_digest_mismatch")
    cases = []
    for case in manifest["cases"]:
        if case.get("successful") is not True:
            continue
        result = (ROOT / case["result_file"]).resolve()
        if not result.is_relative_to(path.parent.resolve()) or digest_file(result) != case["result_sha256"]:
            raise ValueError("retained_result_digest_mismatch")
        summary = verify_case(result)
        evidence = json.loads(result.read_text(encoding="utf-8"))
        summary["sample_count_sum"] = sum(record["sample_count"] for record in evidence["updates"])
        summary["seed"] = evidence.get("seed")
        cases.append(summary)
    if not cases:
        raise ValueError("no_completed_cases_to_verify")
    stable = [case["model_digests"] for case in cases if case["scenario_id"] == "stable"]
    if len(stable) > 1 and any(value != stable[0] for value in stable[1:]):
        raise ValueError("matched_stable_models_differ_across_baselines")
    for case in cases:
        if case["baseline_id"] == "P1" and case["oracle_invalid_incorporations"]:
            raise ValueError("unsafe_proposed_protocol_pilot")
        if case["scenario_id"] == "mid_round" and case["baseline_id"] in {"B1", "B2", "B3"}:
            if case["oracle_invalid_incorporations"] < 1:
                raise ValueError("controlled_baseline_counterexample_not_observed")
    return {"run_id": manifest["run_id"], "manifest_file": path.relative_to(ROOT).as_posix(),
            "manifest_sha256": digest_file(path), "successful": manifest.get("successful") is True,
            "completed_cases_independently_verified": True,
            "security_checks": manifest["security_checks"], "cases": cases,
            "all_launched_parents_stopped": True,
            "all_launch_listeners_stopped": manifest.get("all_launch_listeners_stopped"),
            "aws_credentials_forwarded": manifest.get("aws_credentials_forwarded"),
            "pilot_configuration": manifest.get("pilot_configuration"),
            "retained_last_launch_config": json.loads((path.parent / "active.json").read_text(encoding="utf-8"))
                if (path.parent / "active.json").is_file() else None,
            "matched_stable_parameter_digests_identical": len(stable) > 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if args.all:
        paths = sorted((ROOT / "results/runtime").glob("*/run_manifest.json"))
    else:
        latest = json.loads((ROOT / "results/runtime/latest.json").read_text(encoding="utf-8"))
        paths = [Path(latest["run_manifest"])]
    report = {"schema_version": "0.1.0", "kind": "learning_runtime_pilot_validation",
              "checked_at_utc": datetime.now(timezone.utc).isoformat(), "successful_runs": [], "partial_runs": [], "failed_attempts": [],
              "is_confirmatory": False, "aws_resources_created": False,
              "limitations": ["One localhost trust boundary, not eight Fargate tasks",
                 "Training governance is local memory; DynamoDB/OPA integration is pending",
                 "Validation samples and one seed only; final test holdout not evaluated",
                 "Local retained anchors are not a hardened external trust service"]}
    for path in paths:
        config_path = path.parent / "active.json"
        if config_path.is_file() and json.loads(config_path.read_text(encoding="utf-8")).get("authority_backend") == "dynamodb-s3-opa":
            continue  # Persistent API pilots have their own stricter inventory.
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("successful") is not True:
            error = manifest.get("error", {})
            report["failed_attempts"].append({"run_id": manifest["run_id"], "error_type": error.get("type"),
                "reason": error.get("message", "").split("\n")[0][:200],
                "all_launched_parents_stopped": manifest.get("all_launched_parents_stopped"),
                "manifest_file": path.relative_to(ROOT).as_posix()})
            if any(case.get("successful") is True for case in manifest.get("cases", [])):
                report["partial_runs"].append(verify_manifest(path, allow_partial=True))
            continue
        report["successful_runs"].append(verify_manifest(path))
    report["successful"] = bool(report["successful_runs"])
    cleanup_path = ROOT / "results/runtime/cleanup.json"
    if cleanup_path.is_file():
        report["post_run_worker_cleanup"] = json.loads(cleanup_path.read_text(encoding="utf-8"))
    stable_groups = {}
    for run in report["successful_runs"] + report["partial_runs"]:
        for case in run["cases"]:
            if case["scenario_id"] == "stable":
                key = (case["seed"], case["sample_count_sum"], case["published_models"], case["validation_metrics"]["count"])
                stable_groups.setdefault(key, []).append(case)
    report["stable_comparisons"] = []
    for key, cases in stable_groups.items():
        if len(cases) <= 1:
            continue
        identical = all(case["model_digests"] == cases[0]["model_digests"] for case in cases)
        if not identical:
            raise ValueError("matched_stable_models_differ_across_launches")
        report["stable_comparisons"].append({"seed": key[0], "sample_count_sum": key[1], "rounds": key[2],
           "validation_examples": key[3], "baselines": [case["baseline_id"] for case in cases], "identical_parameter_digests": True})
    (ROOT / "reports/runtime_validation.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    lines = ["# Learning runtime pilot validation", "", "Generated by `scripts/verify_flower.py --all` from retained source, result and model artifacts.", "",
        "Flower 1.27.0 ran eight registered SuperNode processes plus a separate SuperLink over TLS on one Windows host. Unknown certificate authorities and an unregistered node key were rejected. This is local deployment-mode evidence; it does not establish eight Fargate tasks.", "",
        "Each completed case below passed independent interval-oracle assessment, complete final-outcome/audit checks, artifact digests and reconstruction of the published FedAvg model from retained client updates. Invalid incorporations are intentional comparator failures for B1/B2/B3.", "",
        "| Launch | Distribution | System | Scenario | Models | Accepted | Oracle-invalid presented | Invalid included |",
        "|---|---|---|---|---:|---:|---:|---:|"]
    for run in report["successful_runs"] + report["partial_runs"]:
        config = run["pilot_configuration"] or run["retained_last_launch_config"] or {}
        for case in run["cases"]:
            lines.append(f"| {run['run_id']} | {config.get('distribution', 'not recorded')} | {case['baseline_id']} | {case['scenario_id']} | {case['published_models']} | {case['accepted_updates']} | {case['oracle_invalid_presented']} | {case['oracle_invalid_incorporations']} |")
    lines += ["", "Counts use unique presented updates within each case. The main comparison uses seed 296, two rounds, up to 256 training examples per client and 512 validation examples. The initial one-round 64-example P1 check is retained separately. For the interrupted comparison launch, distribution/configuration comes from its retained final active configuration; per-case model and result evidence is individually checked.", "",
        "Stable B1/B2/B3/P1 comparisons with matched seed, sample budget, round count and validation size produced identical parameter digests. These engineering checks are not confirmatory H1–H4 results or evidence of clinical utility. The final test holdout was not evaluated.", "", "## Failed attempts and limits", "",
        f"{len(report['failed_attempts'])} failed launch attempts are retained. An interrupted launch can contain independently verified completed cases; it remains a failed launch, and its unfinished/failed case is not counted as passed.", ""]
    for attempt in report["failed_attempts"]:
        reason = attempt["reason"].replace("`", "'")
        lines.append(f"- `{attempt['run_id']}`: {attempt['error_type']}; {reason}")
    lines += ["", "Startup debugging exposed Flower/Alembic installation-path handling, a SQLAlchemy 2.1 Windows URL incompatibility, SSH-versus-PKCS8 node-key format, and a shared application-cache install race. The tested launcher uses a short user-local environment, SQLAlchemy 2.0.48, OpenSSH node keys and separate node caches. Failed setup runs were stopped and preserved.", "",
        "The hardened launcher forwards only host execution essentials, removes account/API credentials from child environments, and checks listener shutdown after cleanup. Earlier diagnostic launches predate those extra fields; the machine-readable report distinguishes missing evidence from an observed false result.", "",
        "Training governance is an in-memory authority with local checkpoint publication. The earlier S3/DynamoDB smoke is a separate adapter test. Production DynamoDB/OPA integration, isolated evaluator access, hardened anchors, crash recovery and the Fargate deployment remain open. No AWS resource was created by these learning runs.", "",
        "Automatic policy review rejected cleanup of the two generated workspace virtual environments. They remain ignored; the active pinned environment is in the short user-local path.", ""]
    if "post_run_worker_cleanup" in report:
        cleanup = report["post_run_worker_cleanup"]
        lines += [f"Final worker inventory identified and stopped {len(cleanup['orphan_helper_pids_stopped'])} orphan helper trees from failed startup attempts by matching the generated executable and recorded pilot ports. Remaining runtime workers at final readback: {cleanup.get('remaining_runtime_workers', 'not recorded')}. The launcher includes this scoped helper cleanup for future failures.", ""]
    (ROOT / "reports/runtime_validation.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"successful_runs_verified": len(report["successful_runs"]),
                      "failed_launch_attempts_retained": len(report["failed_attempts"]),
                      "partial_launches_with_verified_cases": len(report["partial_runs"]),
                      "cases_verified": sum(len(run["cases"]) for run in report["successful_runs"] + report["partial_runs"])}, indent=2))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
