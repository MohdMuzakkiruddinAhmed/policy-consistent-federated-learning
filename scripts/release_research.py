"""Create an aggregate reproducibility bundle; never copy clinical rows or keys."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pcfl.analysis import analyze_registry, write_analysis
from pcfl.experiments import canonical, digest, file_digest, load_attempts
from finalize_research import accurate_scope, finalize, scoped_file
from public_release import public_attachments, private_catalog, reproduction_script

PUBLIC_SUPPLEMENTS = ("README.md", "plan.md", "theoretical.md", "LICENSE",
    "configs/experiments.json", "configs/experiments_training.json", "configs/research_scope.json",
    "data_manifests/dataset.json", "docs/analysis_protocol.md", "docs/experiment_protocol.md",
    "docs/public_release_integrity.md", "docs/finalization_protocol.md", "docs/reproducibility.md", "docs/cloud_campaign_runbook.md", "docs/cloud_cost_reconciliation.md",
    "docs/runtime_deployment.md", "docs/architecture.md", "docs/protocol_spec.md", "docs/threat_model.md", "spec/invariants.md",
    "docs/scope_ethics.md", "docs/study_charter.md", "docs/literature_review.md", "docs/literature_matrix.csv", "reports/manuscript.md")


def source_archive(plan, output, version, *, root=ROOT):
    expected = plan["provenance"]["source_files_sha256"]
    if not expected or digest(expected) != plan["provenance"]["source_sha256"]:
        raise ValueError("complete_frozen_source_inventory_required")
    files = {}
    roots = {"src", "scripts", "tests", "policies", "schemas", "infra", "containers"}
    root_files = {"pyproject.toml", "requirements.lock", "requirements-runtime.lock", "requirements-analysis.in", "requirements-analysis.lock"}
    allowed_suffixes = {".py", ".rego", ".json", ".tf", ".hcl", ".lock", ".toml", ".in"}
    for name, sha in expected.items():
        if Path(name).as_posix() != name:
            raise ValueError("canonical_public_source_path_required")
        path = scoped_file(Path(root), name)
        relative = Path(name)
        if ((relative.parts[0] not in roots and name not in root_files)
                or (relative.suffix not in allowed_suffixes and name != "containers/Dockerfile")
                or name.endswith(".tfvars.json")
                or {".terraform", "__pycache__", "results", "data", "secrets", "secret-payloads"} & set(relative.parts)):
            raise ValueError("frozen_inventory_contains_nonpublic_source_path")
        if file_digest(path) != sha:
            raise ValueError("frozen_source_changed_before_release")
        files[name] = sha
    for name in PUBLIC_SUPPLEMENTS:
        if (Path(root) / name).is_file():
            files[name] = file_digest(scoped_file(Path(root), name))
    archive = Path(output) / ("source-" + version + ".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name in sorted(files):
            body = scoped_file(Path(root), name).read_bytes()
            if (hashlib.sha256(body).hexdigest() != files[name]
                    or re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{32,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body)
                    or re.search(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", body)):
                raise ValueError("source_changed_or_literal_private_material_detected")
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type, entry.external_attr = zipfile.ZIP_DEFLATED, 0o100644 << 16
            bundle.writestr(entry, body)
    with zipfile.ZipFile(archive) as bundle:
        if set(bundle.namelist()) != set(files) or any(hashlib.sha256(bundle.read(name)).hexdigest() != sha for name, sha in files.items()):
            raise ValueError("public_source_archive_verification_failed")
    manifest = {"artifact_version": version, "archive": archive.name, "archive_sha256": file_digest(archive),
        "files_sha256": files, "frozen_executable_files_sha256": expected,
        "raw_clinical_data_included": False, "private_model_arrays_included": False, "credentials_included": False}
    (Path(output) / "public_source_manifest.json").write_bytes(canonical(manifest) + b"\n")
    return manifest


def create_release(plan, attempts, output, *, artifact_version=None, phase_evidence=None, source_root=ROOT, attachments=None):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("release_output_must_be_new_or_empty")
    artifact_version = artifact_version or output.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", artifact_version):
        raise ValueError("explicit_valid_artifact_version_required")
    report = analyze_registry(plan, attempts)
    output.mkdir(parents=True, exist_ok=True)
    source = source_archive(plan, output, artifact_version, root=source_root)
    finalization, completion = None, False
    if phase_evidence is not None:
        try:
            supplied = json.loads(Path(phase_evidence).read_text(encoding="utf-8"))
            finalization = finalize(supplied.get("recipe", {}), plan, attempts, root=source_root)
            if supplied != finalization or supplied.get("artifact_version") != artifact_version:
                raise ValueError("phase_evidence_changed_or_rebound")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            finalization = {"kind": "rejected-stale-or-rebound-phase-evidence", "all_phases_complete": False,
                            "reason": "The supplied document does not equal current independently recomputed phase evidence"}
        completion = finalization["all_phases_complete"]
        (output / "phase_evidence.json").write_bytes(canonical(finalization) + b"\n")
    write_analysis(report, output)
    analysis_files = {name: file_digest(output / name) for name in
        ["analysis.json", "claim_evidence_matrix.csv", *(table + ".csv" for table in report["tables"])]}
    attachment_report = {"kind": "verified-reviewed-public-attachments", "successful": False,
        "reason": "Explicit reviewed detailed-report/figure attachment spec was not supplied"}
    if attachments is not None:
        if attachments.get("artifact_version") != artifact_version:
            raise ValueError("attachment_artifact_version_mismatch")
        attachment_report = public_attachments(attachments, plan, attempts, output, root=source_root)
    completion = completion and attachment_report["successful"]
    (output / "public_attachment_manifest.json").write_bytes(canonical(attachment_report) + b"\n")
    (output / "private_replay_catalog.json").write_bytes(canonical(private_catalog(plan, attempts)) + b"\n")
    (output / "locked_plan.json").write_bytes(canonical(plan) + b"\n")
    (output / "aggregate_attempts.json").write_bytes(canonical(attempts) + b"\n")
    (output / "reproduce.py").write_text(reproduction_script(), encoding="utf-8")
    scope_path = Path(source_root) / "configs/research_scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
    scope_text = ("The user identifies this as independent computational research with no institutional review requirement. "
        "This is a self-reported scope boundary; no institutional determination, IRB approval or exemption is issued or claimed."
        if accurate_scope(scope) else "The supplied scope record does not establish an administrative determination; no IRB approval or exemption is claimed.")
    lines = ["# Research evidence status", "", f"Artifact version: `{artifact_version}`. All phases complete: `{str(completion).lower()}`.", "",
             "Completion joins the separately referenced phase/gate evidence with actual teardown; hypothesis support is reported independently.", "",
             f"Plan status: `{plan['status']}`. Primary matrix complete: `{report['primary_matrix_complete']}`.", "",
             "| Hypothesis | Verdict |", "|---|---|"]
    lines += [f"| {key} | {value['verdict']} |" for key, value in report["hypotheses"].items()]
    lines += ["", "No clinical records, patient identifiers, model-update arrays, credentials, or private keys are copied.",
              "All attempted/failed/aborted/excluded runs are retained in the aggregate ledger. Missing measurements remain missing.",
              "Phase criteria, actual cloud gates and teardown are linked in phase_evidence.json when supplied.",
              "Detailed public reporting/figures require an explicit reviewed attachment spec; missing attachments keep completion false.",
              "Public reproduction verifies source and aggregate statistics. Separate private model/audit replay is described in private_replay_catalog.json.",
              "No human recruitment, annotation, graders, interviews, surveys or evaluation participants were used by this automation.",
              scope_text, ""]
    if finalization and finalization.get("qualifications"):
        lines += ["Qualified limitations:", ""] + ["- " + code + "." for code in sorted(finalization["qualifications"])] + [""]
    if finalization and finalization.get("phases"):
        lines += ["| Phase/gate | Derived status |", "|---|---|"]
        lines += [f"| {name} | {value['status']} |" for group in (finalization["phases"], finalization["gates"]) for name, value in group.items()]
        lines += [""]
    (output / "final_validation.md").write_text("\n".join(lines), encoding="utf-8")
    inventory = {path.relative_to(output).as_posix(): file_digest(path) for path in sorted(output.rglob("*")) if path.is_file()}
    manifest = {"schema_version": "0.1.0", "kind": "aggregate-research-reproduction-bundle",
        "artifact_version": artifact_version, "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts),
        "source_sha256": plan["provenance"]["source_sha256"], "source_files_sha256": plan["provenance"]["source_files_sha256"],
        "image_digests": plan["provenance"]["image_digests"], "data_manifest_digest": plan["data_manifest_digest"],
        "schedule_hashes": sorted({cell["shared_config"]["policy_schedule_hash"] for cell in plan["primary_cells"]}),
        "files_sha256": inventory, "analysis_files_sha256": analysis_files, "public_source_archive": source["archive"],
        "public_attachments_complete": attachment_report["successful"], "private_replay_scope": "catalog-only; separate retained private verification required",
        "all_phases_complete": completion,
        "raw_clinical_data_included": False, "credentials_included": False,
        "confirmatory_verdict_permitted": report["confirmatory_verdict_permitted"]}
    (output / "release_manifest.json").write_bytes(canonical(manifest) + b"\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempts", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--phase-evidence", type=Path)
    parser.add_argument("--attachments", type=Path, help="Explicit reviewed public aggregate/figure attachment spec")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    manifest = create_release(plan, load_attempts(args.attempts, plan), args.output,
        artifact_version=args.artifact_version, phase_evidence=args.phase_evidence,
        attachments=json.loads(args.attachments.read_text(encoding="utf-8")) if args.attachments else None)
    print(json.dumps({"files": len(manifest["files_sha256"]), "all_phases_complete": manifest["all_phases_complete"],
                      "confirmatory_verdict_permitted": manifest["confirmatory_verdict_permitted"]}))


if __name__ == "__main__":
    main()
