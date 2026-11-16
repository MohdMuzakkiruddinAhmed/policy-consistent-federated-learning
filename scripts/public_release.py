"""Explicit reviewed public aggregates, and a separate nonpublic replay catalog."""
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import unicodedata

SHA = re.compile(r"[0-9a-f]{64}")
REQUIRED = {"claim_evidence_matrix.csv", "claim_evidence_matrix.json", "evidence_references.json", "tables/analysis.json",
    *("reports/" + name + ".md" for name in ("results", "limitations", "design_principles", "validation_findings", "final_validation"))}
PRIVATE_KEYS = {"private_key", "private_key_pem", "server_key_pem", "client_key_pem", "password", "secret_access_key",
    "aws_secret_access_key", "session_token", "aws_session_token", "patient_id", "patient_nbr", "encounter_id", "diag_1", "diag_2", "diag_3",
    "race", "gender", "age", "weight", "parameters", "parameter_arrays", "predictions", "clinical_rows"}


def sha(body): return hashlib.sha256(body).hexdigest()
def digest(value): return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def relative(value):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value or value.startswith("/")
            or unicodedata.normalize("NFC", value) != value or any(part in {"", ".", ".."} for part in value.split("/"))
            or str(PurePosixPath(value)) != value or not re.fullmatch(r"[A-Za-z0-9._/-]+", value)):
        raise ValueError("canonical_public_relative_path_required")
    return value


def source(root, reference):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"} or not isinstance(reference["sha256"], str) or not SHA.fullmatch(reference["sha256"]):
        raise ValueError("public_attachment_exact_source_reference_required")
    name = relative(reference["path"])
    if {part.lower() for part in name.split("/")} & {"data", "private", "raw", "secrets", "secret-payloads", ".terraform"}:
        raise ValueError("private_source_tree_forbidden")
    path = Path(root) / name
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("public_attachment_link_forbidden")
        if part == Path(root): break
    if not path.is_file() or not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError("public_attachment_owned_regular_source_required")
    if path.stat().st_size > 64 * 1024**2:
        raise ValueError("public_attachment_hash_or_size_mismatch")
    body = path.read_bytes()
    if len(body) > 64 * 1024**2 or sha(body) != reference["sha256"]:
        raise ValueError("public_attachment_hash_or_size_mismatch")
    return path, body


def safe_body(body, suffix):
    if (re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body)
            or re.search(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", body)
            or re.search(rb"(?i)(?:file://|(?<![A-Za-z0-9])[A-Z]:[\\/]|/Users/|/home/|/mnt/|/run/secrets/|/runtime/secrets/)", body)
            or re.search(rb"(?i)(?:[?&](?:token|password|secret|X-Amz-Signature|X-Amz-Credential)=)", body)):
        raise ValueError("private_material_or_local_path_in_public_attachment")
    def walk(value):
        if isinstance(value, dict):
            if any(str(key).lower() in PRIVATE_KEYS for key in value):
                raise ValueError("private_or_clinical_record_fields_in_attachment")
            if isinstance(value.get("records"), (list, dict)):
                raise ValueError("raw_record_collections_in_attachment")
            for item in value.values(): walk(item)
        elif isinstance(value, list):
            for item in value: walk(item)
    if suffix == ".json": walk(json.loads(body))
    elif suffix == ".csv":
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))
        if any(key.lower() in PRIVATE_KEYS for row in rows for key in row if key):
            raise ValueError("clinical_or_private_csv_columns_forbidden")
        # Reporter cells may contain nested aggregate JSON, which needs the
        # same forbidden-field checks as the corresponding JSON supplement.
        for row in rows:
            for value in row.values():
                if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
                    try: walk(json.loads(value))
                    except json.JSONDecodeError: pass
    elif suffix == ".svg":
        if (b"<svg" not in body or re.search(rb"(?i)<(?:script|foreignObject)|\bon[a-z]+\s*=|(?:href|src)\s*=\s*['\"](?!#)|url\(\s*['\"]?(?!#)", body)):
            raise ValueError("active_or_external_svg_forbidden")
    elif suffix == ".png":
        if not body.startswith(b"\x89PNG\r\n\x1a\n"): raise ValueError("png_signature_required")
    elif suffix == ".pdf":
        if not body.startswith(b"%PDF-") or re.search(rb"/(?:JavaScript|Launch|EmbeddedFile|OpenAction|URI)\b", body):
            raise ValueError("active_or_nonfigure_pdf_forbidden")
    elif suffix != ".md": raise ValueError("safe_public_attachment_type_required")


def public_attachments(spec, plan, attempts, output, *, root):
    """Copy exactly the reviewed reporting tree; this never passes a study gate."""
    from pcfl.analysis import analyze_registry
    for part in (Path(output).absolute(), *Path(output).absolute().parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_public_output_forbidden")
    required = {"schema_version", "kind", "artifact_version", "plan_digest", "attempts_digest", "reporting_manifest", "files"}
    if (not isinstance(spec, dict) or set(spec) != required or spec.get("schema_version") != "0.1.0"
            or spec.get("kind") != "reviewed-public-release-attachments" or spec.get("plan_digest") != plan["plan_digest"]
            or spec.get("attempts_digest") != digest(attempts) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", spec.get("artifact_version", ""))
            or not isinstance(spec.get("files"), list) or not spec["files"] or len(spec["files"]) > 2000):
        raise ValueError("strict_plan_bound_public_attachment_spec_required")
    manifest_path, manifest_body = source(root, spec["reporting_manifest"])
    safe_body(manifest_body, ".json")
    manifest = json.loads(manifest_body)
    if (manifest.get("kind") != "bound-final-reporting-drafts" or manifest.get("successful") is not True
            or manifest.get("assessment_scope") != "reporting-input-integrity-only" or manifest.get("all_phases_complete") is not False
            or manifest.get("plan_digest") != plan["plan_digest"] or manifest.get("attempts_digest") != digest(attempts)
            or manifest.get("source_sha256") != plan["provenance"]["source_files_sha256"].get("scripts/report_final_artifacts.py")
            or not isinstance(manifest.get("files_sha256"), dict) or not REQUIRED <= set(manifest["files_sha256"])):
        raise ValueError("bound_detailed_reporting_manifest_required")
    selected, bodies, aliases, selected_bytes = {}, {}, set(), 0
    for entry in spec["files"]:
        if not isinstance(entry, dict) or set(entry) != {"source", "destination", "category"}:
            raise ValueError("strict_reviewed_attachment_entry_required")
        destination = relative(entry["destination"])
        if not destination.startswith("reporting/") or destination.casefold() in aliases:
            raise ValueError("public_attachment_destination_scope_or_collision")
        aliases.add(destination.casefold())
        path, body = source(root, entry["source"])
        selected_bytes += len(body)
        if selected_bytes > 256 * 1024**2: raise ValueError("bounded_public_attachment_size_exceeded")
        if Path(output).resolve() == path.resolve() or Path(output).resolve() in path.resolve().parents:
            raise ValueError("attachment_source_output_overlap")
        suffix = Path(destination).suffix
        if suffix not in {".json", ".csv", ".md", ".svg", ".png", ".pdf"} or path.suffix != suffix:
            raise ValueError("safe_public_attachment_type_required")
        safe_body(body, suffix)
        relative_report = destination.removeprefix("reporting/")
        category = entry["category"]
        if category == "reporting":
            if relative_report == "reporting_manifest.json":
                if entry["source"] != spec["reporting_manifest"]: raise ValueError("reporting_manifest_attachment_rebound")
            elif manifest["files_sha256"].get(relative_report) != entry["source"]["sha256"]:
                raise ValueError("attachment_not_in_exact_reporting_tree")
            if path.resolve() != (manifest_path.parent / relative_report).resolve():
                raise ValueError("reporting_source_tree_not_preserved")
        elif category == "figure_manifest":
            if relative_report != "figures/figures_manifest.json": raise ValueError("figure_manifest_destination_required")
        elif category == "exploratory":
            if not re.fullmatch(r"evidence/exploratory-[0-9a-f]{16}\.json", relative_report) or suffix != ".json":
                raise ValueError("normalized_exploratory_destination_required")
        else: raise ValueError("known_public_attachment_category_required")
        selected[destination], bodies[destination] = entry, body
    expected_tree = {"reporting/" + relative(name) for name in manifest["files_sha256"]} | {"reporting/reporting_manifest.json"}
    if not expected_tree <= set(selected): raise ValueError("complete_reporting_tree_attachments_required")
    analysis = analyze_registry(plan, attempts)
    if json.loads(bodies["reporting/tables/analysis.json"]) != analysis:
        raise ValueError("attachment_analysis_not_exact_recomputation")
    claims = json.loads(bodies["reporting/claim_evidence_matrix.json"])
    if (not isinstance(claims, list) or not {"RQ1", "RQ2", "RQ3", "RQ4"} <= {row.get("RQ") for row in claims}
            or any(row.get("plan_digest") != plan["plan_digest"] or row.get("attempts_digest") != digest(attempts) for row in claims)):
        raise ValueError("detailed_claim_matrix_plan_attempt_binding_required")
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=sorted({key for row in claims for key in row}))
    writer.writeheader()
    for row in claims:
        writer.writerow({key: json.dumps(value, sort_keys=True, allow_nan=False) if isinstance(value, (dict, list)) else value
                         for key, value in row.items()})
    if bodies["reporting/claim_evidence_matrix.csv"] != csv_buffer.getvalue().encode():
        raise ValueError("claim_csv_json_exact_equivalence_required")
    figure_key = "reporting/figures/figures_manifest.json"
    if not manifest.get("figures") or figure_key not in selected: raise ValueError("bound_figure_manifest_required")
    figures = json.loads(bodies[figure_key])
    if (figures.get("kind") != "reproducible-descriptive-research-figures" or figures.get("plan_digest") != plan["plan_digest"]
            or figures.get("all_attempts_retained") != len(attempts)
            or figures.get("input_sha256") != {key: manifest["inputs"][name]["sha256"]
                for key, name in (("plan", "accepted_plan"), ("attempts", "figure_attempts"), ("analysis", "analysis"))}
            or not figures.get("files")):
        raise ValueError("figure_manifest_scientific_input_binding_required")
    if {(item["path"], item["sha256"]) for item in figures["files"]} != {(item["path"], item["sha256"]) for item in manifest["figures"]}:
        raise ValueError("figure_manifest_reporting_file_set_mismatch")
    for item in figures["files"]:
        name = "reporting/figures/" + relative(item["path"])
        if name not in bodies or sha(bodies[name]) != item["sha256"]:
            raise ValueError("figure_target_missing_or_hash_changed")
    references = json.loads(bodies["reporting/evidence_references.json"])
    required_exploratory = {row["sha256"] for row in references if row.get("kind") == "independent-exploratory-robustness-summary"}
    supplied_exploratory = set()
    for name, entry in selected.items():
        if entry["category"] != "exploratory": continue
        report = json.loads(bodies[name])
        if (report.get("kind") != "independent-exploratory-robustness-summary" or report.get("data_kind") != "clinical"
                or report.get("plan_digest") != plan["plan_digest"] or report.get("independent_seed_count") != 1
                or report.get("confirmatory") is not False or report.get("evaluation_split") != "validation" or report.get("final_test_accessed") is not False):
            raise ValueError("strict_clinical_exploratory_aggregate_required")
        from robustness_reporting import normalize
        normalize(report, root=root, plan_digest=plan["plan_digest"], report_alias="public-release", report_sha256=entry["source"]["sha256"])
        if name != "reporting/evidence/exploratory-" + entry["source"]["sha256"][:16] + ".json":
            raise ValueError("exploratory_destination_hash_binding_required")
        supplied_exploratory.add(entry["source"]["sha256"])
    if required_exploratory != supplied_exploratory: raise ValueError("all_referenced_normalized_robustness_attachments_required")
    # Resolve public claim links without changing the original bytes/hashes.
    for claim in claims:
        for link in claim.get("figure_links", []):
            name = "reporting/" + relative(link["path"])
            if name not in bodies or sha(bodies[name]) != link["sha256"]: raise ValueError("claim_figure_link_not_retained")
        for link in claim.get("table_links", []):
            name = "reporting/" + relative(link["path"])
            if name not in bodies: raise ValueError("claim_table_link_not_retained")
    total = 0
    for name, entry in selected.items():
        path, current = source(root, entry["source"])
        if current != bodies[name]: raise ValueError("attachment_changed_before_copy")
        total += len(current)
        if total > 256 * 1024**2: raise ValueError("bounded_public_attachment_size_exceeded")
        destination = Path(output) / name
        for part in (destination, *destination.parents):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise ValueError("linked_public_output_forbidden")
            if part == Path(output): break
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream: stream.write(current)
        if sha(destination.read_bytes()) != entry["source"]["sha256"] or path.read_bytes() != current:
            raise ValueError("attachment_copy_or_source_hash_changed")
    return {"kind": "verified-reviewed-public-attachments", "successful": True, "artifact_version": spec["artifact_version"],
        "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts), "spec_digest": digest(spec),
        "files_sha256": {name: sha(body) for name, body in bodies.items()}, "public_file_count": len(bodies),
        "clinical_records_included": False, "private_arrays_included": False, "study_completion_inferred": False}


def private_catalog(plan, attempts):
    """Hash/ID catalog only, never private file bytes or host filesystem paths."""
    return {"kind": "separately-retained-private-replay-catalog", "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts),
        "private_artifacts_in_public_bundle": False, "catalog_establishes_replay_success": False,
        "runs": [{"attempt_id": row["attempt_id"], "cell_id": row["cell_id"], "status": row["status"],
            "deployment_id": row["execution"]["deployment_id"], "run_id": row["execution"].get("namespace"),
            "evidence_sha256": {key: value for key, value in row["evidence"].items() if isinstance(value, str) and SHA.fullmatch(value)}} for row in attempts],
        "retained_inputs_required": ["exact application inventory and raw index versions", "model/update NPZ versions and case artifact_paths.json",
            "original producer durable evidence", "protected operator witnesses", "external public PEM and trusted DER SHA256 pin",
            "accepted plan and separate holdout authorization when test evaluation was accessed"],
        "complete_replay_command": "python source/scripts/verify_cloud_campaign.py --inventory <private-evidence-root>/<application-inventory.json> --witness-public-key <external-operator-public.pem> --witness-public-key-sha256 <trusted-DER-SHA256> --accepted-plan locked_plan.json --holdout-authorization <separate-holdout-authorization.json> --output <new-private-replay-report.json>",
        "validation_only_replay": "Omit --accepted-plan and --holdout-authorization together only for a validation-only run; external operator PEM and pin remain required.",
        "public_scope": "Public reproduce.py verifies source/aggregate inputs and deterministic statistics only; it does not replay private model/audit artifacts."}


def reproduction_script():
    # This script is hashed in release_manifest.json; trust the separately
    # published release-manifest digest before running any downloaded code.
    return '''# Install requirements-analysis.lock in a clean environment first.
import hashlib,json,shutil,sys,tempfile,zipfile
from pathlib import Path,PurePosixPath
root=Path(__file__).resolve().parent
def require(value,reason):
 if not value: raise ValueError(reason)
def digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
def safe(value):
 require(isinstance(value,str) and value and "\\\\" not in value and ":" not in value and not value.startswith("/") and all(part not in {"",".",".."} for part in value.split("/")) and str(PurePosixPath(value))==value,"unsafe_release_member")
 return value
def content(base,name):
 path=base/safe(name)
 require(path.is_file() and path.resolve().is_relative_to(base.resolve()),"missing_or_outside_release_member")
 for part in (path,*path.parents):
  require(not part.is_symlink() and not (hasattr(part,"is_junction") and part.is_junction()),"linked_release_member")
  if part==base: break
 return path.read_bytes()
release_body=content(root,"release_manifest.json")
release=json.loads(release_body)
require(release.get("kind")=="aggregate-research-reproduction-bundle","release_manifest_kind_mismatch")
for name,expected in release["files_sha256"].items():
 require(hashlib.sha256(content(root,name)).hexdigest()==expected,"released_file_digest_mismatch:"+name)
for name in ("locked_plan.json","aggregate_attempts.json","analysis.json","public_source_manifest.json","reproduce.py"):
 require(name in release["files_sha256"],"required_release_binding_missing:"+name)
manifest=json.loads(content(root,"public_source_manifest.json"))
require(manifest["artifact_version"]==release["artifact_version"],"release_version_mismatch")
archive=root/safe(manifest["archive"])
require(hashlib.sha256(content(root,manifest["archive"])).hexdigest()==manifest["archive_sha256"],"source_archive_digest_mismatch")
extracted=root/"source"
with zipfile.ZipFile(archive) as bundle:
 require(len(bundle.namelist())==len(set(bundle.namelist())) and set(bundle.namelist())==set(manifest["files_sha256"]),"source_archive_member_set_mismatch")
 for name,expected in manifest["files_sha256"].items():
  safe(name)
  require(hashlib.sha256(bundle.read(name)).hexdigest()==expected,"source_member_digest_mismatch")
 if extracted.exists():
  require(extracted.is_dir() and not extracted.is_symlink(),"existing_source_not_regular")
  existing={path.relative_to(extracted).as_posix() for path in extracted.rglob("*") if path.is_file()}
  require(existing==set(manifest["files_sha256"]),"existing_source_member_set_mismatch")
  for name,expected in manifest["files_sha256"].items():
   require(hashlib.sha256(content(extracted,name)).hexdigest()==expected,"existing_source_digest_mismatch")
 else: bundle.extractall(extracted)
sys.dont_write_bytecode=True
sys.path.insert(0,str(extracted/"src"))
from pcfl.analysis import analyze_registry,write_analysis
plan=json.loads(content(root,"locked_plan.json"))
attempts=json.loads(content(root,"aggregate_attempts.json"))
require(plan["plan_digest"]==release["plan_digest"] and digest(attempts)==release["attempts_digest"],"released_scientific_input_binding_mismatch")
require(plan["provenance"]["source_files_sha256"]==manifest["frozen_executable_files_sha256"]==release["source_files_sha256"],"frozen_source_inventory_mismatch")
expected_outputs=release["analysis_files_sha256"]
require(expected_outputs and "analysis.json" in expected_outputs and all(release["files_sha256"].get(name)==expected for name,expected in expected_outputs.items()),"analysis_output_binding_missing")
with tempfile.TemporaryDirectory(prefix="pcfl-reproduce-") as temporary:
 generated=Path(temporary)
 write_analysis(analyze_registry(plan,attempts),generated)
 actual={path.relative_to(generated).as_posix() for path in generated.rglob("*") if path.is_file()}
 require(actual==set(expected_outputs),"regenerated_analysis_file_set_mismatch")
 for name,expected in expected_outputs.items():
  body=content(generated,name)
  require(hashlib.sha256(body).hexdigest()==expected and body==content(root,name),"regenerated_analysis_mismatch:"+name)
 destination=root/"reproduced"
 if destination.exists():
  require({path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}==actual,"existing_reproduction_file_set_mismatch")
  for name in actual: require(content(destination,name)==content(generated,name),"existing_reproduction_changed")
 else: shutil.copytree(generated,destination)
print(json.dumps({"kind":"hash-bound-public-release-reproduction","successful":True,"artifact_version":release["artifact_version"],"plan_digest":release["plan_digest"],"attempts_digest":release["attempts_digest"],"release_manifest_sha256":hashlib.sha256(release_body).hexdigest(),"scope":"hash-bound-source-and-aggregate-statistics-only","private_model_audit_replayed":False,"analysis_files_verified":len(expected_outputs)},sort_keys=True))
'''
