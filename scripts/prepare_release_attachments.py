"""Build and validate a deterministic public attachment spec from real reports.

This reversible local preparation calls no AWS service and grants no study gate.
It uses the reporter's exact file inventory, not directory or private-data globs.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
from pcfl.experiments import digest, file_digest, load_attempts
from public_release import public_attachments, relative, source


def prepare(plan, attempts, reporting_manifest, figure_manifest, artifact_version, *, root=ROOT):
    root = Path(root).resolve()
    def reference(path):
        path = Path(path).absolute()
        for part in (path, *path.parents):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise ValueError("public_attachment_link_forbidden")
        path = path.resolve()
        if not path.resolve().is_relative_to(root): raise ValueError("attachment_input_outside_evidence_root")
        if path.stat().st_size > 64 * 1024**2: raise ValueError("bounded_public_attachment_size_exceeded")
        value = {"path": path.relative_to(root).as_posix(), "sha256": file_digest(path)}
        source(root, value)
        return value
    reporting_reference = reference(reporting_manifest)
    reporting_path, body = source(root, reporting_reference)
    manifest = json.loads(body)
    spec = {"schema_version": "0.1.0", "kind": "reviewed-public-release-attachments", "artifact_version": artifact_version,
        "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts), "reporting_manifest": reporting_reference, "files": []}
    for name, expected in sorted(manifest["files_sha256"].items()):
        path = reporting_path.parent / relative(name)
        item = reference(path)
        if item["sha256"] != expected: raise ValueError("reporter_tree_changed_before_spec_preparation")
        spec["files"].append({"source": item, "destination": "reporting/" + name, "category": "reporting"})
    spec["files"].append({"source": reporting_reference, "destination": "reporting/reporting_manifest.json", "category": "reporting"})
    spec["files"].append({"source": reference(figure_manifest), "destination": "reporting/figures/figures_manifest.json", "category": "figure_manifest"})
    references = json.loads((reporting_path.parent / "evidence_references.json").read_bytes())
    for row in references:
        if row.get("kind") != "independent-exploratory-robustness-summary": continue
        item = {name: row[name] for name in ("path", "sha256")}
        source(root, item)
        spec["files"].append({"source": item, "destination": "reporting/evidence/exploratory-" + item["sha256"][:16] + ".json", "category": "exploratory"})
    # Validate semantics, exact schema, public content, figures and every link
    # using temporary copies before writing the caller's reviewable spec.
    with tempfile.TemporaryDirectory(prefix="pcfl-public-spec-") as temporary:
        public_attachments(spec, plan, attempts, Path(temporary) / "bundle", root=root)
    return spec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "attempts", "reporting-manifest", "figure-manifest", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--evidence-root", type=Path, default=ROOT)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_bytes())
    attempts = load_attempts(args.attempts, plan)
    spec = prepare(plan, attempts, args.reporting_manifest, args.figure_manifest, args.artifact_version, root=args.evidence_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(spec, stream, sort_keys=True, indent=2, allow_nan=False); stream.write("\n")
    print(json.dumps({"attachment_spec_written": True, "files": len(spec["files"]), "aws_calls": False,
        "study_completion_inferred": False, "sha256": file_digest(args.output)}))


if __name__ == "__main__": main()
