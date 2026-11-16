"""Check retained candidate-bound gate assessments before an acceptance freeze.

No training, AWS calls, approval inference, or holdout access is performed.
Missing or failed gates produce readiness evidence without an accepted plan.
"""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.experiments import GATES, GATE_CHECKS, canonical, file_digest, freeze_plan, scientific_binding, validate_gate_report, validate_plan


def assess_acceptance(plan, gate_paths, root):
    validate_plan(plan)
    root = Path(root).resolve()
    if set(gate_paths) - GATES:
        raise ValueError("unknown_acceptance_gate")
    refs, readiness = {}, {}
    for gate_id in sorted(GATES):
        if gate_id not in gate_paths:
            readiness[gate_id] = {"passed": False, "reason": "actual-scientific-assessment-missing", "required_checks": sorted(GATE_CHECKS[gate_id])}
            continue
        path = (root / gate_paths[gate_id]).resolve()
        try:
            if not path.is_relative_to(root) or path.is_symlink():
                raise ValueError("gate_path_outside_workspace")
            report = json.loads(path.read_text(encoding="utf-8"))
            validate_gate_report(plan, gate_id, report, root)
            refs[gate_id] = {"path": path.relative_to(root).as_posix(), "sha256": file_digest(path), "passed": True}
            readiness[gate_id] = {"passed": True, "assessment": refs[gate_id]}
        except (ValueError, KeyError, TypeError, OSError) as error:
            readiness[gate_id] = {"passed": False, "reason": str(error)[:256]}
    complete = set(refs) == GATES
    report = {"kind": "scientific-freeze-readiness", "successful": complete,
        "candidate_plan_digest": plan["plan_digest"], "scientific_binding": scientific_binding(plan),
        "gates": readiness, "test_access_authorized": False}
    return report, {"gates": refs} if complete else None


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = canonical(value) + b"\n"
    if path.exists() and path.read_bytes() != body:
        raise ValueError("existing_acceptance_artifact_differs_use_versioned_output")
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="Existing locked candidate; never rebuild during acceptance")
    parser.add_argument("--gates", required=True, help="JSON mapping gate IDs to actual assessment paths")
    parser.add_argument("--readiness", required=True)
    parser.add_argument("--output", required=True, help="New accepted plan, written only after all checks pass")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    report, acceptance = assess_acceptance(plan, json.loads(Path(args.gates).read_text()), ROOT)
    # freeze_plan additionally verifies current source bytes and immutable images.
    accepted = freeze_plan(plan, acceptance, ROOT) if acceptance is not None else None
    write_new(args.readiness, report)
    if accepted is not None:
        write_new(args.output, accepted)
    print(json.dumps({"accepted": accepted is not None, "readiness": args.readiness,
                      "missing_or_failed_gates": [key for key, value in report["gates"].items() if not value["passed"]],
                      "test_access_authorized": False}, sort_keys=True))
    return 0 if accepted is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
