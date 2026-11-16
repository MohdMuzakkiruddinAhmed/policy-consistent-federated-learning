"""Alter disposable copies of a signed cloud export and verify detection."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from anchor_evidence import retained_cases, verify_witness
from verify_cloud_campaign import scoped_artifact_cache
from pcfl import runtime_verify


def assess(inventory_path, *, cell_id, public_key_path, public_key_sha256, expectation=None):
    path = Path(inventory_path).resolve()
    inventory = json.loads(path.read_text())
    application, cases = retained_cases(inventory, path)
    selected = [case for case in cases if case[0] == cell_id]
    if len(selected) != 1:
        raise ValueError("one_explicit_retained_case_required")
    _, original, evidence, raw_sha = selected[0]
    refs = [record for record in inventory["protected_operator_witnesses"] if record["cell_id"] == cell_id
            and record.get("raw_result_sha256") == raw_sha
            and record.get("application_campaign_id", inventory["campaign_id"]) == application]
    if len(refs) != 1:
        raise ValueError("one_exact_signed_case_witness_required")
    witness_path = Path(refs[0]["local_path"])
    if hashlib.sha256(witness_path.read_bytes()).hexdigest() != refs[0]["sha256"]:
        raise ValueError("retained_witness_bytes_changed")
    witness, public_pem = json.loads(witness_path.read_text()), Path(public_key_path).read_bytes()
    cache = json.loads((original / "artifact_paths.json").read_text())
    base = Path.home() / ".pcfl/tamper-copies"
    base.mkdir(parents=True, exist_ok=True)
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="copy-", dir=base) as temporary:
        directory = Path(temporary).resolve()
        if not directory.is_relative_to(base.resolve()):
            raise ValueError("tamper_copy_outside_assigned_temporary_root")
        copied_cache = {}
        for sha, location in cache.items():
            source = (original / location).resolve()
            if not source.is_relative_to(original.resolve()) or hashlib.sha256(source.read_bytes()).hexdigest() != sha:
                raise ValueError("original_model_cache_integrity_failure")
            destination = directory / (sha[:16] + ".npz")
            destination.write_bytes(source.read_bytes())
            copied_cache[sha] = destination.name
        (directory / "artifact_paths.json").write_text(json.dumps(copied_cache))
        result_path = directory / "runtime_result.json"
        original_raw = (original / "runtime_result.json").read_bytes()
        result_path.write_bytes(original_raw)
        def verify():
            raw = result_path.read_bytes()
            current = json.loads(raw)
            if (not verify_witness(witness, public_pem, expected_public_key_sha256=public_key_sha256)
                    or witness["payload"]["raw_result_sha256"] != hashlib.sha256(raw).hexdigest()
                    or witness["payload"]["run_id"] != current["persistent_run_id"]
                    or witness["payload"]["anchor"] != current["anchor"]):
                raise ValueError("external_signed_witness_binding_rejected")
            with scoped_artifact_cache(directory):
                if current.get("full_protocol") is False or current.get("successful") is not True:
                    from pcfl.ablation_verify import assess_case
                    return assess_case(result_path, witness=witness, public_key_pem=public_pem,
                                       expected_public_key_sha256=public_key_sha256)
                return runtime_verify.verify_case(result_path, expect_test_authorization=expectation)
        baseline = verify()
        if not evidence.get("audit"):
            raise ValueError("choose_a_case_with_actual_audit_records_for_record_tamper_attacks")
        for attack in ("modify-record", "delete-record", "replay-record", "reorder-records", "truncate-chain", "change-model-bytes"):
            result_path.write_bytes(original_raw)
            changed = deepcopy(evidence)
            if attack == "modify-record":
                changed["audit"][0]["payload"]["reason"] = "copied-record-tamper"
            elif attack == "delete-record":
                changed["audit"].pop()
            elif attack == "replay-record":
                changed["audit"].append(deepcopy(changed["audit"][0]))
            elif attack == "reorder-records":
                if len(changed["audit"]) < 2:
                    raise ValueError("two_audit_records_required_for_reordering")
                changed["audit"][0], changed["audit"][1] = changed["audit"][1], changed["audit"][0]
            elif attack == "truncate-chain":
                changed["audit"] = changed["audit"][:1]
                changed["anchor"] = {"count": 1, "head": changed["audit"][0]["event_hash"]}
            else:
                artifact = evidence["updates"][0]["artifact"]
                sha = artifact.get("sha256", artifact.get("file_sha256"))
                name = copied_cache[sha]
                model_path = directory / name
                saved = model_path.read_bytes()
                model_path.write_bytes(saved[:-1] + bytes([saved[-1] ^ 1]))
            if attack != "change-model-bytes":
                result_path.write_text(json.dumps(changed, sort_keys=True))
            try:
                verify()
            except (ValueError, KeyError, OSError) as error:
                outcomes.append({"attack_id": attack, "detected": True, "reason": str(error)[:200]})
            else:
                outcomes.append({"attack_id": attack, "detected": False, "reason": "alteration_accepted"})
            if attack == "change-model-bytes":
                model_path.write_bytes(saved)
        result_path.write_bytes(original_raw)
        verify()
    return {"schema_version": "0.1.0", "kind": "externally-anchored-copied-cloud-evidence-tamper-test",
        "successful": bool(baseline) and len(outcomes) == 6 and all(row["detected"] for row in outcomes),
        "application_campaign_id": application, "cell_id": cell_id, "raw_result_sha256": raw_sha,
        "witness_sha256": refs[0]["sha256"], "expected_public_key_sha256": public_key_sha256,
        "original_passed_before_and_after": True, "original_bytes_preserved": True,
        "tamper_scope": "disposable-copies-after-runtime-invocation", "attacks": outcomes,
        "limitations": ["Trusted operator key and host are outside the attacker boundary",
                        "Copied export changes are detected by the externally signed raw-result binding; model changes also require independent byte-digest/model verification"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "cell-id", "public-key", "public-key-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--accepted-plan")
    parser.add_argument("--holdout-authorization")
    args = parser.parse_args()
    if bool(args.accepted_plan) != bool(args.holdout_authorization):
        raise ValueError("both_external_test_authority_inputs_required")
    expectation = ({"accepted_plan": json.loads(Path(args.accepted_plan).read_text()),
                    "authorization": json.loads(Path(args.holdout_authorization).read_text())} if args.accepted_plan else None)
    report = assess(args.inventory, cell_id=args.cell_id, public_key_path=args.public_key,
                    public_key_sha256=args.public_key_sha256, expectation=expectation)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"successful": report["successful"], "tamper_detected": sum(row["detected"] for row in report["attacks"])}))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
