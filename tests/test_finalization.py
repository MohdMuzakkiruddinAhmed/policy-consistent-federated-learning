"""Final evidence joins and public packaging; no actual cloud/clinical claims."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import finalize_research as final
import release_research as release
from pcfl.experiments import canonical, digest, file_digest


def retain(root, name, body):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(body) + b"\n")
    return {"path": name, "sha256": file_digest(path)}


def fixture(root):
    source = root / "src/example.py"
    source.parent.mkdir()
    source.write_text("# public synthetic source fixture\n", encoding="utf-8")
    sources = {"src/example.py": file_digest(source)}
    plan = {"plan_digest": digest("synthetic-finalization-unit-plan"), "status": "accepted_frozen",
        "provenance": {"source_files_sha256": sources, "source_sha256": digest(sources), "image_digests": {}},
        "primary_cells": [], "data_manifest_digest": digest("synthetic-metadata")}
    report = retain(root, "reports/fixture.json", {"kind": "synthetic-unit-test-only", "checks": {"verified": True}})
    abstract = retain(root, "reports/abstract.json", {"kind": "user-provided-literature-abstract-provenance", "available_content": "abstract-only",
        "full_text_read": False, "retrieval_status": "stopped-per-user-confirmed-abstract-only-boundary", "unknown_from_available_abstract": ["exact interval semantics"]})
    scope = retain(root, "configs/research_scope.json", json.loads((ROOT / "configs/research_scope.json").read_text(encoding="utf-8")))
    retain(root, "state/foundation.json", {"resources": []})
    retain(root, "state/runtime.json", {"resources": []})
    originals = {name: retain(root, "state/" + name + "-before.json", {"resources": [{"type": "synthetic-private-unit-state", "instances": []}]})
                 for name in ("foundation", "runtime")}
    private = root / "private-model.npz"
    private.write_bytes(b"synthetic-private-array-placeholder-not-a-real-model")
    inv = {"campaign_id": "campaign-one", "account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-test", "teardown_complete": True,
        "state_paths": {"foundation": "state/foundation.json", "runtime": "state/runtime.json"},
        "pre_teardown_state_snapshots": originals,
        "retained_artifact_versions": [{"local_path": "private-model.npz", "sha256": file_digest(private)}]}
    inventory = retain(root, "evidence/inventory.json", inv)
    readback = retain(root, "evidence/readback.json", {**{key: inv[key] for key in ("campaign_id", "account_id", "region", "project_id")},
        "kind": "actual-aws-campaign-teardown-validation", "successful": True, "performed_read_only": True,
        "inventory_sha256": inventory["sha256"], "checks": {key: True for key in final.TEARDOWN_CHECKS}})
    authorization = retain(root, "evidence/authorization.json", {"approved": True, "account_id": inv["account_id"], "region": inv["region"],
        "authorization_scope": "remaining-phases-cloud-campaign-including-replication"})
    ledger = retain(root, "evidence/budget-ledger.json", {"authorization_sha256": authorization["sha256"], "tasks": {},
        "deployments": {"one": {"campaign_id": "campaign-one", "finished_at": "2026-11-13T00:00:00Z"}}})
    leaf = {"report": "test", "pointer": "/checks/verified", "expected": True}
    recipe = {"schema_version": "0.1.0", "kind": "research-phase-evidence-map", "artifact_version": "synthetic-unit-v1", "plan_digest": plan["plan_digest"],
        "reports": {"test": report, "abstract": abstract}, "research_scope": scope,
        "qualifications": {"abstract-only-related-work": "abstract"},
        "phases": {group: {name: dict(leaf) for name in names} for group, names in final.PHASES.items()},
        "gates": {group: {name: dict(leaf) for name in names} for group, names in final.GATES.items()},
        "teardown": {"inventories": [inventory], "readbacks": [readback], "budget_ledger": ledger, "authorization": authorization}}
    # This mocked analysis is explicitly confined to compiler unit tests.
    analysis = {"primary_matrix_complete": True, "confirmatory_verdict_permitted": True,
        "coverage": {name: {"unattempted": 0} for name in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells")},
        "tables": {"replications": [{"fresh_deployment_metadata_verified": True}]},
        "hypotheses": {name: {"verdict": "inconclusive" if name == "H3" else "not supported"} for name in ("H1", "H2", "H3", "H4")}}
    return plan, recipe, analysis


class FinalizationTests(unittest.TestCase):
    def test_complete_reference_join_allows_qualified_h3_without_claiming_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, recipe, analysis = fixture(root)
            with patch.object(final, "analyze_registry", return_value=analysis):
                result = final.finalize(recipe, plan, [], root=root)
            self.assertTrue(result["all_phases_complete"], result)
            self.assertEqual(result["phases"]["P1"]["status"], "qualified")
            self.assertEqual(result["phases"]["P9"]["status"], "qualified")
            self.assertIn("no support claimed", result["qualifications"]["H3-inconclusive"]["claim"])

    def test_missing_phase_gate_leaf_or_fake_pass_flag_keeps_completion_false(self):
        for missing in ("phase", "gate", "leaf", "assumed-pass", "missing-false-leaf"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, recipe, analysis = fixture(root)
                if missing == "phase": del recipe["phases"]["P10"]
                elif missing == "gate": del recipe["gates"]["G1"]
                elif missing == "leaf": recipe["phases"]["P7"]["guarded_publication"]["pointer"] = "/missing"
                elif missing == "assumed-pass": recipe["phases"]["P7"]["guarded_publication"] = True
                else: recipe["phases"]["P0"]["no_human_collection"] = {"report": "test", "pointer": "/missing", "expected": False}
                with patch.object(final, "analyze_registry", return_value=analysis), self.subTest(missing=missing):
                    self.assertFalse(final.finalize(recipe, plan, [], root=root)["all_phases_complete"])

    def test_malformed_qualification_or_report_map_returns_incomplete_document(self):
        for field, value in (("reports", []), ("qualifications", {"abstract-only-related-work": []}), ("teardown", None)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, recipe, analysis = fixture(root)
                recipe[field] = value
                with patch.object(final, "analyze_registry", return_value=analysis):
                    self.assertFalse(final.finalize(recipe, plan, [], root=root)["all_phases_complete"])

    def test_changed_reports_sources_and_missing_private_retention_fail_closed(self):
        for changed in ("report", "source", "private-array", "stack-state"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, recipe, analysis = fixture(root)
                target = {"report": "reports/fixture.json", "source": "src/example.py", "private-array": "private-model.npz", "stack-state": "state/runtime.json"}[changed]
                (root / target).write_bytes(b"changed")
                with patch.object(final, "analyze_registry", return_value=analysis), self.subTest(changed=changed):
                    self.assertFalse(final.finalize(recipe, plan, [], root=root)["all_phases_complete"])

    def test_old_last_campaign_only_or_open_deployment_clock_cannot_satisfy_teardown(self):
        for extra in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, recipe, analysis = fixture(root)
                path = root / recipe["teardown"]["budget_ledger"]["path"]
                ledger = json.loads(path.read_text())
                ledger["deployments"]["two"] = {"campaign_id": "campaign-omitted" if extra else "campaign-one", "finished_at": "2026-11-13T00:00:00Z" if extra else None}
                recipe["teardown"]["budget_ledger"] = retain(root, "evidence/budget-ledger.json", ledger)
                with patch.object(final, "analyze_registry", return_value=analysis):
                    result = final.finalize(recipe, plan, [], root=root)
                self.assertFalse(result["checks"]["final_aws_teardown_verified"])

    def test_bounded_failed_preparation_is_qualified_and_never_clinical_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, recipe, analysis = fixture(root)
            recipe["reports"]["preparation"] = retain(root, "reports/preparation.json", {"kind": "non-iid-sensitivity-data-preparation", "attempts": [{
                "alpha": .1, "status": "failed", "clinical_training_executed": False, "constraints_weakened": False,
                "retry_limit": 200, "minimum_patient_groups": 100, "minimum_positive_encounters": 25}]})
            recipe["qualifications"]["bounded-data-preparation-failure"] = "preparation"
            with patch.object(final, "analyze_registry", return_value=analysis):
                result = final.finalize(recipe, plan, [], root=root)
            self.assertTrue(result["all_phases_complete"])
            self.assertEqual(result["phases"]["P10"]["status"], "qualified")

    def test_missing_holdout_or_unattempted_trials_cannot_be_qualified_away(self):
        for changed in ("holdout", "coverage", "replication"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, recipe, analysis = fixture(root)
                if changed == "holdout": analysis["hypotheses"]["H4"]["verdict"] = "inconclusive"
                elif changed == "coverage": analysis["coverage"]["targeted_cells"]["unattempted"] = 1
                else: analysis["tables"]["replications"][0]["fresh_deployment_metadata_verified"] = False
                with patch.object(final, "analyze_registry", return_value=analysis):
                    self.assertFalse(final.finalize(recipe, plan, [], root=root)["all_phases_complete"])

    def test_public_source_archive_is_exact_versioned_and_excludes_private_arrays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, _, _ = fixture(root)
            output = root / "bundle"
            output.mkdir()
            manifest = release.source_archive(plan, output, "actual-artifact-v3", root=root)
            self.assertEqual(manifest["archive"], "source-actual-artifact-v3.zip")
            with zipfile.ZipFile(output / manifest["archive"]) as bundle:
                self.assertIn("src/example.py", bundle.namelist())
                self.assertNotIn("private-model.npz", bundle.namelist())
                self.assertEqual(set(bundle.namelist()), set(manifest["files_sha256"]))
            self.assertEqual(file_digest(output / manifest["archive"]), manifest["archive_sha256"])

    def test_source_archive_rejects_raw_rows_private_keys_and_changed_source(self):
        for kind in ("rows", "key", "changed"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan, _, _ = fixture(root)
                output = root / "bundle"
                output.mkdir()
                if kind == "rows":
                    path = root / "data/raw.csv"
                    path.parent.mkdir()
                    path.write_text("synthetic-only\n")
                    plan["provenance"]["source_files_sha256"]["data/raw.csv"] = file_digest(path)
                    plan["provenance"]["source_sha256"] = digest(plan["provenance"]["source_files_sha256"])
                elif kind == "key":
                    body = "-----BEGIN " + "PRIVATE KEY-----\n" + "x" * 80 + "\n-----END " + "PRIVATE KEY-----\n"
                    (root / "src/example.py").write_text(body)
                    plan["provenance"]["source_files_sha256"]["src/example.py"] = file_digest(root / "src/example.py")
                    plan["provenance"]["source_sha256"] = digest(plan["provenance"]["source_files_sha256"])
                else: (root / "src/example.py").write_text("changed")
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    release.source_archive(plan, output, "unit-v1", root=root)

    def test_release_recomputes_phase_document_and_preserves_scope_statement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, recipe, analysis = fixture(root)
            with patch.object(final, "analyze_registry", return_value=analysis):
                evidence = final.finalize(recipe, plan, [], root=root)
                path = root / "phase.json"
                path.write_bytes(canonical(evidence))
                with patch.object(release, "analyze_registry", return_value=analysis), patch.object(release, "write_analysis", side_effect=lambda report, output: [(Path(output) / name).write_text("synthetic-analysis-fixture") for name in ("analysis.json", "claim_evidence_matrix.csv", "replications.csv")]):
                    manifest = release.create_release(plan, [], root / "release", artifact_version="synthetic-unit-v1", phase_evidence=path, source_root=root)
                    self.assertFalse(manifest["all_phases_complete"])
                    self.assertFalse(manifest["public_attachments_complete"])
                    prose = (root / "release/final_validation.md").read_text()
                    self.assertIn("self-reported scope boundary", prose)
                    self.assertNotIn("Institutional classification is unverified", prose)
                    evidence["phases"]["P9"]["status"] = "passed"
                    path.write_bytes(canonical(evidence))
                    rejected = release.create_release(plan, [], root / "rebound", artifact_version="synthetic-unit-v1", phase_evidence=path, source_root=root)
                    self.assertFalse(rejected["all_phases_complete"])


if __name__ == "__main__":
    unittest.main()
