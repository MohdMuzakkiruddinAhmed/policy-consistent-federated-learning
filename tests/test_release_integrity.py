"""Real released analysis execution over synthetic aggregates; no cloud/training."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts"), str(ROOT / "tests")]
import release_research as release
from pcfl.experiments import append_attempt, build_plan, canonical, digest, file_digest, freeze_plan, scientific_sources
from test_experiments import example_attempt, synthetic_gate_refs


def fixture(directory):
    root = Path(directory)
    package = root / "src/pcfl"
    package.mkdir(parents=True)
    for name in ("__init__.py", "analysis.py", "experiments.py"):
        (package / name).write_bytes((ROOT / "src/pcfl" / name).read_bytes())
    scripts = root / "scripts"; scripts.mkdir()
    reporter = scripts / "report_final_artifacts.py"
    reporter.write_bytes((ROOT / "scripts/report_final_artifacts.py").read_bytes())
    sources = {path.relative_to(root).as_posix(): file_digest(path) for path in [*package.glob("*.py"), reporter]}
    config = json.loads((ROOT / "configs/experiments.json").read_text())
    training = json.loads((ROOT / config["training_config"]).read_text())
    training.update(pilot_only=False, confirmatory_frozen=True)
    hashes = {f"{distribution}/org_{number:02d}.csv": digest([distribution, number])
        for distribution in ("iid", "non_iid") for number in range(1, 9)}
    hashes.update({name: digest(name) for name in ("preprocessor.json", "test.csv", "validation.csv")})
    data = {"private_artifacts_sha256": hashes, "checks": {key: True for key in
        ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")}}
    provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "git_commit": None,
        "image_digests": {"runtime": "111111111111.dkr.ecr.us-east-1.amazonaws.com/pcfl-test/runtime@sha256:" + "b" * 64}}
    plan = build_plan(config, training, data, provenance)
    attempts = [example_attempt(plan)]
    output = root / "release"
    manifest = release.create_release(plan, attempts, output, artifact_version="synthetic-replay-v1", source_root=root)
    return root, output, plan, attempts, manifest


def run(output):
    # Only the release's verified source archive supplies pcfl in this process.
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    return subprocess.run([sys.executable, "-I", str(output / "reproduce.py")], cwd=output.parent,
        env=env, capture_output=True, text=True, timeout=45)


class ReleaseIntegrityTests(unittest.TestCase):
    def test_complete_current_scientific_source_archive_accepts_staged_frozen_overlay(self):
        staged = Path(release.__file__).parent
        overlay = {"scripts/release_research.py": staged / "release_research.py", "scripts/public_release.py": staged / "public_release.py",
            "scripts/prepare_release_attachments.py": staged / "prepare_release_attachments.py", "tests/test_finalization.py": staged / "test_finalization.py",
            "tests/test_release_integrity.py": Path(__file__), "tests/test_public_attachments.py": staged / "test_public_attachments.py"}
        overlay = {name: path if path.is_file() else ROOT / name for name, path in overlay.items()}
        sources = scientific_sources(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in sorted(set(sources) | set(overlay)):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(overlay.get(name, ROOT / name).read_bytes())
            expected = scientific_sources(root)
            plan = {"provenance": {"source_files_sha256": expected, "source_sha256": digest(expected)}}
            output = root / "public-package"; output.mkdir()
            manifest = release.source_archive(plan, output, "synthetic-full-source-test", root=root)
            self.assertEqual(set(manifest["frozen_executable_files_sha256"]), set(expected))
            self.assertFalse(manifest["credentials_included"])

    def test_actual_reporter_tree_prepares_attachments_and_releases_preserved_links(self):
        from pcfl.analysis import analyze_registry
        from report_final_artifacts import generate
        from prepare_release_attachments import prepare
        with tempfile.TemporaryDirectory() as directory:
            root, _, candidate, _, _ = fixture(directory)
            plan = freeze_plan(candidate, synthetic_gate_refs(candidate, root), root)
            attempts = [example_attempt(plan)]
            plan_path = root / "plan.json"; plan_path.write_bytes(canonical(plan) + b"\n")
            ledger = root / "attempts.jsonl"
            append_attempt(ledger, plan, attempts[0])
            aggregate = root / "aggregate.json"; aggregate.write_bytes(canonical(attempts) + b"\n")
            analysis_path = root / "analysis.json"
            analysis_path.write_text(json.dumps(analyze_registry(plan, attempts), sort_keys=True, indent=2) + "\n")
            figures = root / "figures"; figures.mkdir()
            figure = figures / "invalid_incorporation_by_scenario.svg"
            figure.write_text('<svg xmlns="http://www.w3.org/2000/svg"><text>synthetic fixture</text></svg>')
            figure_manifest = figures / "figures_manifest.json"
            figure_manifest.write_text(json.dumps({"schema_version": "0.1.0", "kind": "reproducible-descriptive-research-figures",
                "plan_digest": plan["plan_digest"], "all_attempts_retained": len(attempts),
                "files": [{"path": figure.name, "sha256": file_digest(figure)}],
                "input_sha256": {"plan": file_digest(plan_path), "attempts": file_digest(aggregate), "analysis": file_digest(analysis_path)}}))
            reporting = root / "reporting-drafts"
            generate(plan_path, ledger, analysis_path, reporting, evidence_root=root,
                figure_manifest=figure_manifest, figure_attempts=aggregate)
            spec = prepare(plan, attempts, reporting / "reporting_manifest.json", figure_manifest, "actual-synthetic-test-v1", root=root)
            output = root / "detailed-release"
            manifest = release.create_release(plan, attempts, output, artifact_version="actual-synthetic-test-v1", source_root=root, attachments=spec)
            self.assertTrue(manifest["public_attachments_complete"])
            self.assertFalse(manifest["all_phases_complete"])
            self.assertEqual((output / "reporting/claim_evidence_matrix.json").read_bytes(), (reporting / "claim_evidence_matrix.json").read_bytes())
            self.assertTrue((output / "reporting/figures/figures_manifest.json").is_file())
            result = run(output)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_clean_release_reproduces_exact_outputs_and_can_be_rechecked(self):
        with tempfile.TemporaryDirectory() as directory:
            _, output, _, _, manifest = fixture(directory)
            self.assertFalse(manifest["all_phases_complete"])
            first = run(output)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse(json.loads(first.stdout)["private_model_audit_replayed"])
            self.assertEqual((output / "analysis.json").read_bytes(), (output / "reproduced/analysis.json").read_bytes())
            second = run(output)
            self.assertEqual(second.returncode, 0, second.stderr)

    def test_schema_valid_aggregate_metric_tamper_is_detected_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            _, output, _, _, _ = fixture(directory)
            path = output / "aggregate_attempts.json"
            rows = json.loads(path.read_text()); rows[0]["metrics"]["auroc"] = .81
            path.write_text(json.dumps(rows))
            result = run(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("released_file_digest_mismatch:aggregate_attempts.json", result.stderr)

    def test_locked_plan_input_byte_drift_is_detected_even_when_json_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            _, output, _, _, _ = fixture(directory)
            path = output / "locked_plan.json"
            path.write_bytes(path.read_bytes() + b" ")
            result = run(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("released_file_digest_mismatch:locked_plan.json", result.stderr)

    def test_regenerated_analysis_mismatch_is_detected_after_retained_hash_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            _, output, _, _, manifest = fixture(directory)
            path = output / "analysis.json"
            report = json.loads(path.read_text()); report["hypotheses"]["H4"]["verdict"] = "supported"
            path.write_text(json.dumps(report))
            manifest["files_sha256"][path.name] = file_digest(path)
            manifest["analysis_files_sha256"][path.name] = file_digest(path)
            (output / "release_manifest.json").write_text(json.dumps(manifest))
            result = run(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regenerated_analysis_mismatch:analysis.json", result.stderr)

    def test_regenerated_table_mismatch_is_detected_after_retained_hash_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            _, output, _, _, manifest = fixture(directory)
            path = output / "governance.csv"
            path.write_bytes(path.read_bytes() + b"unexpected-extra-table-row\n")
            manifest["files_sha256"][path.name] = file_digest(path)
            manifest["analysis_files_sha256"][path.name] = file_digest(path)
            (output / "release_manifest.json").write_text(json.dumps(manifest))
            result = run(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regenerated_analysis_mismatch:governance.csv", result.stderr)

    def test_archive_drift_and_missing_analysis_binding_do_not_pass(self):
        for mutation in ("archive", "analysis-binding"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                _, output, _, _, manifest = fixture(directory)
                if mutation == "archive":
                    path = output / manifest["public_source_archive"]
                    path.write_bytes(path.read_bytes() + b"changed")
                else:
                    del manifest["analysis_files_sha256"]["analysis.json"]
                    (output / "release_manifest.json").write_text(json.dumps(manifest))
                result = run(output)
                self.assertNotEqual(result.returncode, 0)

    def test_private_catalog_contains_only_ids_hashes_and_placeholder_replay_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root, output, _, attempts, _ = fixture(directory)
            catalog = json.loads((output / "private_replay_catalog.json").read_text())
            self.assertFalse(catalog["catalog_establishes_replay_success"])
            self.assertFalse(catalog["private_artifacts_in_public_bundle"])
            self.assertEqual(catalog["runs"][0]["attempt_id"], attempts[0]["attempt_id"])
            self.assertIn("<trusted-DER-SHA256>", catalog["complete_replay_command"])
            self.assertNotIn(str(root), json.dumps(catalog))
            self.assertIn("--holdout-authorization", catalog["complete_replay_command"])


if __name__ == "__main__": unittest.main()
