"""Synthetic wire/metadata fixtures only; no actual clinical reporting or AWS."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "scripts/report_final_artifacts.py").is_file())
STAGE = Path(__file__).resolve().parent
sys.path[:0] = [str(STAGE), str(ROOT / "scripts"), str(ROOT / "tests"), str(ROOT / "src")]
import robustness_reporting as reader


def write(root, name, value):
    path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, allow_nan=False))
    import hashlib
    return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def fixture(root, *, statuses=("successful", "failed", "unattempted"), plan_digest="a" * 64):
    """Wire-shaped positive contract, never a real protection/clinical claim."""
    sources, cases, attempts, indexed = [], [], [], []
    for number, status in enumerate(statuses):
        vector = {**reader.DEFAULTS, "artificial_latency_ms": [0, 250, 1000][number % 3]}
        descriptor = {"schema_version": "0.1.0", "protocol_id": "pcfl-exploratory-robustness-v1", "factors": vector,
            "seed": 296, "data_manifest_digest": "b" * 64, "reference_main_plan_digest": plan_digest,
            "adapter_source_sha256": "c" * 64, "adapter_image": "example.invalid/test-fixture@sha256:" + "d" * 64,
            "evaluation_split": "validation", "final_test_access_permitted": False, "confirmatory": False}
        descriptor["descriptor_digest"] = reader.digest(descriptor)
        identity = "exploratory-" + reader.digest([descriptor, "iid"])[:24]
        sources.append({"case_id": identity, "deployment_group": "group-test", "seed": 296, "distribution": "iid",
            "robustness": descriptor, "architecture": {"float32_parameter_bytes": 4000}, "status": "registered_not_run", "actual_cloud_trial": False})
        case = {"case_id": identity, "group_id": "group-test", "seed": 296, "distribution": "iid", "factors": vector,
            "factor_levels": reader.factor_levels(vector), "adapter_source_sha256": descriptor["adapter_source_sha256"],
            "adapter_image": descriptor["adapter_image"], "reference_main_plan_digest": plan_digest,
            "status": status, "attempt_ids": [], "metrics": None}
        cases.append(case)
        if status == "unattempted": continue
        metrics = {name: 0 for name in reader.COUNTS}
        metrics.update(assigned_tasks=40, acknowledged_tasks=40, presented_updates=40, accepted_updates=30, rejected_updates=10,
            final_decisions=40, audit_complete_decisions=40, published_models=5, oracle_invalid_presented=10,
            validation_metrics={"count": 10, "positive_count": 2, "prevalence": .2, "auroc": .75, "auprc": .5,
                "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7},
            round_durations_ms=[100, 110, 120, 130, 140],
            actual_selected_per_round=[{"round_id": f"round-{r}", "org_ids": [f"org_{n:02d}" for n in range(1, 9)],
                "selected_count": 8, "accepted_count": 6} for r in range(1, 6)],
            parameter_bytes=4000, configured_reply_delay_ms=vector["artificial_latency_ms"], reported_clock_offsets_ms=[0] * 40)
        success = status == "successful"
        raw = {"kind": "exploratory_robustness_validation", "persistent_run_id": "synthetic-wire-run-" + str(number),
            "cell_id": identity, "cloud_campaign_id": "synthetic-wire-application", "robustness": descriptor,
            "seed": 296, "distribution": "iid", "registered_primary_case": False, "test_holdout_evaluated": False,
            "aws_used": True, "successful": success, "fixture_only_not_actual_clinical_evidence": True}
        raw_ref = write(root, f"raw-{number}.json", raw)
        exact = {"bucket": "synthetic-test-bucket", "key": f"evidence/campaigns/synthetic-wire-application/{identity}/runtime_result.json",
            "version_id": "synthetic-wire-v1", "sha256": raw_ref["sha256"], "size_bytes": (root / raw_ref["path"]).stat().st_size}
        attempt = {"attempt_id": "synthetic-attempt-" + str(number), "case_id": identity,
            "application_campaign_id": "synthetic-wire-application", "run_id": raw["persistent_run_id"], "index": None,
            "raw_result": exact, "execution_successful": success, "verification": {key: success for key in reader.VERIFICATION},
            "status": status, "reason": "synthetic-unit-fixture-not-real-evidence", "metrics": metrics if success else None,
            "evidence_refs": [raw_ref]}
        attempts.append(attempt)
        case["attempt_ids"] = [attempt["attempt_id"]]
        if success: case["metrics"] = deepcopy(metrics)
        indexed.append({"cell_id": identity, "successful": success, "artifacts": [deepcopy(exact)]})
    index_ref = write(root, "producer-index.json", {"campaign_id": "synthetic-wire-application", "cases": indexed})
    index = {"bucket": "synthetic-test-bucket", "key": "evidence/campaigns/synthetic-wire-application/campaign_result.json",
        "version_id": "synthetic-index-v1", "sha256": index_ref["sha256"], "size_bytes": (root / index_ref["path"]).stat().st_size}
    for attempt in attempts:
        attempt["index"] = deepcopy(index); attempt["evidence_refs"].append(index_ref)
        attempt["attempt_id"] = "exploratory-attempt-" + reader.digest([index, attempt["case_id"]])[:32]
    for case in cases:
        case["attempt_ids"] = [row["attempt_id"] for row in attempts if row["case_id"] == case["case_id"]]
    excluded = [{"seed": 296, "distribution": "non_iid", "factors": {**reader.DEFAULTS, "non_iid_alpha": .1},
        "status": "failed_preparation", "actual_cloud_trial": False, "evidence": {"constraints_weakened": False, "retry_limit": 200}}]
    registry = {"schema_version": "0.1.0", "kind": "exploratory-robustness-registry", "reference_main_plan_digest": plan_digest,
        "cases": sources, "excluded_preparation_attempts": excluded, "independent_seed_count": 1,
        "actual_cloud_trials_executed": 0, "final_holdout_accessed": False, "execution_authorized": False}
    registry["registry_digest"] = reader.digest(registry)
    registry_ref = write(root, "registry.json", registry)
    return {"schema_version": "0.1.0", "kind": reader.KIND, "plan_digest": plan_digest, "registry_digest": registry["registry_digest"],
        "normalization_complete": True, "successful": all(row["status"] == "successful" for row in cases), "independent_seed_count": 1,
        "confirmatory": False, "evaluation_split": "validation", "final_test_accessed": False, "data_kind": "clinical",
        "inputs": [registry_ref], "cases": cases, "attempts": attempts, "excluded_preparation_attempts": excluded,
        "limitations": ["Synthetic test wire contract; never real clinical, AWS or protected evidence"]}


def normalize(report, root):
    return reader.normalize(report, root=root, plan_digest=report["plan_digest"], report_alias="test-summary", report_sha256="e" * 64)


class RobustnessReportingTests(unittest.TestCase):
    def test_success_failed_unattempted_and_shared_control_are_descriptive_with_no_ci(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = fixture(root); normalized = normalize(report, root)
            self.assertEqual([row["status"] for row in normalized["cases"]], ["successful", "failed", "unattempted"])
            self.assertEqual(normalized["independent_seed_count"], 1)
            self.assertFalse(normalized["confirmatory"])
            self.assertTrue(all(row["confidence_interval"] is None and row["effect"] is None for row in normalized["cases"]))
            self.assertIsNone(normalized["cases"][1]["metrics"])
            self.assertIsNone(normalized["cases"][2]["metrics"])
            self.assertEqual(len(normalized["cases"][0]["factor_levels"]), 6)
            self.assertEqual(len(normalized["excluded_preparation_attempts"]), 1)
            self.assertIsNone(reader.descriptive_row(normalized["cases"][2])["accepted_updates"])
            self.assertEqual(reader.descriptive_row(normalized["cases"][0])["validation_auroc"], .75)

    def test_synthetic_confirmatory_test_split_or_wrong_seed_cannot_enter_clinical_supplement(self):
        for mode in ("synthetic", "confirmatory", "test", "seeds", "seed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); report = fixture(root)
                if mode == "synthetic": report["data_kind"] = "synthetic_test"
                elif mode == "confirmatory": report["confirmatory"] = True
                elif mode == "test": report["evaluation_split"] = "test"
                elif mode == "seeds": report["independent_seed_count"] = 5
                else: report["cases"][0]["seed"] = 593
                with self.assertRaises(ValueError): normalize(report, root)

    def test_missing_planned_case_failed_preparation_or_changed_factor_image_and_group_is_rejected(self):
        for mode in ("omitted-case", "omitted-preparation", "factor", "image", "source", "group", "run"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); report = fixture(root)
                if mode == "omitted-case": report["cases"].pop()
                elif mode == "omitted-preparation": report["excluded_preparation_attempts"] = []
                elif mode == "factor": report["cases"][0]["factors"]["participation_fraction"] = .5
                elif mode == "image": report["cases"][0]["adapter_image"] = "other@sha256:" + "f" * 64
                elif mode == "source": report["cases"][0]["adapter_source_sha256"] = "f" * 64
                elif mode == "group": report["cases"][0]["group_id"] = "foreign-group"
                else: report["attempts"][0]["run_id"] = "different-run"
                with self.assertRaises(ValueError): normalize(report, root)

    def test_unprotected_numeric_claim_wrong_version_and_changed_evidence_fail_closed(self):
        for mode in ("protected", "version", "bytes", "metric-rows", "payload"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); report = fixture(root)
                if mode == "protected": report["attempts"][0]["verification"]["protected_witness"] = False
                elif mode == "version": report["attempts"][0]["raw_result"]["version_id"] = "unindexed-version"
                elif mode == "bytes": (root / "raw-0.json").write_text("{}")
                elif mode == "metric-rows": report["attempts"][0]["metrics"]["validation_metrics"]["labels"] = [1]
                else: report["attempts"][0]["metrics"]["parameter_bytes"] = 8000; report["cases"][0]["metrics"]["parameter_bytes"] = 8000
                with self.assertRaises(ValueError): normalize(report, root)

    def test_multiple_attempts_cannot_select_favorable_case_metrics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = fixture(root, statuses=("successful",))
            duplicate = deepcopy(report["attempts"][0]); duplicate["index"]["version_id"] = "synthetic-second-index-version"
            duplicate["attempt_id"] = "exploratory-attempt-" + reader.digest([duplicate["index"], duplicate["case_id"]])[:32]
            report["attempts"].append(duplicate)
            report["cases"][0].update(status="multiple-attempts", attempt_ids=[row["attempt_id"] for row in report["attempts"]], metrics=None)
            report["successful"] = False
            result = normalize(report, root)
            self.assertEqual(len(result["attempts"]), 2)
            self.assertIsNone(result["cases"][0]["metrics"])
            report["cases"][0]["metrics"] = deepcopy(duplicate["metrics"])
            with self.assertRaisesRegex(ValueError, "metric_selection"): normalize(report, root)

    def test_actual_normalizer_partial_fixture_matches_reader_contract_without_any_clinical_success(self):
        from test_summarize_robustness import fixture as producer_fixture
        import summarize_robustness
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); spec, registry = producer_fixture(root, producer_failure=True)
            report = summarize_robustness.normalize(root / spec["path"], evidence_root=root)
            result = normalize(report, root)
            self.assertFalse(result["successful"])
            self.assertEqual(len(result["attempts"]), 1)
            self.assertEqual(result["attempts"][0]["status"], "failed")
            self.assertTrue(all(row["metrics"] is None for row in result["cases"]))

    def test_private_array_row_or_private_key_inputs_are_rejected_before_reporting(self):
        for suffix, content in ((".csv", b"synthetic-row-fixture"), (".npz", b"synthetic-array-fixture"), (".pem", b"-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-key")):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); report = fixture(root)
                target = root / ("forbidden" + suffix); target.write_bytes(content)
                report["inputs"].append({"path": target.name, "sha256": "f" * 64})
                with self.assertRaisesRegex(ValueError, "aggregate_json_or_public_key|public_key_only"):
                    normalize(report, root)

    def test_duplicate_summary_snapshots_cannot_silently_select_favorable_registry_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = fixture(root); ref = write(root, "summary.json", report)
            evidence = [{**ref, "alias": name, "kind": reader.KIND, "category": "exploratory"} for name in ("first", "second")]
            with self.assertRaisesRegex(ValueError, "duplicate_exploratory_registry"):
                reader.collect(evidence, root=root, plan_digest=report["plan_digest"])

    def test_staged_reporter_materializes_case_attempt_axis_tables_without_changing_primary_analysis(self):
        from test_report_final_artifacts import ReportingTests
        context = ReportingTests(); context.setUp(); self.addCleanup(context.doCleanups)
        report = fixture(context.root, plan_digest=context.plan["plan_digest"])
        index, _ = context.evidence(report, category="exploratory", alias="exploratory-summary")
        reporter_path = STAGE / "report_final_artifacts.py"
        if not reporter_path.is_file(): reporter_path = ROOT / "scripts/report_final_artifacts.py"
        spec = importlib.util.spec_from_file_location("staged_robustness_reporter", reporter_path)
        reporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(reporter)
        output = context.root / "report-output"
        manifest = reporter.generate(context.plan_path, context.ledger, context.analysis_path, output,
            evidence_root=context.root, evidence_index=index)
        self.assertFalse(manifest["all_phases_complete"])
        self.assertFalse(manifest["clinical_confirmatory_verdict_permitted"])
        self.assertEqual(manifest["attempt_count"], 0)
        self.assertEqual(manifest["exploratory_attempt_count"], 2)
        self.assertIn("exploratory-cases-unattempted-failed-or-ambiguous", manifest["pending"])
        cases = json.loads((output / "supplements/exploratory_cases.json").read_text())["rows"]
        self.assertEqual(len(cases), 3)
        self.assertIsNone(cases[-1]["metrics"])
        axes = json.loads((output / "supplements/exploratory_factor_levels.json").read_text())["rows"]
        self.assertEqual(sum(row["shared_default_control"] for row in axes), 6)
        self.assertEqual(len({row["independent_observation_id"] for row in axes}), 3)
        self.assertTrue(all(row["confidence_interval"] is None for row in axes))
        claims = json.loads((output / "claim_evidence_matrix.json").read_text())
        claim = next(row for row in claims if row["component"] == "separately-normalized-ofat-robustness")
        self.assertFalse(claim["clinical_confirmatory_claim_permitted"])
        self.assertEqual(claim["verdict"], "descriptive-only")
        self.assertEqual(claim["statistical_result"]["independent_seed_count"], 1)
        for link in claim["table_links"]: self.assertTrue((output / link["path"]).is_file())


if __name__ == "__main__": unittest.main()
