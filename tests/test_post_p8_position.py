"""Synthetic chronology contracts only; no AWS or clinical execution."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(path for path in STAGE.parents if (path / "pyproject.toml").is_file())
V2 = STAGE.parent / "v2" if (STAGE.parent / "v2").is_dir() else ROOT / "tests"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(V2))
import test_remaining_campaign_forecast as fixture_module
import forecast_remaining_campaign as previous
sys.path.insert(0, str(STAGE))
import post_p8_position as position
HELPER = STAGE / "forecast_remaining_campaign.py" if (STAGE / "forecast_remaining_campaign.py").is_file() else ROOT / "scripts/forecast_remaining_campaign.py"
spec = importlib.util.spec_from_file_location("position_forecast", HELPER)
forecast = importlib.util.module_from_spec(spec); spec.loader.exec_module(forecast)
write, digest = fixture_module.write, fixture_module.digest


def safety():
    rows, hashes = [], {}
    for distribution in forecast.DISTRIBUTIONS:
        for scenario, seed in [*((f"S{n}", 296) for n in range(4, 9)), ("S8", 593)]:
            cell = f"synthetic-safety-{distribution}-{scenario}-{seed}"
            hashes[cell] = digest(cell)
            row = {"cell_id": cell, "distribution": distribution, "scenario": scenario, "seed": seed,
                "baseline": "P1", "raw_result_sha256": hashes[cell], "anchored": True, "test_accessed": False,
                "execution_successful": scenario != "S8", "summary": {"successful": True,
                    "persistent_protocol_verified": True, "runtime_observations_verified": True}}
            if scenario == "S8":
                row.update(scripted_fault="audit_transport_unavailable" if seed == 593 else "opa_transport_unavailable",
                    partial={"protected_witness_verified": True, "attempt_accounting_complete": True,
                        "indeterminate_count": 0, "audit_complete_for_all_final_outcomes": True,
                        "final_audit_expected_count": 8, "final_audit_recorded_count": 8},
                    fault_trace=[{"phase": "fault_failed_closed", "pointer_unchanged": True,
                        "published_models_during_fault": 0, "recovery_errors": [], "blocked_calls": 1}])
            rows.append(row)
    return rows, hashes


class PositionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture_module.ForecastTests(); self.f.setUp()
        self.f.batch("iid"); self.f.batch("non_iid")
        self.root, self.doc, self.cost = self.f.root, self.f.doc, self.f.cost
        self.rows, hashes = safety()
        self.plan = json.loads(Path(self.doc["plan"]["path"]).read_text())
        self.plan["provenance"] = {"source_files_sha256": {"scripts/post_p8_position.py": forecast.sha(position.__file__)},
            "image_digests": {"runtime": "synthetic/own@" + self.f.image}}
        self.plan.pop("plan_digest"); self.plan["plan_digest"] = digest(self.plan)
        self.doc["plan"] = write(self.root / "plan.json", self.plan)
        self.doc.update(forecast_position=position.POSITION, pending_safety_pilot_cases=0,
            completed_safety_raw_sha256=hashes)
        self.doc["operational_allowances"].update(application_launches=13, remaining_deployments=2,
            bounded_fault_events=30, additional_bootstrap_export_collection_seconds=7200)
        self.old = {"campaign_id": "retired-pilot", "account_id": self.f.account, "region": self.f.region,
            "project_id": "pcfl-retired", "teardown_complete": True,
            "task_arns": list(self.cost["resources"]["tasks"]),
            "retained_artifact_versions": [{"sha256": row["raw_result_sha256"], "version_id": "synthetic-version",
                "key": f"evidence/campaigns/synthetic/{row['cell_id']}/runtime_result.json"} for row in self.rows]}
        self.current = {"campaign_id": "fresh-main", "application_campaign_id": "fresh-main-g1",
            "account_id": self.f.account, "region": self.f.region, "project_id": "pcfl-main",
            "deployment_started_at": "2026-11-13T09:40:00Z", "task_arns": ["synthetic-fresh-G1-task"]}
        self.cost.update(campaign_id="fresh-main", as_of_utc="2026-11-13T10:00:00Z")
        self.cost["resources"]["tasks"]["synthetic-fresh-G1-task"] = {"synthetic_fixture": True}
        self.cost["resources"]["deployments"] = [
            {"campaign_id": "retired-pilot", "elapsed_hours": 4, "finished_at": "2026-11-13T09:31:00Z"},
            {"campaign_id": "fresh-main", "elapsed_hours": 1 / 3, "finished_at": None}]
        manifest = write(self.root / "scope-manifest.json", {"kind": "synthetic-snapshot-only"})
        self.request = {"kind": "frozen-campaign-cost-request", "account_id": self.f.account, "region": self.f.region,
            "campaign_id": "fresh-main", "authorization": self.doc["authorization"],
            "cost_scope_snapshot": {"schema_version": "0.1.0", "kind": "campaign-cost-scope-snapshot",
                "manifest": manifest, "execution_disabled": True}}
        self.campaign = {"campaign_id": "fresh-main-g1", "cases": [{"cell_id": "synthetic-G1",
            "runtime": {"rounds": 1, "max_examples": 64, "validation_max_examples": 128}}]}
        key_path = self.root / "public.pem"; key_path.write_text("-----BEGIN PUBLIC KEY-----\nSYNTHETIC\n-----END PUBLIC KEY-----\n")
        key = forecast.ref(key_path)
        self.doc["post_p8_connectivity"] = {"cost_request": None,
            "g1": {"inventory": None, "campaign": None, "witness_public_key": key,
                "expected_public_key_sha256": self.f.pin}, "retired_pilot_campaigns": [],
            "contingency_allowances": {"extra_application_launches": 0, "extra_fault_events": 0, "extra_g1_cases": 0}}
        metadata = {"metadata_digest": "a" * 64, "model_schema_hash": "b" * 64, "hidden_dims": [64, 32]}
        self.f.manifest["private_artifacts_sha256"] = {"validation.csv": "c" * 64}
        self.doc["base_data_manifest"] = write(self.root / "base.json", self.f.manifest)
        self.campaign["cases"][0]["runtime"].update(max_examples_per_client=64, baseline_id="P1", scenario_id="S0",
            distribution="iid", seed=296, persistent_run_id="synthetic-g1-run", model_metadata=metadata,
            validation_source_sha256="c" * 64)
        self.raw = {"persistent_run_id": "synthetic-g1-run", "rounds": [{}], "test_holdout_evaluated": False,
            "cell_id": "synthetic-G1", "cloud_campaign_id": "fresh-main-g1", "successful": True, "aws_used": True,
            "baseline_id": "P1", "scenario_id": "stable", "seed": 296,
            "model_metadata_digest": metadata["metadata_digest"], "model_schema_hash": metadata["model_schema_hash"],
            "client_training": [{"org_id": f"org_{n:02d}", "sample_count": 64, "round_id": "round-1",
                "optimizer": "adam", "epochs": 1, "example_exposures": 64, "batches": 1, "seed": 395 + n} for n in range(1, 9)],
            "validation_metrics": {"count": 128}, "case_started_at_utc": "2026-11-13T09:45:00Z",
            "case_finished_at_utc": "2026-11-13T09:50:00Z"}
        self.native = {"successful": True, "placement_successful": True, "image_reference": self.plan["provenance"]["image_digests"]["runtime"],
            "exported_cases": 1, "all_case_outcomes_retained": True,
            "rows": [{"cell_id": "synthetic-G1", "raw_result_sha256": digest(self.raw), "anchored": True,
                "execution_successful": True, "test_accessed": False, "baseline": "P1", "scenario": "S0", "facts": {"partitions": True},
                "summary": {key: True for key in ("successful", "persistent_protocol_verified",
                    "committed_evaluation_response_verified", "runtime_observations_verified")}}]}
        self.isolation = {"placement_successful": True, "placement": {"source_snapshot_integrity": True,
            "eight_distinct_learning_clients": True}, "image_reference": self.native["image_reference"]}
        self.readback = {"kind": "actual-aws-campaign-teardown-validation", "successful": True, "performed_read_only": True,
            **{key: self.old[key] for key in ("account_id", "region", "campaign_id", "project_id")},
            "checked_at_utc": "2026-11-13T09:31:00Z", "checks": {key: True for key in position.CHECKS}}
        self.bind()

    def bind(self):
        proof = self.doc["post_p8_connectivity"]
        proof["cost_request"] = write(self.root / "frozen-cost-request.json", self.request)
        current = write(self.root / "current-inventory.json", self.current)
        old = write(self.root / "retired-inventory.json", self.old)
        proof["g1"]["inventory"] = current
        proof["g1"]["campaign"] = write(self.root / "g1-campaign.json", self.campaign)
        self.readback["inventory_sha256"] = old["sha256"]
        proof["retired_pilot_campaigns"] = [{"inventory": old,
            "readback": write(self.root / "readback.json", self.readback)}]
        self.scope_inputs = [proof["cost_request"], current, old, self.doc["authorization"],
            write(self.root / "successor-ledger.json", {"tasks": {key: {} for key in self.cost["resources"]["tasks"]}})]
        self.cost["source_inputs"] = [self.doc["authorization"], *self.scope_inputs,
            *(batch["inventory"] for batch in self.doc["pilot_batches"])]
        self.doc["priced_usage"] = write(self.root / "cost.json", self.cost)

    def tearDown(self): self.f.tearDown()

    def generate(self):
        self.bind()
        ledger = {"tasks": {key: {} for key in self.cost["resources"]["tasks"]}}
        scope = (self.request, self.f.authorization, ledger,
            {self.old["campaign_id"]: self.old, self.current["campaign_id"]: self.current}, self.scope_inputs)
        self.native["rows"][0]["raw_result_sha256"] = digest(self.raw)
        cases = [("synthetic-G1", self.root, self.raw, digest(self.raw))]
        with patch.object(position, "_cost_scope", return_value=scope), patch.object(position, "_native_g1",
                return_value=(self.native, self.isolation, cases)):
            return forecast.generate(self.doc, base=self.root, project_root=self.root, verified_safety_rows=self.rows)

    def test_default_no_position_is_exact_previous_292_behavior(self):
        document = deepcopy(self.doc)
        document.pop("forecast_position"); document.pop("post_p8_connectivity")
        document["pending_safety_pilot_cases"] = 12
        document["operational_allowances"].update(application_launches=16, remaining_deployments=3,
            bounded_fault_events=36, additional_bootstrap_export_collection_seconds=10800)
        self.assertEqual(forecast.generate(document, base=self.root), previous.generate(document, base=self.root))

    def test_position_279_current_main_plus_two_new_projects_and_no_acceptance_cycle(self):
        result = self.generate()
        self.assertTrue(result["forecast_ready"])
        self.assertEqual(result["total_remaining_work"], 279)
        self.assertEqual(result["work_counts"], forecast.COUNTS)
        self.assertEqual(result["operational_allowances"]["minimum_application_groups"], 13)
        self.assertEqual(result["operational_allowances"]["remaining_deployments"], 2)
        self.assertEqual(result["operational_allowances"]["additional_bootstrap_export_collection_seconds"], 7200)
        projects = {row["project_group"]: row for row in result["deployment_schedule"]["projects"]}
        self.assertEqual(set(projects), {"current-main-P9", "fresh-P10-exploratory", "fresh-replica"})
        self.assertEqual(projects["current-main-P9"]["already_elapsed_project_hours"], 1 / 3)
        self.assertEqual(projects["current-main-P9"]["new_project_bootstrap_allowance_hours"], 0)
        self.assertEqual(sum(row["new_project_bootstrap_allowance_hours"] for row in projects.values()), 2)
        self.assertFalse(result["position_evidence"]["P8_acceptance_required_before_this_cost_check"])
        self.assertFalse(result["execution_authorized"])

    def test_explicit_extra_G1_launch_and_fault_contingencies_stay_outside_scientific_count(self):
        base = self.generate()
        self.doc["post_p8_connectivity"]["contingency_allowances"].update(extra_application_launches=3,
            extra_fault_events=6, extra_g1_cases=1)
        self.doc["operational_allowances"].update(application_launches=16, bounded_fault_events=36)
        result = self.generate()
        self.assertEqual(result["total_remaining_work"], 279)
        self.assertGreater(result["operational_allowances"]["unallocated_contingency_G1_full_case_seconds"], 0)
        self.assertGreater(result["priced_comparison"]["models"]["stratified"]["projected_total_usd"],
            base["priced_comparison"]["models"]["stratified"]["projected_total_usd"])

    def test_missing_or_indeterminate_safety_cannot_be_marked_past(self):
        for mode in ("pending", "missing", "indeterminate"):
            with self.subTest(mode=mode):
                saved = deepcopy(self.rows)
                if mode == "pending": self.doc["pending_safety_pilot_cases"] = 12
                elif mode == "missing": self.rows.pop()
                else: next(row for row in self.rows if row["scenario"] == "S8")["partial"]["indeterminate_count"] = 1
                with self.assertRaises(ValueError): self.generate()
                self.rows = saved; self.doc["pending_safety_pilot_cases"] = 0

    def test_live_request_or_foreign_current_cost_scope_or_old_project_reuse_rejected(self):
        for mode in ("live", "enabled", "wrongcost", "reusedproject", "beforeteardown"):
            with self.subTest(mode=mode):
                request, current, cost = deepcopy(self.request), deepcopy(self.current), deepcopy(self.cost)
                if mode == "live": self.request["kind"] = "campaign-request"
                elif mode == "enabled": self.request["cost_scope_snapshot"]["execution_disabled"] = False
                elif mode == "wrongcost": self.cost["campaign_id"] = "retired-pilot"
                elif mode == "reusedproject": self.current["project_id"] = self.old["project_id"]
                else: self.current["deployment_started_at"] = "2026-11-13T09:00:00Z"
                with self.assertRaises(ValueError): self.generate()
                self.request, self.current, self.cost = request, current, cost

    def test_incomplete_false_or_misbound_terminal_readback_rejected(self):
        for mode in ("false", "truthy", "wrongscope"):
            with self.subTest(mode=mode):
                saved = deepcopy(self.readback)
                if mode == "false": self.readback["checks"]["foundation_removed"] = False
                elif mode == "truthy": self.readback["checks"]["foundation_removed"] = 1
                else: self.readback["project_id"] = "stranger"
                with self.assertRaises(ValueError): self.generate()
                self.readback = saved

    def test_unprotected_failed_wrong_source_or_nonG1_clinical_budget_rejected(self):
        for mode in ("unprotected", "failed", "source", "sample", "validation", "test"):
            with self.subTest(mode=mode):
                native, raw = deepcopy(self.native), deepcopy(self.raw)
                if mode == "unprotected": self.native["rows"][0]["anchored"] = False
                elif mode == "failed": self.native["successful"] = False
                elif mode == "source": self.isolation["placement"]["source_snapshot_integrity"] = False
                elif mode == "sample": self.raw["client_training"][0]["sample_count"] = 63
                elif mode == "validation": self.raw["validation_metrics"]["count"] = 127
                else: self.raw["test_holdout_evaluated"] = True
                with self.assertRaises(ValueError): self.generate()
                self.native, self.raw = native, raw
                self.isolation["placement"]["source_snapshot_integrity"] = True

    def test_missing_explicit_reserves_or_expired_current_project_cannot_pass(self):
        self.doc["operational_allowances"]["application_launches"] = 16
        with self.assertRaisesRegex(ValueError, "13_science_groups"): self.generate()
        self.doc["operational_allowances"]["application_launches"] = 13
        self.cost["resources"]["deployments"][1]["elapsed_hours"] = 23.9
        self.assertFalse(self.generate()["deployment_schedule"]["all_project_expiries_feasible"])

    def test_safety_custody_and_historical_orphan_cannot_leave_priced_scope(self):
        self.old["retained_artifact_versions"].pop()
        with self.assertRaisesRegex(ValueError, "safety_raw"): self.generate()
        self.old["retained_artifact_versions"] = [{"sha256": row["raw_result_sha256"], "version_id": "synthetic-version",
            "key": f"evidence/synthetic/{row['cell_id']}/runtime_result.json"} for row in self.rows]
        self.old["task_arns"].pop()
        with self.assertRaisesRegex(ValueError, "tasks_must_remain_priced"): self.generate()

    def test_stale_G1_cost_and_closed_current_project_are_rejected(self):
        self.cost["as_of_utc"] = "2026-11-13T09:49:00Z"
        with self.assertRaisesRegex(ValueError, "64_128"): self.generate()
        self.cost["as_of_utc"] = "2026-11-13T10:00:00Z"
        self.cost["resources"]["deployments"][1]["finished_at"] = "2026-11-13T09:55:00Z"
        with self.assertRaisesRegex(ValueError, "CURRENT_MAIN"): self.generate()

    def test_G1_identity_and_model_metadata_must_match_actual_source_configuration(self):
        for mode in ("run", "metadata", "cell", "baseline", "futurestart"):
            with self.subTest(mode=mode):
                raw = deepcopy(self.raw)
                if mode == "run": self.raw["persistent_run_id"] = "some-other-run"
                elif mode == "metadata": self.raw["model_metadata_digest"] = "d" * 64
                elif mode == "cell": self.raw["cell_id"] = "some-other-case"
                elif mode == "baseline": self.raw["baseline_id"] = "B1"
                else: self.raw["case_started_at_utc"] = "2026-11-13T09:00:00Z"
                with self.assertRaisesRegex(ValueError, "64_128"): self.generate()
                self.raw = raw

    def test_additive_checker_must_be_frozen_in_candidate_provenance(self):
        self.plan["provenance"]["source_files_sha256"]["scripts/post_p8_position.py"] = "0" * 64
        self.plan.pop("plan_digest"); self.plan["plan_digest"] = digest(self.plan)
        self.doc["plan"] = write(self.root / "plan.json", self.plan)
        with self.assertRaisesRegex(ValueError, "candidate_source"): self.generate()


if __name__ == "__main__": unittest.main()
