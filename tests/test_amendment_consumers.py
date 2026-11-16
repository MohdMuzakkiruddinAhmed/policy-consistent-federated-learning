"""Fictional temporary approvals and local SDK-free successor consumer checks."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

STAGE = Path(__file__).resolve().parent
ROOT = next(parent for parent in STAGE.parents if (parent / "pyproject.toml").is_file())
sys.path[:0] = [str(STAGE), str(ROOT / "scripts"), str(ROOT / "src"), str(ROOT / "tests")]
import campaign_budget as budget
import aws_campaign as campaign
import finalize_research as final
import prepare_campaign as preparer
from initialize_campaign_budget import initialize
import initialize_campaign_budget as initializer
from test_campaign_budget_lineage import Fixture


def put(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, sort_keys=True, allow_nan=False))
    import hashlib
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class AmendmentConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = Fixture(self.root); self.f.build()
        self.f.request["authorization"]["path"] = str(self.root / self.f.request["authorization"]["path"])
        put(self.root / "results/aws" / self.f.old_campaign / "inventory.json", self.f.inventory)
        self.ledger_path = self.root / "results/aws" / ("budget-ledger-" + self.f.request["authorization"]["sha256"] + ".json")

    def runner(self):
        with patch.object(campaign, "ROOT", self.root):
            runner = campaign.CampaignRunner(self.f.request, clients={})
        runner.approval = deepcopy(self.f.approval)
        return runner

    def test_default_preview_does_not_create_successor_or_change_approval_bytes(self):
        before = {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob("*.json")}
        report = initialize(self.f.request, root=self.root)
        self.assertFalse(report["mutations_enabled"])
        self.assertFalse(report["successor_created"])
        self.assertFalse(self.ledger_path.exists())
        self.assertEqual(before, {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob("*.json")})

    def test_local_apply_copies_exact_old_rows_and_reuses_progressed_successor_without_reset(self):
        first = initialize(self.f.request, root=self.root, apply=True)
        self.assertTrue(first["successor_created"])
        successor = json.loads(self.ledger_path.read_text())
        arn = f"arn:aws:ecs:{self.f.region}:{self.f.account}:task/{self.f.new_project}-runtime/" + "c" * 32
        successor["tasks"][arn] = {"campaign_id": self.f.new_campaign, "vcpu_hours": .2, "gib_hours": .8}
        inventory = {"account_id": self.f.account, "region": self.f.region, "project_id": self.f.new_project,
            "campaign_id": self.f.new_campaign, "task_arns": [arn]}
        put(self.root / "results/aws" / self.f.new_campaign / "inventory.json", inventory)
        put(self.ledger_path, successor)
        before = self.ledger_path.read_bytes()
        second = initialize(self.f.request, root=self.root, apply=True)
        self.assertTrue(second["existing_valid_successor_reused"])
        self.assertFalse(second["successor_created"])
        self.assertEqual(before, self.ledger_path.read_bytes())
        successor["tasks"].pop(self.f.old_arns[0]); put(self.ledger_path, successor)
        with self.assertRaisesRegex(ValueError, "predecessor_rows"):
            initialize(self.f.request, root=self.root, apply=True)

    def test_typed_authorization_requires_the_initialized_ledger_before_cleanup_or_execution(self):
        runner = self.runner()
        with patch.object(campaign, "ROOT", self.root):
            self.assertEqual(campaign.validate_authorization(self.f.request)["approved_total_usd"], 30)
            with self.assertRaisesRegex(ValueError, "initialized_successor"):
                runner.authorize(cleanup=True)
            initialize(self.f.request, root=self.root, apply=True)
            self.assertEqual(runner.authorize(cleanup=True)["approved_total_usd"], 30)

    def test_legacy_20_32_limits_and_empty_initial_ledger_behavior_are_unchanged(self):
        request = {**self.f.request, "authorization": {**self.f.old_auth_ref, "path": str(self.root / self.f.old_auth_ref["path"])}}
        request.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            self.assertEqual(campaign.validate_authorization(request)["approved_total_usd"], 20)
            runner = campaign.CampaignRunner(request, clients={})
            runner.approval = deepcopy(self.f.old_auth)
            default = {"authorization_sha256": request["authorization"]["sha256"], "tasks": {}}
            self.assertEqual(runner._read_budget_ledger(default), default)
            for field, value in (("approved_total_usd", 21), ("max_cumulative_fleet_hours", 33)):
                invalid = deepcopy(self.f.old_auth); invalid[field] = value
                changed = {**request, "authorization": put(self.root / "invalid-legacy.json", invalid)}
                with self.assertRaisesRegex(ValueError, "new_scoped"):
                    campaign.validate_authorization(changed)

    def test_status_writer_cannot_bypass_amendment_guard_with_unset_approval(self):
        runner = self.runner(); runner.approval = None
        with patch.object(campaign, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "initialized_successor"):
                runner._read_budget_ledger({"tasks": {}})
            initialize(self.f.request, root=self.root, apply=True)
            self.assertEqual(len(runner._read_budget_ledger({"tasks": {}})["tasks"]), len(self.f.old_arns))
            self.assertEqual(runner.local_plan("bootstrap")["required_limits"]["total_usd_max"], 30)

    def test_bound_b_kind_without_marker_cannot_take_legacy_status_or_writer_path(self):
        initialize(self.f.request, root=self.root, apply=True)
        request = deepcopy(self.f.request); request.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            runner = campaign.CampaignRunner(request, clients={})
            before = self.ledger_path.read_bytes()
            with patch.object(runner, "sdk", side_effect=AssertionError("untyped B reached SDK")):
                with self.assertRaisesRegex(ValueError, "explicit_new_typed"):
                    runner.execute("status")
                with self.assertRaisesRegex(ValueError, "explicit_new_typed"):
                    runner._read_budget_ledger({"tasks": {}})
        self.assertEqual(before, self.ledger_path.read_bytes())

    def test_amended_deployment_writer_keeps_terminal_old_clock_exact_and_appends_new_clock(self):
        initialize(self.f.request, root=self.root, apply=True)
        runner = self.runner()
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None): return cls(2026, 11, 13, 4, 0, tzinfo=timezone.utc)
        with patch.object(campaign, "ROOT", self.root), patch.object(campaign, "datetime", Clock):
            runner.deployment_clock()
        stored = json.loads(self.ledger_path.read_text())
        for key, row in self.f.terminal["deployments"].items():
            self.assertEqual(stored["deployments"][key], row)
        self.assertEqual(len(stored["deployments"]), len(self.f.terminal["deployments"]) + 1)
        stored["tasks"][self.f.old_arns[0]]["vcpu_hours"] = 0
        put(self.ledger_path, stored)
        with patch.object(campaign, "ROOT", self.root), self.assertRaisesRegex(ValueError, "predecessor_rows"):
            runner.deployment_clock()

    def test_finalizer_invokes_lineage_before_a_dropped_campaign_could_disappear(self):
        from test_finalization import fixture as final_fixture
        plan, recipe, analysis = final_fixture(self.root)
        initialize(self.f.request, root=self.root, apply=True)
        bad = json.loads(self.ledger_path.read_text())
        bad["tasks"].pop(self.f.old_arns[0])
        ledger_ref = put(self.ledger_path, bad)
        # The complete synthetic phase checklist is irrelevant: the inherited
        # usage loss independently blocks finalization before any completion.
        recipe["teardown"] = {"inventories": [self.f.inventory_ref], "readbacks": [self.f.readback_ref],
            "budget_ledger": {"path": str(self.ledger_path.relative_to(self.root)), "sha256": ledger_ref["sha256"]},
            "authorization": {**self.f.request["authorization"], "path": str(Path(self.f.request["authorization"]["path"]).relative_to(self.root))}}
        with patch.object(final, "analyze_registry", return_value=analysis):
            report = final.finalize(recipe, plan, [], root=self.root)
        self.assertFalse(report["all_phases_complete"])
        self.assertTrue(any("predecessor_rows" in error for error in report["errors"]), report["errors"])

    def stopped_runtime_after_corrupt_ledger(self):
        initialize(self.f.request, root=self.root, apply=True)
        self.ledger_path.write_bytes(b"deliberately-corrupt-ledger-bytes")
        runner = self.runner()
        cluster = f"arn:aws:ecs:{self.f.region}:{self.f.account}:cluster/{self.f.new_project}-runtime"
        arn = cluster.replace(":cluster/", ":task/") + "/" + "c" * 32
        definition = f"arn:aws:ecs:{self.f.region}:{self.f.account}:task-definition/{self.f.new_project}-org_01:1"
        role = f"arn:aws:iam::{self.f.account}:role/{self.f.new_project}-org_01"
        runner.inventory.update(runtime_contract={"cluster_arn": cluster, "task_definition_arns": {"org_01": definition},
            "service_names": {"opa": self.f.new_project + "-opa"}}, task_arns=[arn],
            task_definition_history={definition: {"task_role_arn": role, "container_commands": {"org_01": ["client"]}}})
        ecs, sts = Mock(), Mock()
        sts.get_caller_identity.return_value = {"Account": self.f.account}
        active = {"value": True}
        ecs.list_tasks.side_effect = lambda **kw: {"taskArns": [arn] if (kw["desiredStatus"] == "RUNNING") == active["value"] else []}
        def describe(**kwargs):
            self.assertEqual(kwargs["cluster"], cluster); self.assertEqual(kwargs["tasks"], [arn])
            now = datetime.now(timezone.utc)
            task = {"taskArn": arn, "taskDefinitionArn": definition, "lastStatus": "RUNNING" if active["value"] else "STOPPED",
                "cpu": "256", "memory": "1024", "pullStartedAt": now - timedelta(seconds=20),
                "containers": [{"exitCode": None if active["value"] else 0}]}
            if not active["value"]: task["stoppedAt"] = now
            return {"tasks": [task], "failures": []}
        ecs.describe_tasks.side_effect = describe
        def stop(**kwargs):
            self.assertEqual(kwargs["cluster"], cluster); self.assertEqual(kwargs["task"], arn)
            active["value"] = False
            return {"task": {"taskArn": arn}}
        ecs.stop_task.side_effect = stop
        runner.clients = {"sts": sts, "ecs": ecs}; runner.sleep = lambda seconds: None
        return runner, ecs, arn

    def test_corrupt_ledger_cleanup_stops_exact_owned_compute_without_any_ledger_or_resource_deletion(self):
        runner, ecs, arn = self.stopped_runtime_after_corrupt_ledger()
        bad = self.ledger_path.read_bytes()
        with patch.object(campaign, "ROOT", self.root):
            with self.assertRaises(ValueError): runner.authorize(cleanup=True)
            runner._allow_ledger_fault_cleanup = True
            runner.authorize(cleanup=True)
            with patch.object(runner, "terraform_step", side_effect=AssertionError("no resource deletion")):
                with self.assertRaisesRegex(RuntimeError, "budget_ledger_recovery_required"):
                    runner.teardown()
        self.assertEqual(ecs.stop_task.call_count, 1)
        ecs.update_service.assert_called_once_with(cluster=runner.inventory["runtime_contract"]["cluster_arn"],
            service=self.f.new_project + "-opa", desiredCount=0)
        self.assertEqual(self.ledger_path.read_bytes(), bad)
        self.assertTrue(runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertFalse(runner.inventory["teardown_complete"])
        self.assertFalse(runner.inventory["compute_stop_with_budget_ledger_fault"]["accounting_complete"])
        self.assertTrue(runner.inventory["compute_stop_with_budget_ledger_fault"]["foundation_retained"])
        self.assertFalse(getattr(runner, "_emergency_stop_observation_only", False))
        self.assertEqual(runner.inventory["observed_tasks"][0]["task_arn"], arn)
        self.assertEqual(runner.inventory["observed_tasks"][0]["last_status"], "STOPPED")

    def test_midwatch_financial_failure_preserves_original_error_and_still_stops_owned_compute(self):
        runner, ecs, _ = self.stopped_runtime_after_corrupt_ledger()
        bad = self.ledger_path.read_bytes()
        with patch.object(campaign, "ROOT", self.root):
            with self.assertRaises(json.JSONDecodeError):
                runner._with_shutdown(lambda: runner._read_budget_ledger({}), stage="run")
        self.assertEqual(ecs.stop_task.call_count, 1)
        self.assertTrue(runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertIn("budget_ledger_recovery_required", runner.inventory)
        self.assertEqual(self.ledger_path.read_bytes(), bad)
        self.assertFalse(getattr(runner, "_emergency_stop_observation_only", False))

    def test_retirement_prevents_old_approval_execution_without_changing_historical_evidence(self):
        old_bytes = (self.root / self.f.old_auth_ref["path"]).read_bytes()
        initialize(self.f.request, root=self.root, apply=True)
        old_request = {**self.f.request, "authorization": {**self.f.old_auth_ref, "path": str(self.root / self.f.old_auth_ref["path"])}}
        old_request.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            self.assertEqual(campaign.validate_authorization(old_request)["approved_total_usd"], 20)
            old_runner = campaign.CampaignRunner(old_request, clients={})
            with patch.object(old_runner, "sdk", side_effect=AssertionError("retired request reached SDK")):
                with self.assertRaises(budget.RetiredAuthorization): old_runner.execute("status")
                with self.assertRaises(budget.RetiredAuthorization): old_runner.authorize(cleanup=True)
        self.assertEqual(old_bytes, (self.root / self.f.old_auth_ref["path"]).read_bytes())
        self.assertTrue((self.root / "results/aws/budget-lineage-required.json").is_file())

    def test_crash_between_retirement_and_successor_file_cannot_fork_or_reset_usage(self):
        real_link = initializer.os.link
        def crash(source, destination, *args, **kwargs):
            if Path(destination).resolve() == self.ledger_path.resolve():
                raise RuntimeError("synthetic-local-crash-before-successor-publish")
            return real_link(source, destination, *args, **kwargs)
        with patch.object(initializer.os, "link", crash), self.assertRaisesRegex(RuntimeError, "synthetic-local-crash"):
            initialize(self.f.request, root=self.root, apply=True)
        self.assertFalse(self.ledger_path.exists())
        with self.assertRaises(budget.RetiredAuthorization):
            budget.assert_authorization_not_retired({"account_id": self.f.account, "region": self.f.region,
                "authorization": self.f.old_auth_ref}, root=self.root)
        with patch.object(campaign, "ROOT", self.root), self.assertRaisesRegex(ValueError, "initialized_successor"):
            self.runner().authorize(cleanup=True)
        retry = initialize(self.f.request, root=self.root, apply=True)
        self.assertTrue(retry["successor_created"])
        self.assertEqual(json.loads(self.ledger_path.read_text())["tasks"], self.f.terminal["tasks"])

    def test_required_missing_registry_blocks_automatic_legacy_fallback_and_requires_exact_restore(self):
        initialize(self.f.request, root=self.root, apply=True)
        registry = self.root / "results/aws/budget-authorization-retirements.json"
        recorded = registry.read_bytes()
        registry.unlink()
        with self.assertRaisesRegex(ValueError, "registry_missing_restore_exact_history"):
            initialize(self.f.request, root=self.root)
        with patch.object(campaign, "ROOT", self.root), self.assertRaisesRegex(ValueError, "registry_missing_restore_exact_history"):
            self.runner()._read_budget_ledger({})
        self.assertTrue(self.ledger_path.is_file())
        registry.write_bytes(recorded)
        before = self.ledger_path.read_bytes()
        self.assertTrue(initialize(self.f.request, root=self.root, apply=True)["existing_valid_successor_reused"])
        self.assertEqual(before, self.ledger_path.read_bytes())

    def preparation_inputs(self):
        import hashlib
        data = self.root / "data/processed/uci296-v0.1.0-seed296"
        names = [f"{distribution}/org_{number:02d}.csv" for distribution in ("iid", "non_iid") for number in range(1, 9)]
        names += ["preprocessor.json", "validation.csv", "test.csv"]
        hashes = {}
        for name in names:
            path = data / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic-preparation-bytes-only\n")
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        put(self.root / "data_manifests/dataset.json", {"private_artifacts_sha256": hashes})
        for name in ("reports/runtime_infrastructure_validation.json", "containers/build_validation.json", "reports/service_container_validation.json"):
            put(self.root / name, {"kind": "synthetic-preparation-fixture-only"})
        (self.root / "configs").mkdir(exist_ok=True)
        (self.root / "configs/aws_campaign_authorization.json").write_bytes((self.root / self.f.old_auth_ref["path"]).read_bytes())

    def test_explicit_preparer_uses_actual_bound_successor_total_estimate_and_typed_marker(self):
        self.preparation_inputs()
        destination = self.root / "new-prepared-request"
        with patch.object(preparer, "ROOT", self.root):
            path = preparer.initial_request(destination, campaign_authorization=self.f.request["authorization"]["path"])
        request = json.loads(Path(path).read_text())
        foundation, runtime = (json.loads(Path(request[name]).read_text()) for name in ("foundation_vars", "runtime_vars"))
        self.assertEqual(foundation["budget_usd"], 30)
        self.assertEqual(runtime["budget"]["approved_total_usd"], 30)
        self.assertEqual(runtime["budget"]["estimated_total_usd"], 25)
        self.assertEqual(request["campaign_budget_kind"], budget.KIND)
        self.assertFalse(request["final_test_evaluation_permitted"])

    def test_preparer_keeps_legacy_default_values_until_that_approval_is_retired(self):
        self.preparation_inputs()
        with patch.object(preparer, "ROOT", self.root):
            legacy = json.loads(Path(preparer.initial_request(self.root / "legacy-request")).read_text())
            self.assertNotIn("campaign_budget_kind", legacy)
            runtime = json.loads(Path(legacy["runtime_vars"]).read_text())
            self.assertEqual(runtime["budget"]["approved_total_usd"], 20)
            self.assertEqual(runtime["budget"]["estimated_total_usd"], 15.2728)
            initialize(self.f.request, root=self.root, apply=True)
            with self.assertRaises(budget.RetiredAuthorization):
                preparer.initial_request(self.root / "retired-default-request")
        self.assertFalse((self.root / "retired-default-request").exists())


if __name__ == "__main__": unittest.main()
