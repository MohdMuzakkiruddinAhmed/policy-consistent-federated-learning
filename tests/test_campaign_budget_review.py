"""Independent staged fault checks; fictional temp decisions, no AWS calls."""
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src"), str(ROOT / "tests")]
import campaign_budget as budget
import aws_campaign as campaign
import initialize_campaign_budget as initialization
import budget_containment as containment
import test_amendment_consumers as core_fixture
import test_amendment_cost_consumers as cost_fixture


class IndependentSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.block = patch("boto3.session.Session.client", side_effect=AssertionError("actual_AWS_forbidden_in_review_test"))
        self.block.start(); self.addCleanup(self.block.stop)
        self.f = core_fixture.AmendmentConsumerTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.root = self.f.root

    def test_crash_before_atomic_successor_publish_retries_without_reset_or_reenabling_A(self):
        original = initialization.os.link
        def partial(source, destination, *args, **kwargs):
            if Path(destination).resolve() == self.f.ledger_path.resolve():
                self.assertFalse(self.f.ledger_path.exists())
                self.assertEqual(json.loads(Path(source).read_text())["tasks"], self.f.f.terminal["tasks"])
                raise SystemExit("synthetic_process_exit_before_atomic_publish")
            return original(source, destination, *args, **kwargs)
        with patch.object(initialization.os, "link", partial), self.assertRaises(SystemExit):
            initialization.initialize(self.f.f.request, root=self.root, apply=True)
        old = {"account_id": self.f.f.account, "region": self.f.f.region, "authorization": self.f.f.old_auth_ref}
        with self.assertRaises(budget.RetiredAuthorization): budget.assert_authorization_not_retired(old, root=self.root)
        self.assertFalse(self.f.ledger_path.exists())
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        self.assertEqual(json.loads(self.f.ledger_path.read_text())["tasks"], self.f.f.terminal["tasks"])

    def test_crash_after_atomic_publication_reuses_complete_B_without_overwrite(self):
        original = initialization.os.link
        def after(source, destination, *args, **kwargs):
            value = original(source, destination, *args, **kwargs)
            if Path(destination).resolve() == self.f.ledger_path.resolve():
                raise SystemExit("synthetic_process_exit_after_atomic_publish")
            return value
        with patch.object(initialization.os, "link", after), self.assertRaises(SystemExit):
            initialization.initialize(self.f.f.request, root=self.root, apply=True)
        before = self.f.ledger_path.read_bytes()
        self.assertEqual(json.loads(before)["tasks"], self.f.f.terminal["tasks"])
        self.assertTrue(initialization.initialize(self.f.f.request, root=self.root, apply=True)["existing_valid_successor_reused"])
        self.assertEqual(before, self.f.ledger_path.read_bytes())

    def test_missing_registry_cannot_reenable_default_A_even_if_successor_is_corrupt(self):
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        (self.root / "results/aws/budget-authorization-retirements.json").unlink()
        self.f.ledger_path.write_bytes(b"synthetic_corrupt_B")
        old = {**self.f.f.request, "authorization": {**self.f.f.old_auth_ref,
            "path": str(self.root / self.f.f.old_auth_ref["path"])}}
        old.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            runner = campaign.CampaignRunner(old, clients={})
            with patch.object(runner, "sdk", side_effect=AssertionError("retired_default_A_reached_SDK")):
                with self.assertRaisesRegex(ValueError, "registry_missing"):
                    runner.execute("status")

    def test_omitting_B_marker_cannot_downgrade_status_reader_to_unchecked_legacy(self):
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        damaged = json.loads(self.f.ledger_path.read_text())
        damaged["tasks"].pop(self.f.f.old_arns[0])
        core_fixture.put(self.f.ledger_path, damaged)
        request = deepcopy(self.f.f.request); request.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            runner = campaign.CampaignRunner(request, clients={})
            self.assertIsNone(runner.approval)
            with patch.object(runner, "sdk", side_effect=AssertionError("untyped_B_reached_SDK")):
                with self.assertRaises(ValueError): runner._read_budget_ledger({})

    def test_two_valid_successors_cannot_fork_same_predecessor_family(self):
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        registry = self.root / "results/aws/budget-authorization-retirements.json"
        before = registry.read_bytes()
        second = core_fixture.Fixture(self.root)
        real_put = second.put
        second.put = lambda name, value: real_put(name.replace("next/", "other-next/"), value)
        second.quote.update(requested_cumulative_total_usd=31, requested_incremental_usd=11)
        second.decision["approved_total_usd"] = second.approval["approved_total_usd"] = 31
        second.build()
        with self.assertRaisesRegex(ValueError, "fork"):
            initialization.initialize(second.request, root=self.root, apply=True)
        self.assertEqual(before, registry.read_bytes())
        new_path = self.root / "results/aws" / ("budget-ledger-" + second.request["authorization"]["sha256"] + ".json")
        self.assertFalse(new_path.exists())

    def test_retirement_committed_while_waiting_for_operation_lock_blocks_stale_A_dispatch(self):
        old = {**self.f.f.request, "authorization": {**self.f.f.old_auth_ref,
            "path": str(self.root/self.f.f.old_auth_ref["path"])}}
        old.pop("campaign_budget_kind")
        with patch.object(campaign, "ROOT", self.root):
            runner = campaign.CampaignRunner(old, clients={}, apply=True)
            def authorize(**kwargs): runner.approval = deepcopy(self.f.f.old_auth)
            @contextmanager
            def migrate_before_enter(path):
                initialization.initialize(self.f.f.request, root=self.root, apply=True)
                yield
            with patch.object(runner, "authorize", side_effect=authorize), patch.object(runner, "sdk", return_value={}), \
                    patch.object(campaign, "exclusive_file", migrate_before_enter), patch.object(runner, "publish_inputs") as publish:
                with self.assertRaises(budget.RetiredAuthorization): runner.execute("publish-inputs")
                publish.assert_not_called()

    def test_133_retained_tasks_carry_exactly_without_sampling_or_truncation(self):
        f = self.f.f
        for index in range(131):
            arn = f"arn:aws:ecs:{f.region}:{f.account}:task/{f.old_project}-runtime/{index:032x}"
            row = {"campaign_id": f.old_campaign, "cpu": 256, "memory_mib": 1024,
                "vcpu_hours": .001, "gib_hours": .004, "last_status": "STOPPED"}
            f.snapshot["tasks"][arn] = deepcopy(row); f.terminal["tasks"][arn] = deepcopy(row)
            f.quote_cost["resources"]["tasks"][arn] = deepcopy(row)
            f.terminal_cost["resources"]["tasks"][arn] = deepcopy(row)
            f.inventory["task_arns"].append(arn)
        request = f.build()
        initialization.initialize(request, root=self.root, apply=True)
        ledger_path = self.root/"results/aws"/("budget-ledger-"+request["authorization"]["sha256"]+".json")
        carried = json.loads(ledger_path.read_text())
        self.assertEqual(len(carried["tasks"]), 133)
        self.assertEqual(carried["tasks"], f.terminal["tasks"])
        self.assertEqual(set(carried["tasks"]), set(f.inventory["task_arns"]))

    def test_corrupt_B_emergency_stop_never_reaches_storage_or_terraform_mutation(self):
        runner, ecs, _ = self.f.stopped_runtime_after_corrupt_ledger()
        original = self.f.ledger_path.read_bytes()
        runner._allow_ledger_fault_cleanup = True
        with patch.object(campaign, "ROOT", self.root), patch.object(runner, "terraform_step",
                side_effect=AssertionError("terraform_forbidden_during_accounting_fault")):
            runner.authorize(cleanup=True)
            with self.assertRaisesRegex(RuntimeError, "budget_ledger_recovery_required"):
                runner.teardown()
        self.assertEqual(ecs.stop_task.call_count, 1)
        self.assertEqual(original, self.f.ledger_path.read_bytes())
        self.assertEqual(set(runner.clients), {"sts", "ecs"})
        self.assertTrue(runner.inventory["compute_stop_with_budget_ledger_fault"]["foundation_retained"])
        self.assertFalse(runner.inventory["teardown_complete"])

    def test_global_lock_recheck_still_allows_owned_stop_when_B_registry_and_ledger_are_corrupt(self):
        runner, ecs, _ = self.f.stopped_runtime_after_corrupt_ledger()
        runner.apply = True
        registry = self.root / "results/aws/budget-authorization-retirements.json"
        registry.write_bytes(b"synthetic_corrupt_registry")
        ledger_before, registry_before = self.f.ledger_path.read_bytes(), registry.read_bytes()
        with patch.object(campaign, "ROOT", self.root), patch.object(runner, "terraform_step",
                side_effect=AssertionError("emergency_stop_must_not_destroy_resources")):
            with self.assertRaisesRegex(RuntimeError, "budget_ledger_recovery_required"):
                runner.execute("teardown")
        self.assertEqual(ecs.stop_task.call_count, 1)
        self.assertEqual(ledger_before, self.f.ledger_path.read_bytes())
        self.assertEqual(registry_before, registry.read_bytes())
        self.assertTrue(runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertFalse(runner.inventory["teardown_complete"])

    def test_retry_cannot_extend_original_project_to_25_hours_inside_56_global_hours(self):
        now = datetime(2026, 11, 13, 4, tzinfo=timezone.utc)
        request = {"account_id": self.f.f.account, "region": self.f.f.region, "campaign_id": "fresh-main",
            "project_id": "pcfl-main", "authorization": {"sha256": "f" * 64}}
        approval = {"max_cumulative_fleet_hours": 56, "per_deployment_max_hours": 24}
        ledger = {"authorization_sha256": "f" * 64, "tasks": {}, "deployments": {"main-0": {
            "campaign_id": "fresh-main", "project_id": "pcfl-main", "started_at": (now-timedelta(hours=1)).isoformat(),
            "finished_at": None}}}
        with self.assertRaises(ValueError):
            containment.check_bootstrap_window(request, approval, ledger,
                {"hard_expiry_utc": (now+timedelta(hours=24)).isoformat()}, now=now, current_deployment_key="main-0")

    def test_remaining_global_hours_guard_includes_retained_endpoint_rounding(self):
        now = datetime(2026, 11, 13, 4, tzinfo=timezone.utc)
        request = {"account_id": self.f.f.account, "region": self.f.f.region, "campaign_id": "fresh-main",
            "project_id": "pcfl-main", "authorization": {"sha256": "f" * 64}}
        approval = {"max_cumulative_fleet_hours": 56, "per_deployment_max_hours": 24}
        ledger = {"authorization_sha256": "f" * 64, "tasks": {}, "deployments": {"old": {
            "campaign_id": "old", "project_id": "pcfl-old", "started_at": (now-timedelta(hours=53)).isoformat(),
            "finished_at": now.isoformat()}}}
        proof = containment.check_bootstrap_window(request, approval, ledger,
            {"hard_expiry_utc": (now+timedelta(hours=3)).isoformat()}, now=now)
        self.assertEqual(proof["accrued_normalized_hours_upper"], 53)
        with self.assertRaisesRegex(ValueError, "remaining_cumulative"):
            containment.check_bootstrap_window(request, approval, ledger,
                {"hard_expiry_utc": (now+timedelta(hours=3, seconds=1)).isoformat()}, now=now)

    def test_B_bootstrap_wires_expiry_guard_before_any_SDK_or_Terraform(self):
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        runner = self.f.runner()
        self.assertTrue(hasattr(runner, "check_bootstrap_containment"), "staged_B_bootstrap_guard_not_yet_wired")
        runner.apply = True
        now = datetime.now(timezone.utc)
        with patch.object(campaign, "ROOT", self.root), patch.object(runner, "variables",
                return_value={"hard_expiry_utc": (now+timedelta(hours=25)).isoformat()}), \
                patch.object(runner, "sdk", side_effect=AssertionError("expiry_failure_reached_SDK")), \
                patch.object(runner, "terraform_step", side_effect=AssertionError("expiry_failure_reached_TF")):
            with self.assertRaisesRegex(ValueError, "deployment_window"): runner.bootstrap()
            with patch.object(runner, "authorize", return_value=self.f.f.approval):
                with self.assertRaisesRegex(ValueError, "deployment_window"): runner.execute("bootstrap")

    def test_B_partial_bootstrap_cannot_extend_recorded_earlier_deadline(self):
        initialization.initialize(self.f.f.request, root=self.root, apply=True)
        runner = self.f.runner()
        self.assertTrue(hasattr(runner, "check_bootstrap_containment"), "staged_B_bootstrap_guard_not_yet_wired")
        now = datetime.now(timezone.utc)
        ledger = json.loads(self.f.ledger_path.read_text())
        ledger["deployments"]["partial-main"] = {"campaign_id": self.f.f.new_campaign,
            "project_id": self.f.f.new_project, "started_at": (now-timedelta(hours=1)).isoformat(), "finished_at": None}
        core_fixture.put(self.f.ledger_path, ledger)
        runner.inventory.update(endpoint_deployment_key="partial-main", runtime_variables={"hard_expiry_utc": (now+timedelta(hours=1)).isoformat()})
        with patch.object(campaign, "ROOT", self.root), patch.object(runner, "variables",
                return_value={"hard_expiry_utc": (now+timedelta(hours=2)).isoformat()}), \
                patch.object(runner, "sdk", side_effect=AssertionError("extended_deadline_reached_SDK")):
            with self.assertRaisesRegex(ValueError, "recorded_expiry"): runner.check_bootstrap_containment()


class IndependentCostTests(unittest.TestCase):
    def setUp(self):
        self.block = patch("boto3.session.Session.client", side_effect=AssertionError("actual_AWS_forbidden_in_review_test"))
        self.block.start(); self.addCleanup(self.block.stop)
        self.f = cost_fixture.AmendmentCostConsumerTests(); self.f.setUp(); self.addCleanup(self.f.tearDown)

    def test_native_new_usage_delta_cannot_be_absorbed_by_large_ancestor_floor(self):
        first = self.f.report()
        self.f.ledger["tasks"][self.f.new_arn]["vcpu_hours"] += 1
        self.f.ledger["tasks"][self.f.new_arn]["gib_hours"] += 4
        self.f.f.put(self.f.ledger_relative, self.f.ledger)
        second = self.f.report()
        expected = 1*float(self.f.f.quote["rates"]["cpu"]["usd"])+4*float(self.f.f.quote["rates"]["memory"]["usd"])
        self.assertAlmostEqual(second["current_conservative_planning_estimate_usd"]-first["current_conservative_planning_estimate_usd"], expected)
        self.assertEqual(first["inherited_current_cost_floor_usd"], second["inherited_current_cost_floor_usd"])

    def test_native_snapshot_replays_price_after_live_history_deleted_and_registry_retired(self):
        receipt = cost_fixture.snapshots.create(self.f.request_path, self.f.root/"frozen-review", root=self.f.root, loader=cost_fixture.cost.load_scope)
        frozen = self.f.root/receipt["request"]["path"]
        before = cost_fixture.cost.load_scope(frozen, root=self.f.root)
        for path in (self.f.root/self.f.ledger_relative,
                self.f.root/f"results/aws/{self.f.f.new_campaign}/inventory.json",
                self.f.root/"results/aws/budget-authorization-retirements.json"):
            path.unlink()
        after = cost_fixture.cost.load_scope(frozen, root=self.f.root)
        self.assertEqual(before, after)
        self.assertEqual(after[2]["tasks"][self.f.f.old_arns[0]], self.f.f.terminal["tasks"][self.f.f.old_arns[0]])


if __name__ == "__main__": unittest.main()
