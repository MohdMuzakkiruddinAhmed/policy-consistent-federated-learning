"""Local planned-window containment only; no authorization or AWS calls."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

STAGE = Path(__file__).resolve().parent
ROOT = next(parent for parent in STAGE.parents if (parent / "pyproject.toml").is_file())
sys.path[:0] = [str(STAGE), str(ROOT / "scripts")]
from budget_containment import check_bootstrap_window
MODULE = STAGE / "aws_campaign.py" if (STAGE / "aws_campaign.py").is_file() else ROOT / "scripts/aws_campaign.py"
spec = importlib.util.spec_from_file_location("expiry_guard_campaign_under_test", MODULE)
campaign = importlib.util.module_from_spec(spec); spec.loader.exec_module(campaign)

NOW = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
REQUEST = {"account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-next",
    "campaign_id": "synthetic-next", "authorization": {"sha256": "a" * 64}}


def approval(hours=32):
    return {"max_cumulative_fleet_hours": hours, "per_deployment_max_hours": 24}


def ledger(old_hours=8.2):
    return {"authorization_sha256": "a" * 64,
        "tasks": {"synthetic-old-task": {"campaign_id": "synthetic-old", "last_status": "STOPPED",
            "cpu": 256, "memory_mib": 1024, "vcpu_hours": .25, "gib_hours": 1}},
        "deployments": {"old-0": {"campaign_id": "synthetic-old", "project_id": "pcfl-old",
            "started_at": (NOW - timedelta(hours=old_hours + 1)).isoformat(),
            "finished_at": (NOW - timedelta(hours=1)).isoformat()}}}


def variables(hours):
    return {"hard_expiry_utc": (NOW + timedelta(hours=hours)).isoformat()}


class BudgetContainmentTests(unittest.TestCase):
    def test_new_24hour_window_fits_approved56_after_old9hour_ceiling_without_changing_old_rows(self):
        old = ledger(); before = deepcopy(old)
        result = check_bootstrap_window(REQUEST, approval(56), old, variables(24), now=NOW)
        self.assertEqual(result["accrued_normalized_hours_upper"], 9)
        self.assertEqual(result["reserved_window_hours_upper"], 24)
        self.assertTrue(result["successful"]); self.assertFalse(result["ledger_rows_modified"])
        self.assertEqual(old, before)

    def test_individually_valid_24hour_window_cannot_exceed_original32_cumulative_cap(self):
        with self.assertRaisesRegex(ValueError, "remaining_cumulative_budget"):
            check_bootstrap_window(REQUEST, approval(32), ledger(), variables(24), now=NOW)
        self.assertTrue(check_bootstrap_window(REQUEST, approval(32), ledger(), variables(23), now=NOW)["successful"])

    def test_past_cpu_and_memory_can_dominate_endpoint_wall_time(self):
        old = ledger(.1)
        old["tasks"]["synthetic-old-task"].update(cpu=4096, memory_mib=14336, vcpu_hours=120, gib_hours=420)
        with self.assertRaisesRegex(ValueError, "remaining_cumulative_budget"):
            check_bootstrap_window(REQUEST, approval(32), old, variables(3), now=NOW)

    def test_stopped_linux_60second_minimum_and_ceil_are_retained_in_upper_model(self):
        old = ledger(0)
        old["tasks"]["synthetic-old-task"].update(vcpu_hours=.25 * 20 / 3600, gib_hours=20 / 3600)
        report = check_bootstrap_window(REQUEST, approval(), old, variables(1), now=NOW)
        self.assertAlmostEqual(report["retained_vcpu_hours_upper"], .25 / 60)
        self.assertAlmostEqual(report["retained_gib_hours_upper"], 1 / 60)
        old["tasks"]["synthetic-old-task"].update(vcpu_hours=.25 * 61.2 / 3600, gib_hours=61.2 / 3600)
        report = check_bootstrap_window(REQUEST, approval(), old, variables(1), now=NOW)
        self.assertAlmostEqual(report["retained_gib_hours_upper"], 62 / 3600)

    def test_other_open_projects_and_unstopped_tasks_block_fresh_bootstrap(self):
        for mutation in ("clock", "task"):
            with self.subTest(mutation=mutation):
                old = ledger()
                if mutation == "clock": old["deployments"]["old-0"]["finished_at"] = None
                else: old["tasks"]["synthetic-old-task"]["last_status"] = "PENDING"
                with self.assertRaises(ValueError): check_bootstrap_window(REQUEST, approval(56), old, variables(24), now=NOW)

    def test_partial_retry_preserves_total24hour_lifetime_and_original_deadline(self):
        old = ledger()
        old["deployments"] = {"current": {"campaign_id": REQUEST["campaign_id"], "project_id": REQUEST["project_id"],
            "started_at": (NOW - timedelta(hours=1)).isoformat(), "finished_at": None}}
        with self.assertRaisesRegex(ValueError, "reset_total_deployment_lifetime"):
            check_bootstrap_window(REQUEST, approval(56), old, variables(24), now=NOW, current_deployment_key="current")
        with self.assertRaisesRegex(ValueError, "extend_recorded_expiry"):
            check_bootstrap_window(REQUEST, approval(56), old, variables(20), now=NOW,
                current_deployment_key="current", recorded_expiry_utc=(NOW + timedelta(hours=19)).isoformat())
        self.assertTrue(check_bootstrap_window(REQUEST, approval(56), old, variables(20), now=NOW,
            current_deployment_key="current", recorded_expiry_utc=(NOW + timedelta(hours=20)).isoformat())["successful"])

    def test_bad_target_clock_limits_and_unknown_resource_quantities_fail_closed(self):
        for mutation in ("auth", "future", "negative", "boolean", "expired", "too_long", "naive"):
            with self.subTest(mutation=mutation):
                old, settings = ledger(), variables(1)
                if mutation == "auth": old["authorization_sha256"] = "b" * 64
                elif mutation == "future": old["deployments"]["old-0"]["finished_at"] = (NOW + timedelta(hours=1)).isoformat()
                elif mutation == "negative": old["tasks"]["synthetic-old-task"]["vcpu_hours"] = -1
                elif mutation == "boolean": old["tasks"]["synthetic-old-task"]["cpu"] = True
                elif mutation == "expired": settings = variables(-1)
                elif mutation == "too_long": settings = variables(24.01)
                else: settings["hard_expiry_utc"] = "2026-11-14T09:00:00"
                with self.assertRaises(ValueError): check_bootstrap_window(REQUEST, approval(), old, settings, now=NOW)

    def test_sdk_is_not_reached_by_execute_or_direct_bootstrap_when_cumulative_window_fails(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(campaign, "ROOT", Path(temporary)):
            root = Path(temporary)
            # A real temporary, hash-bound legacy approval exercises the active
            # authority guard without mocking it. Source-report authorization is
            # outside this focused containment fixture.
            bound_approval = {**approval(), "account_id": REQUEST["account_id"], "region": REQUEST["region"],
                "approved": True, "source": "user-conversation", "authorization_scope": campaign.SCOPE,
                "approved_total_usd": 20, "max_vcpu": 4, "max_memory_gib": 14}
            authorization = root / "authorization.json"
            authorization.write_bytes(json.dumps(bound_approval, sort_keys=True).encode())
            authorization_hash = hashlib.sha256(authorization.read_bytes()).hexdigest()
            target = {**REQUEST, "authorization": {"path": str(authorization), "sha256": authorization_hash},
                "runtime_vars": str(root / "runtime.json")}
            (root / "runtime.json").write_text(json.dumps({**variables(24), "expected_account_id": target["account_id"],
                "aws_region": target["region"], "project_id": target["project_id"]}))
            runner = campaign.CampaignRunner(target, apply=True, clients={})
            runner.approval = campaign.validate_authorization(target)
            self.assertEqual(runner.approval, bound_approval)
            runner.budget_ledger_path.parent.mkdir(parents=True, exist_ok=True)
            shared = ledger(); shared["authorization_sha256"] = authorization_hash
            runner.budget_ledger_path.write_text(json.dumps(shared))
            class Clock(datetime):
                @classmethod
                def now(cls, tz=None): return NOW
            with patch.object(campaign, "datetime", Clock), patch.object(runner, "authorize"), patch.object(runner, "sdk", side_effect=AssertionError("SDK reached")) as sdk:
                with self.assertRaisesRegex(ValueError, "remaining_cumulative_budget"): runner.execute("bootstrap")
                with self.assertRaisesRegex(ValueError, "remaining_cumulative_budget"): runner.bootstrap()
                sdk.assert_not_called()

    def test_frozen_cost_request_cannot_bypass_read_only_scope_through_direct_sdk_method(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(campaign, "ROOT", Path(temporary)):
            runner = campaign.CampaignRunner({**REQUEST, "cost_scope_snapshot": {}}, apply=False, clients={})
            with self.assertRaisesRegex(ValueError, "snapshot_request_is_read_only"):
                runner.sdk()


if __name__ == "__main__": unittest.main()
