"""Frozen cost snapshots must never become mutating campaign requests."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(parent for parent in STAGE.parents if (parent / "pyproject.toml").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
MODULE = STAGE / "aws_campaign.py" if (STAGE / "aws_campaign.py").is_file() else ROOT / "scripts/aws_campaign.py"
SPEC = importlib.util.spec_from_file_location("frozen_cost_guard_under_test", MODULE)
campaign = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(campaign)


class FrozenCostGuardTests(unittest.TestCase):
    def test_every_snapshot_marker_rejects_apply_before_inventory_or_sdk_work(self):
        for marker in ({}, None, False, "immutable-snapshot"):
            with self.subTest(marker=marker), patch.object(Path, "read_text", side_effect=AssertionError("inventory read")):
                with self.assertRaisesRegex(ValueError, "snapshot_request_is_read_only"):
                    campaign.CampaignRunner({"cost_scope_snapshot": marker}, apply=True, clients={})

    def test_typed_frozen_request_rejects_apply_without_relying_on_marker(self):
        with self.assertRaisesRegex(ValueError, "snapshot_request_is_read_only"):
            campaign.CampaignRunner({"kind": "frozen-campaign-cost-request"}, apply=True, clients={})

    def test_legacy_constructor_and_read_only_snapshot_preview_remain_local_and_unchanged(self):
        request = {"campaign_id": "synthetic-snapshot", "project_id": "pcfl-synthetic",
            "account_id": "123456789012", "region": "us-east-1", "authorization": {"sha256": "a" * 64}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(campaign, "ROOT", Path(temporary)):
            regular = campaign.CampaignRunner(request, apply=True, clients={})
            frozen = campaign.CampaignRunner({**request, "cost_scope_snapshot": {}}, apply=False, clients={})
            self.assertTrue(regular.apply); self.assertFalse(frozen.apply)
            self.assertEqual(regular.inventory, frozen.inventory)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_status_and_collect_cannot_mutate_live_ledger_through_apply_false_exception(self):
        request = {"campaign_id": "synthetic-snapshot", "project_id": "pcfl-synthetic",
            "account_id": "123456789012", "region": "us-east-1", "authorization": {"sha256": "a" * 64},
            "cost_scope_snapshot": {"execution_disabled": True}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(campaign, "ROOT", Path(temporary)):
            runner = campaign.CampaignRunner(request, apply=False, clients={})
            with patch.object(runner, "sdk", side_effect=AssertionError("SDK before snapshot guard")):
                for stage in ("status", "collect"):
                    with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "snapshot_request_is_read_only"):
                        runner.execute(stage)


if __name__ == "__main__": unittest.main()
