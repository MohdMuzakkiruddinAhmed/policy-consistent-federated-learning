"""Financial-fault recovery cannot dispatch a resource-deleting override."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests'),str(ROOT/'src')]
import aws_campaign as campaign
import initialize_campaign_budget as initializer
import test_amendment_consumers as fixtures


class AmendmentSubclassCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AmendmentConsumerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture

    def assert_stops_without_override(self,klass):
        with patch.object(campaign,'ROOT',self.f.root):
            initializer.initialize(self.f.f.request,root=self.f.root,apply=True)
            self.f.ledger_path.write_bytes(b'{corrupt financial ledger')
            runner=klass(self.f.f.request,apply=True,clients={})
            runner.sdk=Mock(return_value={})
            def stop():runner.inventory['shutdown_confirmation']={'confirmed':True}
            runner.stop_recorded=Mock(side_effect=stop)
            original=self.f.ledger_path.read_bytes()
            with patch.object(klass,'teardown',side_effect=AssertionError('destructive_override_must_not_dispatch')) as override:
                with self.assertRaisesRegex(RuntimeError,'budget_ledger_recovery_required'):runner.execute('teardown')
            override.assert_not_called();runner.stop_recorded.assert_called_once()
            self.assertEqual(original,self.f.ledger_path.read_bytes())
            self.assertFalse(runner.inventory['teardown_complete'])
            self.assertFalse(runner.inventory['compute_stop_with_budget_ledger_fault']['runtime_resource_deletion_attempted'])

    def test_corrupt_B_ledger_forces_base_STOP_only_before_generic_override(self):
        class Override(campaign.CampaignRunner):
            def teardown(self):raise AssertionError('resource_deletion_not_allowed')
        self.assert_stops_without_override(Override)

    def test_partial_foundation_subclass_cannot_bypass_financial_STOP_only_guard(self):
        import finalize_partial_foundation as recovery
        self.assert_stops_without_override(recovery.PartialFoundationRunner)

    def test_secret_cleanup_subclass_cannot_bypass_financial_STOP_only_guard(self):
        import cleanup_project_secrets as recovery
        self.assert_stops_without_override(recovery.SecretCleanupRunner)
