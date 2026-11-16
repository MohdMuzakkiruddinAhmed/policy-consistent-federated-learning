"""Runner wiring retains authority graph before destructive image cleanup."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
import aws_campaign as campaign
import ecr_manifest_cleanup as cleanup
import test_ecr_manifest_cleanup as fixtures
from test_aws_campaign import request,clients,explicit_zero_secret_fixture


class ECRRunnerCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ECRManifestCleanupTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture;self.patch=patch.object(campaign,'ROOT',self.f.directory);self.patch.start();self.addCleanup(self.patch.stop)
        target=request(self.f.directory,'synthetic-campaign');target.update(project_id=self.f.project)
        self.aws=clients();self.aws['ecr']=self.f.ecr
        self.runner=campaign.CampaignRunner(target,clients=self.aws)
        self.runner.directory.mkdir(parents=True,exist_ok=True)
        self.runner.inventory.update(deepcopy(self.f.inventory))
        self.runner.inventory.update(runtime_variables={},foundation_variables={},uploads=[],retained_artifact_versions=[],
            task_arns=[],runtime_contract={},export={'source':'synthetic-retained-export'})
        self.runner.inventory['foundation'].update(bucket_name='synthetic-owned-bucket',state_table_name='synthetic-table')
        explicit_zero_secret_fixture(self.runner)
        ownership=self.f.directory/'results/aws/project-ownership.json';ownership.parent.mkdir(parents=True,exist_ok=True);ownership.write_text('{}')
        self.runner.stop_recorded=Mock();self.runner.retain_pre_teardown_states=Mock();self.runner.terraform_step=Mock()
        self.runner.deployment_clock=Mock();self.runner.retirement_pointer_bindings=Mock(return_value={})

    def test_graph_is_persisted_to_inventory_before_image_deletion_and_survives_cleanup(self):
        original=self.f.delete
        def guarded_delete(**kwargs):
            inventory=json.loads(self.runner.inventory_path.read_text())
            binding=inventory['ecr_manifest_graph'];self.assertTrue(Path(binding['path']).is_file())
            cleanup.load_graph(binding,inventory,self.runner.directory)
            return original(**kwargs)
        self.f.ecr.batch_delete_image.side_effect=guarded_delete
        with patch.object(campaign,'purge_recorded_versions',return_value=0):result=self.runner.teardown()
        self.assertTrue(result['teardown_complete']);self.assertFalse(self.f.remote)
        secret_report=json.loads(Path(self.runner.inventory['generated_secret_cleanup']['path']).read_text())
        self.assertTrue(secret_report['explicit_zero_authority']);self.assertFalse(secret_report['aws_api_calls'])
        self.assertTrue(self.runner.inventory['ecr_manifest_cleanup']['successful'])
        self.assertEqual(self.runner.inventory['removed_owned_image_references'],[self.f.uri+'@'+self.f.root_digest])
        self.assertEqual(self.runner.terraform_step.call_args_list[-1].args[0],'foundation')

    def test_missing_parent_without_graph_retains_foundation_and_S3_evidence(self):
        del self.f.remote[self.f.root_digest]
        with patch.object(campaign,'purge_recorded_versions') as purge,self.assertRaisesRegex(ValueError,'without_retained_content'):
            self.runner.teardown()
        purge.assert_not_called();self.f.ecr.batch_delete_image.assert_not_called()
        self.assertEqual([call.args[0] for call in self.runner.terraform_step.call_args_list],['runtime'])
        self.assertNotEqual(self.runner.inventory.get('teardown_complete'),True)
