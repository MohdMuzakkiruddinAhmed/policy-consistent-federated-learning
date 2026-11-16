"""Synthetic reusable secret barrier and normal teardown ordering."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
from botocore.exceptions import ClientError
import aws_campaign
import generated_secret_cleanup as generated
import test_cleanup_project_secrets as secret_fixtures
from test_aws_campaign import clients as campaign_clients, request as campaign_request, contract


class GeneratedSecretCleanupTests(unittest.TestCase):
    def setUp(self):
        f=secret_fixtures.SecretCleanupTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        f.inventory.update(shutdown_confirmation={'confirmed':True,'unresolved_task_arns':[],'uncertain_launch_tokens':[]},task_arns=[],shared_fleet_ledger={})
        f.inventory['state_paths']={'runtime':str(f.directory/'state/runtime.tfstate')}
        p=Path(f.inventory['pre_teardown_state_snapshots']['runtime']['path']);state=json.loads(p.read_text());state.update(lineage='runtime',serial=1);p.write_text(json.dumps(state));f.inventory['pre_teardown_state_snapshots']['runtime']=f.ref(p)
        p=f.directory/'state/runtime.tfstate';p.parent.mkdir();p.write_text(json.dumps({'lineage':'runtime','serial':2,'resources':[]}))
        for client in (f.sts,f.sm):client.meta=SimpleNamespace(region_name='us-east-1')
        p=patch.object(generated,'local_custody',return_value={'successful':True,'synthetic_fixture':True});p.start();self.addCleanup(p.stop)

    def invoke(self,**kwargs):
        f=self.f
        return generated.cleanup_generated_secrets({'sts':f.sts,'secretsmanager':f.sm},f.request,f.inventory,
            directory=f.directory,root=f.root,sleep=Mock(),max_polls=2,**kwargs)

    def test_complete_secret_contract_deletes_exact16_and_records_actual_absence(self):
        report=self.invoke()
        self.assertTrue(report['successful'],report);self.assertEqual(len(report['actions']),16);self.assertTrue(report['all_selected_secrets_absent'])
        self.f.sm.get_secret_value.assert_not_called();self.f.sm.restore_secret.assert_not_called();self.f.sm.list_secrets.assert_not_called()

    def test_explicit_three_source_zero_contract_is_zero_SDK(self):
        f=self.f;f.request['secrets']=[];f.inventory['runtime_contract']['secret_arns']={};f.inventory['secret_versions']={}
        p=Path(f.inventory['pre_teardown_state_snapshots']['runtime']['path']);s=json.loads(p.read_text());s['resources']=[];p.write_text(json.dumps(s));f.inventory['pre_teardown_state_snapshots']['runtime']=f.ref(p)
        r=generated.cleanup_generated_secrets({},f.request,f.inventory,directory=f.directory,root=f.root)
        self.assertTrue(r['successful']);self.assertTrue(r['explicit_zero_authority']);self.assertFalse(r['aws_api_calls'])
        del f.inventory['secret_versions'];r=self.invoke();self.assertFalse(r['successful']);self.f.sts.get_caller_identity.assert_not_called()

    def test_changed_source_or_unbound_runtime_or_unconfirmed_stop_rejects_before_SDK(self):
        f=self.f;f.inventory['shutdown_confirmation']['confirmed']=False
        self.assertFalse(self.invoke()['successful']);f.sts.get_caller_identity.assert_not_called()
        f.inventory['shutdown_confirmation']['confirmed']=True;Path(f.request['secrets'][0]['payload_path']).write_text('rebound')
        self.assertFalse(self.invoke()['successful']);f.sts.get_caller_identity.assert_not_called()

    def test_wrong_region_or_native_Project_never_deletes(self):
        f=self.f;f.sm.meta.region_name='us-west-2';self.assertFalse(self.invoke()['successful']);f.sts.get_caller_identity.assert_not_called()
        f.sm.meta.region_name='us-east-1';f.sm.describe_secret.side_effect=lambda **kw:{**f.describe(**kw),'Tags':[{'Key':'Project','Value':'foreign'}]}
        r=self.invoke();self.assertFalse(r['successful']);f.sm.delete_secret.assert_not_called();self.assertEqual(r['errors'][0]['operation'],'SecretsManager.DescribeSecret-preflight')

    def test_unknown_error_retains_exact_failed_ARN_and_prevents_all_mutations(self):
        f=self.f;f.sm.describe_secret.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'DescribeSecret')
        r=self.invoke();self.assertFalse(r['successful']);self.assertEqual(r['errors'][0]['arn'],r['selected_sources'][0]['arn']);f.sm.delete_secret.assert_not_called()

    def test_partial_delete_retry_preserves_failure_and_skips_proven_absent_secret(self):
        f=self.f;counter=[0]
        def partial(**kwargs):
            counter[0]+=1
            if counter[0]==2:raise ClientError({'Error':{'Code':'InternalServiceError'}},'DeleteSecret')
            return f.delete(**kwargs)
        f.sm.delete_secret.side_effect=partial;first=self.invoke()
        self.assertFalse(first['successful']);self.assertEqual(len(first['actions']),2);self.assertEqual(len(first['readback']),16)
        f.sm.delete_secret.side_effect=f.delete;second=self.invoke()
        self.assertTrue(second['successful']);self.assertEqual(len(second['actions']),15)
        self.assertEqual(sum(row['absent'] for row in second['before']),1)

    def test_acknowledgments_without_absence_block_success(self):
        f=self.f;f.sm.delete_secret.side_effect=lambda **kw:{'ARN':kw['SecretId'],'Name':f.describe_name(kw['SecretId'])}
        r=self.invoke();self.assertFalse(r['successful']);self.assertEqual(len(r['readback']),16);self.assertFalse(r['all_selected_secrets_absent'])

    def test_all_attempt_receipts_are_content_addressed_and_tamper_rejects(self):
        r=self.invoke();one=generated.retain_cleanup_receipt(r,directory=self.f.directory);two=generated.retain_cleanup_receipt(r,directory=self.f.directory)
        self.assertEqual(one,two);self.assertEqual(hashlib.sha256(Path(one['path']).read_bytes()).hexdigest(),one['sha256'])
        Path(one['path']).write_text('tampered')
        with self.assertRaisesRegex(ValueError,'collision'):generated.retain_cleanup_receipt(r,directory=self.f.directory)


class NormalRunnerSecretBarrierTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        p=patch.object(aws_campaign,'ROOT',self.root);p.start();self.addCleanup(p.stop)
        self.aws=campaign_clients();self.runner=aws_campaign.CampaignRunner(campaign_request(self.root),clients=self.aws)
        self.runner.directory.mkdir(parents=True,exist_ok=True)
        self.runner.inventory.update(runtime_contract=contract(),runtime_variables={},foundation_variables={},foundation={'bucket_name':'test','state_table_name':'test'},uploads=[])
        self.events=[]
        self.runner.stop_recorded=Mock(side_effect=lambda:self.events.append('stop'))
        self.runner.retain_pre_teardown_states=Mock(side_effect=lambda:self.events.append('snapshots'))
        self.runner.terraform_step=Mock(side_effect=lambda stack,*a,**kw:self.events.append('TF-'+stack))
        self.runner.deployment_clock=Mock();self.runner.sdk=Mock(return_value=self.aws);self.runner.save=Mock()
        self.runner.retirement_pointer_bindings=Mock(return_value={'RUN#one':{'manifest_id':'m'}})
        self.aws['dynamodb'].get_item.return_value={'Item':{'manifest_id':{'S':'m'}}}
        self.aws['dynamodb'].update_item.side_effect=lambda **kw:self.events.append('pointer-retirement')
        ownership=self.root/'results/aws/project-ownership.json';ownership.parent.mkdir(parents=True,exist_ok=True);ownership.write_text('{}')
        for target,ret in [('ecr_manifest_cleanup.retain_image_graph',{'path':'synthetic','sha256':'a'*64}),('ecr_manifest_cleanup.delete_image_graph',{}),('probe_anchor.sentinel_references',[])]:
            p=patch(target,return_value=ret);p.start();self.addCleanup(p.stop)
        p=patch.object(aws_campaign,'purge_recorded_versions',side_effect=lambda *a,**kw:self.events.append('S3-purge') or 0);p.start();self.addCleanup(p.stop)

    def result(self,successful):
        self.events.append('secret-barrier');return {'kind':'synthetic-generated-secret-attempt','successful':successful}

    def test_normal_order_runtime_then_pointer_then_secret_then_purge_then_foundation(self):
        with patch.object(generated,'cleanup_generated_secrets',side_effect=lambda *a,**kw:self.result(True)):
            self.assertTrue(self.runner.teardown()['teardown_complete'])
        for a,b in zip(['TF-runtime','pointer-retirement','secret-barrier','S3-purge'],['pointer-retirement','secret-barrier','S3-purge','TF-foundation']):
            self.assertLess(self.events.index(a),self.events.index(b))
        self.assertEqual(len(self.runner.inventory['generated_secret_cleanup_attempts']),1)

    def test_failed_secret_readback_retained_and_blocks_storage_purge(self):
        with patch.object(generated,'cleanup_generated_secrets',side_effect=lambda *a,**kw:self.result(False)):
            with self.assertRaisesRegex(RuntimeError,'before_storage_purge'):self.runner.teardown()
        self.assertNotIn('S3-purge',self.events);self.assertNotIn('TF-foundation',self.events)
        ref=self.runner.inventory['generated_secret_cleanup'];self.assertFalse(json.loads(Path(ref['path']).read_text())['successful'])
        self.assertNotIn('teardown_complete',self.runner.inventory)


if __name__=='__main__':unittest.main()
