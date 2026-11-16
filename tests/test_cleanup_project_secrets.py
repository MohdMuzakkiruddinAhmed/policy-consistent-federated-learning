"""Synthetic exact generated-secret metadata, force/delete and absence checks."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts'))

from botocore.exceptions import ClientError, EndpointConnectionError
import aws_campaign
import cleanup_project_secrets as cleanup


class SecretCleanupTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        for module in (cleanup,aws_campaign):
            p=patch.object(module,'ROOT',self.root);p.start();self.addCleanup(p.stop)
        self.project='pcfl-synthetic';self.account='111111111111';self.campaign='synthetic-cleanup'
        self.directory=self.root/'results/aws'/self.campaign;self.directory.mkdir(parents=True)
        payloads=self.directory/'secret-payloads';payloads.mkdir()
        entries=[];arns={};versions={};instances=[]
        for name in sorted(cleanup.NAMES):
            p=payloads/(name+'.json');p.write_text(json.dumps({'synthetic-only':name}));digest=hashlib.sha256(p.read_text().encode()).hexdigest()
            arn=f'arn:aws:secretsmanager:us-east-1:{self.account}:secret:{self.project}/runtime/{name}-Ab12Cd'
            entries.append({'logical_name':name,'payload_path':str(p)});arns[name]=arn;versions[name]={'arn':arn,'sha256':digest,'version_id':digest}
            instances.append({'index_key':name,'attributes':{'arn':arn,'name':self.project+'/runtime/'+name,'tags_all':{'Project':self.project},'recovery_window_in_days':7}})
        state=self.directory/'before-runtime.json';state.write_text(json.dumps({'resources':[{'type':'aws_secretsmanager_secret','instances':instances}]}))
        self.request={'account_id':self.account,'region':'us-east-1','project_id':self.project,'campaign_id':self.campaign,'secrets':entries,'authorization':{'sha256':'a'*64}}
        self.inventory={**{k:self.request[k] for k in ('account_id','region','project_id','campaign_id')},'runtime_contract':{'secret_arns':arns},'secret_versions':versions,'pre_teardown_state_snapshots':{'runtime':self.ref(state)}}
        self.inventory_path=self.directory/'inventory.json';self.inventory_path.write_text(json.dumps(self.inventory))
        self.sts=Mock();self.sts.get_caller_identity.return_value={'Account':self.account};self.sm=Mock();self.removed=set()
        self.sm.describe_secret.side_effect=self.describe;self.sm.delete_secret.side_effect=self.delete
        self.runner=cleanup.SecretCleanupRunner(self.request,apply=True,clients={'sts':self.sts,'secretsmanager':self.sm},sleep=Mock())
        self.runner.recovery={'expected_inventory_sha256':self.sha(self.inventory_path),'expected_request_sha256':'b'*64,'receipt_ref':{},'closure_ref':{}}
        p=patch.object(cleanup,'local_guards',side_effect=self.guard);p.start();self.addCleanup(p.stop)

    @staticmethod
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

    def ref(self,p):return {'path':str(p),'sha256':self.sha(p)}

    def guard(self,runner,**values):
        if self.sha(self.inventory_path)!=values['expected_inventory_sha256']:raise ValueError('CAS_failed')
        return {}

    def describe(self,*,SecretId):
        name=next(k for k,v in self.inventory['runtime_contract']['secret_arns'].items() if v==SecretId)
        if SecretId in self.removed:raise ClientError({'Error':{'Code':'ResourceNotFoundException'}},'DescribeSecret')
        return {'ARN':SecretId,'Name':self.project+'/runtime/'+name,'Tags':[{'Key':'Project','Value':self.project}],
            'DeletedDate':datetime(2026,11,13,tzinfo=timezone.utc),'VersionIdsToStages':{self.inventory['secret_versions'][name]['version_id']:['AWSCURRENT']}}

    def delete(self,*,SecretId,ForceDeleteWithoutRecovery):
        self.assertTrue(ForceDeleteWithoutRecovery);self.removed.add(SecretId)
        return {'ARN':SecretId,'Name':self.describe_name(SecretId)}

    def describe_name(self,arn):return arn.split(':secret:',1)[1].rsplit('-',1)[0]

    def pin_preview(self):
        report=self.runner.operation(delete=False);self.assertTrue(report['successful'],report)
        p=self.root/'preview.json';p.write_text(json.dumps(report));self.runner.preview_ref=self.ref(p)
        return report

    def test_preview_exact16_metadata_and_source_hashes_without_secret_values_or_mutation(self):
        r=self.runner.operation(delete=False)
        self.assertTrue(r['successful']);self.assertEqual(len(r['selected_sources']),16);self.assertFalse(r['aws_mutations'])
        self.sm.delete_secret.assert_not_called();self.sm.get_secret_value.assert_not_called();self.sm.restore_secret.assert_not_called();self.sm.list_secrets.assert_not_called()

    def test_direct_force_exactARNs_only_and_actual_notfound_required(self):
        self.pin_preview();r=self.runner.operation(delete=True)
        self.assertTrue(r['successful'],r);self.assertTrue(r['all_selected_secrets_absent']);self.assertEqual(len(r['actions']),16)
        self.assertEqual({call.kwargs['SecretId'] for call in self.sm.delete_secret.call_args_list},set(self.inventory['runtime_contract']['secret_arns'].values()))
        self.assertTrue(all(set(call.kwargs)=={'SecretId','ForceDeleteWithoutRecovery'} for call in self.sm.delete_secret.call_args_list))
        self.sm.get_secret_value.assert_not_called();self.sm.restore_secret.assert_not_called()

    def test_successful_delete_ack_but_still_scheduled_cannot_pass(self):
        self.pin_preview();self.sm.delete_secret.side_effect=lambda **kw:{'ARN':kw['SecretId'],'Name':self.describe_name(kw['SecretId'])};self.runner.polls=2
        r=self.runner.operation(delete=True)
        self.assertFalse(r['successful']);self.assertFalse(r['all_selected_secrets_absent']);self.assertEqual(r['readback_attempts'],2)

    def test_wrong_project_unscheduled_or_changed_version_fail_before_first_mutation(self):
        self.pin_preview()
        for field,value in [('Tags',[{'Key':'Project','Value':'foreign'}]),('DeletedDate',None),('VersionIdsToStages',{})]:
            with self.subTest(field=field):
                self.sm.describe_secret.side_effect=lambda **kw:{**self.describe(**kw),field:value}
                r=self.runner.operation(delete=True);self.assertFalse(r['successful']);self.sm.delete_secret.assert_not_called()

    def test_unregistered_extra_secret_payload_rebound_or_prestate_missing_fail_closed(self):
        self.request['secrets'][0]['logical_name']='user-account-password'
        r=self.runner.operation(delete=False);self.assertFalse(r['successful']);self.sm.describe_secret.assert_not_called()
        self.request['secrets'][0]['logical_name']=sorted(cleanup.NAMES)[0]
        Path(self.request['secrets'][0]['payload_path']).write_text('changed')
        r=self.runner.operation(delete=False);self.assertFalse(r['successful']);self.sm.describe_secret.assert_not_called()

    def test_identity_mismatch_or_unknown_metadata_failure_stops_without_mutation(self):
        self.sts.get_caller_identity.return_value={'Account':'999999999999'}
        r=self.runner.operation(delete=False);self.assertFalse(r['successful']);self.sm.describe_secret.assert_not_called()
        self.sts.get_caller_identity.return_value={'Account':self.account}
        self.sm.describe_secret.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'DescribeSecret')
        r=self.runner.operation(delete=False);self.assertFalse(r['successful']);self.sm.delete_secret.assert_not_called()

    def test_generic_exception_cannot_impersonate_notfound(self):
        class PretendNotFound(Exception):
            response={'Error':{'Code':'ResourceNotFoundException'}}
        self.sm.describe_secret.side_effect=PretendNotFound('not an AWS ClientError')
        r=self.runner.operation(delete=True)
        self.assertFalse(r['successful']);self.assertFalse(r['all_selected_secrets_absent']);self.sm.delete_secret.assert_not_called()

    def test_unpinned_or_rebound_preview_cannot_authorize_deletion(self):
        self.runner.preview_ref={'path':str(self.root/'missing.json'),'sha256':'a'*64}
        r=self.runner.operation(delete=True);self.assertFalse(r['successful']);self.sm.delete_secret.assert_not_called()

    def test_ambiguous_delete_failure_retains_attempt_and_never_claims_absence(self):
        self.pin_preview();self.sm.delete_secret.side_effect=EndpointConnectionError(endpoint_url='https://secrets.invalid')
        r=self.runner.operation(delete=True)
        self.assertFalse(r['successful']);self.assertTrue(r['aws_mutation_attempted']);self.assertEqual(len(r['actions']),1);self.assertFalse(r['actions'][0]['acknowledged']);self.assertFalse(r['all_selected_secrets_absent'])

    def test_master_CAS_change_during_metadata_prevents_mutation(self):
        self.pin_preview()
        def changed(**kw):
            value=self.describe(**kw);self.inventory_path.write_text('{}');return value
        self.sm.describe_secret.side_effect=changed;r=self.runner.operation(delete=True)
        self.assertFalse(r['successful']);self.assertFalse(r['inventory_unchanged']);self.sm.delete_secret.assert_not_called()

    def test_apply_inherits_standard_authorization_operation_dispatch(self):
        self.assertIs(cleanup.SecretCleanupRunner.execute,aws_campaign.CampaignRunner.execute)
        with patch.object(self.runner,'authorize',side_effect=ValueError('denied')):
            with self.assertRaisesRegex(ValueError,'denied'):self.runner.execute('teardown')
        self.sm.delete_secret.assert_not_called()


if __name__=='__main__':unittest.main()
