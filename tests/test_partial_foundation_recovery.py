"""Synthetic recovery boundaries; no actual AWS or clinical inputs."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

PROJECT_ROOT = next(path for path in Path(__file__).resolve().parents if (path / 'pyproject.toml').is_file())
sys.path[:0] = [str(PROJECT_ROOT / 'scripts'), str(PROJECT_ROOT / 'tests')]

import aws_campaign
import finalize_partial_foundation as recovery
from test_campaign_teardown import fixture, clients


class PartialFoundationRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for module in (recovery, aws_campaign):
            p = patch.object(module, 'ROOT', self.root); p.start(); self.addCleanup(p.stop)
        self.directory = self.root / 'results/aws/synthetic-deployment'; self.directory.mkdir(parents=True)
        self.path, self.inventory = fixture(self.directory)
        i = self.inventory; i.pop('teardown_complete'); i['removed_recorded_s3_versions'] = 4
        i['shutdown_confirmation']={'confirmed':True,'unresolved_task_arns':[],'uncertain_launch_tokens':[]}
        i['shared_fleet_ledger']={arn:{'last_status':'STOPPED'} for arn in i['task_arns']}
        self.repository = 'pcfl-synthetic/coordinator'; self.uri = '111111111111.dkr.ecr.us-east-1.amazonaws.com/' + self.repository
        raw = self.root / 'root-index.json'; raw.write_text('{"manifests":[]}')
        self.digest = 'sha256:' + self.sha(raw)
        i['image_history'] = [{'reference': self.uri + '@' + self.digest}]
        i['removed_owned_image_references'] = [self.uri + '@' + self.digest]
        i['foundation_variables'] = {'project_id': i['project_id']}
        current = Path(i['state_paths']['foundation']); prior = Path(i['pre_teardown_state_snapshots']['foundation']['path'])
        old = json.loads(prior.read_text()); item = next(row for row in old['resources'] if row['type']=='aws_ecr_repository' and row['instances'][0]['attributes']['name']==self.repository)
        item['instances'][0]['attributes'].update(id=self.repository,repository_url=self.uri)
        before = json.loads(current.read_text()); before['resources'] = [deepcopy(item)]
        current.write_text(json.dumps(before)); prior.write_text(json.dumps(old)); i['pre_teardown_state_snapshots']['foundation']['sha256']=self.sha(prior)
        self.path.write_text(json.dumps(i))
        self.request = {key:i[key] for key in ('account_id','region','project_id','campaign_id')}
        self.request['authorization']={'sha256':'a'*64}
        self.request_path=self.directory/'request.json';self.request_path.write_text(json.dumps(self.request))
        for name in recovery.REQUIRED_FILES:
            p=self.directory/name
            if not p.exists():p.write_text('synthetic retained failed attempt '+name)
        attempt=self.directory/'cleanup-attempts/one';attempt.mkdir(parents=True)
        rows=[]
        for name in sorted(recovery.REQUIRED_FILES):
            p=self.directory/name;q=attempt/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes())
            rows.append({'source':str(p),'retained':str(q),'sha256':self.sha(p),'size_bytes':p.stat().st_size})
        self.receipt=attempt/'receipt.json';self.receipt.write_text(json.dumps({'kind':'private-failed-cleanup-attempt-custody','terminal_teardown_claimed':False,'files':rows}))
        self.closure=self.root/'closure.json';self.closure.write_text(json.dumps({'kind':'read-only-recorded-OCI-index-ECR-manifest-closure-audit','account_id':i['account_id'],'region':i['region'],'inventory':self.ref(self.path),'foundation_state':self.ref(current),'all_remaining_digests_are_verified_exact_recorded_descendants':True,'unknown_remaining_digests':[],'repository':self.repository,'repository_uri':self.uri,'recorded_index_roots':[{'index_digest':self.digest,'raw_index':self.ref(raw)}],'remaining_images':[]}))
        self.runner=recovery.PartialFoundationRunner(self.request,apply=True)
        self.runner.recovery={'receipt_ref':self.ref(self.receipt),'closure_ref':self.ref(self.closure),'expected_inventory_sha256':self.sha(self.path),'expected_request_sha256':self.sha(self.request_path)}
        self.aws,self.calls=clients({('ecr','describe_repositories'):lambda kw:({'repositories':[{'repositoryName':self.repository}]} if kw['repositoryNames']==[self.repository] else self.absent_repo()),('ecr','list_images'):{'imageIds':[]}})
        self.runner.absence_clients=self.aws
        ownership=self.root/'results/aws/project-ownership.json';ownership.write_text(json.dumps({':'.join(self.request[k] for k in ('account_id','region','project_id')):i['campaign_id']}))
        self.runner.terraform_step=Mock(side_effect=self.destroy)

    @staticmethod
    def absent_repo():
        from test_campaign_teardown import AwsError
        raise AwsError('RepositoryNotFoundException')

    @staticmethod
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

    def ref(self,p):return {'path':str(p),'sha256':self.sha(p),'size_bytes':p.stat().st_size}

    def destroy(self,stack,variables,*,destroy):
        self.assertEqual(stack,'foundation');self.assertTrue(destroy)
        p=Path(self.inventory['state_paths']['foundation']);s=json.loads(p.read_text());s['resources']=[];s['serial']+=1;p.write_text(json.dumps(s))

    def test_exact_local_custody_and_empty_repository_finalize_foundation_only(self):
        result=self.runner.teardown()
        self.assertTrue(result['teardown_complete']);self.assertTrue(self.runner.inventory['teardown_complete'])
        self.runner.terraform_step.assert_called_once_with('foundation',self.inventory['foundation_variables'],destroy=True)
        self.assertTrue(self.calls);self.assertEqual(self.calls[0][0:2],('sts','get_caller_identity'))
        self.assertFalse(any(op.startswith(('put_','delete_','update_','batch_delete','run_','stop_')) for _,op,_ in self.calls))
        self.assertEqual(json.loads((self.root/'results/aws/project-ownership.json').read_text()),{})

    def test_inherits_normal_execute_authorization_and_lock_path(self):
        self.assertIs(recovery.PartialFoundationRunner.execute,aws_campaign.CampaignRunner.execute)
        self.assertIs(recovery.PartialFoundationRunner.authorize,aws_campaign.CampaignRunner.authorize)
        with patch.object(self.runner,'authorize',side_effect=ValueError('denied')):
            with self.assertRaisesRegex(ValueError,'denied'):self.runner.execute('teardown')
        self.assertFalse(self.calls);self.runner.terraform_step.assert_not_called()

    def test_same_scope_alternate_request_cannot_use_canonical_request_SHA(self):
        self.runner.request={**self.runner.request,'local_image_tag':'rebound-same-project'}
        with self.assertRaisesRegex(ValueError,'exact_pinned_canonical_request'):self.runner.teardown()
        self.assertFalse(self.calls);self.runner.terraform_step.assert_not_called()

    def test_nonempty_repository_blocks_Terraform_and_completion(self):
        self.aws,self.calls=clients({('ecr','describe_repositories'):lambda kw:({'repositories':[{'repositoryName':self.repository}]} if kw['repositoryNames']==[self.repository] else self.absent_repo()),('ecr','list_images'):{'imageIds':[{'imageDigest':'sha256:'+'b'*64}]}})
        self.runner.absence_clients=self.aws
        with self.assertRaisesRegex(ValueError,'observed_empty'):self.runner.teardown()
        self.runner.terraform_step.assert_not_called();self.assertNotIn('teardown_complete',self.runner.inventory)

    def test_present_bucket_or_unknown_DDB_never_skips_to_final_destroy(self):
        from test_campaign_teardown import AwsError
        for override in ({('s3','get_bucket_location'):{}}, {('dynamodb','describe_table'):lambda kw:(_ for _ in ()).throw(AwsError('AccessDeniedException'))}):
            with self.subTest(override=list(override)):
                self.runner.absence_clients,_=clients(override)
                with self.assertRaisesRegex(ValueError,'not_confirmed_absent'):self.runner.teardown()
                self.runner.terraform_step.assert_not_called()

    def test_CAS_or_retained_failed_attempt_log_change_rejects_before_SDK(self):
        (self.directory/'foundation-destroy-3.log').write_text('changed')
        with self.assertRaisesRegex(ValueError,'original_bytes_changed'):self.runner.teardown()
        self.assertFalse(self.calls);self.runner.terraform_step.assert_not_called()

    def test_default_final_validator_still_rejects_nonempty_foundation(self):
        with self.assertRaisesRegex(ValueError,'stack_not_empty'):
            recovery.resource_targets(self.inventory,self.directory)

    def test_foreign_new_resource_and_runtime_remaining_are_not_recoverable(self):
        for stack in ('foundation','runtime'):
            p=Path(self.inventory['state_paths'][stack]);original=p.read_bytes();s=json.loads(original);s['resources'].append({'mode':'managed','type':'aws_s3_bucket','name':'foreign','instances':[{'attributes':{'id':'foreign'}}]});p.write_text(json.dumps(s))
            with self.assertRaises(ValueError):self.runner.teardown()
            self.runner.terraform_step.assert_not_called();p.write_bytes(original)

    def test_changed_local_export_or_manifest_custody_blocks_cleanup(self):
        model=self.directory/'r'/hashlib.sha256(b'synthetic-S0').hexdigest()[:8]/'model.npz';model.write_bytes(b'tampered')
        with self.assertRaises(ValueError):self.runner.teardown()
        self.assertFalse(self.calls);self.runner.terraform_step.assert_not_called()

    def test_uncertain_launch_or_unconfirmed_shared_task_never_becomes_absence(self):
        for field, value in (('launch_intents',{'unknown':{'state':'issuing'}}),('shared_fleet_ledger',{})):
            original=self.runner.inventory.get(field)
            self.runner.inventory[field]=value;self.path.write_text(json.dumps(self.runner.inventory))
            self.runner.recovery['expected_inventory_sha256']=self.sha(self.path)
            with self.assertRaisesRegex(ValueError,'no_uncertain_launches'):self.runner.teardown()
            self.runner.terraform_step.assert_not_called()
            if original is None:self.runner.inventory.pop(field)
            else:self.runner.inventory[field]=original


if __name__=='__main__':unittest.main()
