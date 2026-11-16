"""Fake-SDK current-only observations with real complete B pricing/lineage."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests'),str(ROOT/'src')]
import campaign_budget
import cost_scope_snapshot
import reconcile_current_campaign as driver
import test_amendment_cost_consumers as fixtures

NOW=datetime(2026,11,13,6,tzinfo=timezone.utc)


class CurrentCampaignCostTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.AmendmentCostConsumerTests();f.setUp();self.addCleanup(f.tearDown);self.f=f
        self.root=f.root;inv=f.new_inventory
        self.cluster=f'arn:aws:ecs:{f.f.region}:{f.f.account}:cluster/{f.f.new_project}-runtime'
        contract=inv['runtime_contract'];contract.update(cluster_arn=self.cluster,vpc_id='vpc-current',
            interface_endpoint_ids=[f'vpce-new-{n}' for n in range(5)],log_groups={'coordinator':'/'+f.f.new_project+'/runtime/coordinator'})
        f.f.put(f'results/aws/{f.f.new_campaign}/inventory.json',inv)
        self.dataset=f.f.put('data-manifest.json',{'partitions':{}});self.training=f.f.put('training.json',{'num_rounds':5})
        snap=cost_scope_snapshot.create(f.request_path,self.root/'snapshot-B-current',root=self.root,loader=driver.cost.load_scope)
        self.snapshot=self.root/snap['request']['path'];self.calls=[];self.raw_stop=datetime(2026,11,13,5,tzinfo=timezone.utc)
        self.clients={name:Mock() for name in ('sts','ecs','ec2','ecr','cloudwatch','ce')}
        self.clients['sts'].get_caller_identity.side_effect=self.identity
        self.clients['ecs'].describe_tasks.side_effect=self.tasks
        self.clients['ec2'].describe_vpc_endpoints.side_effect=self.endpoints
        self.clients['ecr'].describe_images.side_effect=self.images
        self.clients['cloudwatch'].get_metric_statistics.side_effect=self.logs

    def identity(self):self.calls.append(('sts',{}));return {'Account':self.f.f.account}

    def tasks(self,**kwargs):
        self.calls.append(('ecs',kwargs));self.assertEqual(kwargs['cluster'],self.cluster);self.assertEqual(kwargs['tasks'],[self.f.new_arn])
        return {'tasks':[{'taskArn':self.f.new_arn,'taskDefinitionArn':self.cluster.replace(':cluster/',':task-definition/')+':1',
            'lastStatus':'STOPPED','cpu':'256','memory':'1024','pullStartedAt':datetime(2026,11,13,4,tzinfo=timezone.utc),'stoppedAt':self.raw_stop}], 'failures':[]}

    def endpoints(self,**kwargs):
        self.calls.append(('ec2',kwargs));self.assertEqual(set(kwargs['VpcEndpointIds']),set(self.f.new_inventory['runtime_contract']['interface_endpoint_ids']))
        return {'VpcEndpoints':[{'VpcEndpointId':name,'VpcId':'vpc-current','State':'available',
            'Tags':[{'Key':'Project','Value':self.f.f.new_project}],'CreationTimestamp':datetime(2026,11,13,4,tzinfo=timezone.utc),'NetworkInterfaceIds':['eni-current']} for name in kwargs['VpcEndpointIds']]}

    def images(self,**kwargs):
        self.calls.append(('ecr',kwargs));self.assertEqual(kwargs['registryId'],self.f.f.account)
        self.assertEqual(kwargs['repositoryName'],self.f.f.new_project+'/coordinator')
        self.assertEqual(kwargs['imageIds'],[{'imageDigest':'sha256:'+'f'*64}])
        return {'imageDetails':[{'registryId':self.f.f.account,'repositoryName':kwargs['repositoryName'],
            'imageDigest':'sha256:'+'f'*64,'imageSizeInBytes':200000,'imagePushedAt':datetime(2026,11,13,3,tzinfo=timezone.utc)}]}

    def logs(self,**kwargs):
        self.calls.append(('logs',kwargs));self.assertEqual(kwargs['Dimensions'],[{'Name':'LogGroupName','Value':'/'+self.f.f.new_project+'/runtime/coordinator'}])
        return {'Datapoints':[{'Sum':1000}]}

    def invoke(self,**kwargs):
        f=self.f
        return driver.build_report(self.snapshot,catalog_path=self.root/f.catalog_ref['path'],
            data_manifest_path=self.root/self.dataset['path'],training_path=self.root/self.training['path'],
            prior_report_path=self.root/f.f.terminal_cost_ref['path'],prior_report_sha256=f.f.terminal_cost_ref['sha256'],
            root=self.root,clients=self.clients,clock=lambda:NOW,remaining_cells=0,**kwargs)

    def test_only_current_scope_is_queried_and_all_old_rows_are_still_priced(self):
        report=self.invoke()
        self.assertEqual(self.calls[0][0],'sts');self.assertTrue(report['current_spend_accounted'])
        self.assertEqual(report['current_scope_driver']['observed_campaign_ids'],[self.f.f.new_campaign])
        self.assertEqual(set(report['current_scope_driver']['priced_campaign_ids']),{self.f.f.old_campaign,self.f.f.new_campaign})
        self.assertEqual(set(report['resources']['tasks']),{*self.f.f.old_arns,self.f.new_arn})
        self.assertEqual(report['inherited_current_cost_floor_usd'],12)
        self.assertGreater(report['current_conservative_planning_estimate_usd'],12)
        self.assertTrue(report['current_scope_driver']['native_full_union_replay_verified'])
        self.assertEqual(report['image_pull_endpoint_planning_envelope']['missing_image_size_references'],[])
        self.assertFalse(report['actual_bill_reconciled']);self.clients['ce'].get_cost_and_usage.assert_not_called()
        self.assertTrue(any(ref['sha256']==self.f.f.terminal_cost_ref['sha256'] for ref in report['source_inputs']))

    def test_extra_current_usage_adds_above_old_floor_without_replacing_old_cost(self):
        first=self.invoke();self.raw_stop=NOW;second=self.invoke()
        self.assertEqual(first['inherited_current_cost_floor_usd'],second['inherited_current_cost_floor_usd'])
        self.assertAlmostEqual(second['current_conservative_planning_estimate_usd']-first['current_conservative_planning_estimate_usd'],.25*.04048+1*.004445)
        for arn in self.f.f.old_arns:self.assertEqual(first['resources']['tasks'][arn],second['resources']['tasks'][arn])

    def test_ancestor_quote_time_report_is_not_allowed_before_SDK(self):
        f=self.f
        with self.assertRaisesRegex(ValueError,'exact_approved_terminal'):
            driver.build_report(self.snapshot,catalog_path=self.root/f.catalog_ref['path'],data_manifest_path=self.root/self.dataset['path'],
                training_path=self.root/self.training['path'],prior_report_path=self.root/f.f.quote_cost_ref['path'],
                prior_report_sha256=f.f.quote_cost_ref['sha256'],root=self.root,clients=self.clients,clock=lambda:NOW,remaining_cells=0)
        self.assertEqual(self.calls,[])

    def test_missing_current_image_metadata_and_endpoint_errors_cannot_be_zero(self):
        self.clients['ecr'].describe_images.side_effect=RuntimeError('metadata unavailable')
        with self.assertRaisesRegex(ValueError,'observation_errors'):self.invoke()
        self.clients['ecr'].describe_images.side_effect=self.images
        self.clients['ec2'].describe_vpc_endpoints.return_value={'VpcEndpoints':[]};self.clients['ec2'].describe_vpc_endpoints.side_effect=None
        with self.assertRaisesRegex(ValueError,'complete_current_endpoint'):self.invoke()

    def test_missing_current_task_requires_original_terminal_observation(self):
        self.clients['ecs'].describe_tasks.side_effect=lambda **kwargs:{'tasks':[],'failures':[{'arn':self.f.new_arn,'reason':'MISSING'}]}
        report=self.invoke();self.assertEqual(report['current_scope_driver']['current_observations']['retained_current_STOPPED_observations'],1)
        req,approval,ledger,invs,_=driver.cost.load_scope(self.snapshot,root=self.root)
        observed=driver.cost.observe_resources(req,{req['campaign_id']:invs[req['campaign_id']]},now=NOW,clients=self.clients)
        invs[req['campaign_id']]['observed_tasks']=[]
        with self.assertRaisesRegex(ValueError,'no_retained_terminal'):
            driver._complete_observations(req,invs[req['campaign_id']],observed)

    def test_two_observed_AZ_ENIs_cannot_be_priced_as_frozen_one_AZ(self):
        def changed(**kwargs):
            response=self.endpoints(**kwargs)
            for row in response['VpcEndpoints']:row['NetworkInterfaceIds']=['eni-AZ-one','eni-AZ-two']
            return response
        self.clients['ec2'].describe_vpc_endpoints.side_effect=changed
        with self.assertRaisesRegex(ValueError,'complete_current_endpoint'):self.invoke()

    def test_live_request_is_not_a_frozen_replayable_cost_scope(self):
        with self.assertRaisesRegex(ValueError,'frozen_complete'):
            driver.build_report(self.f.request_path,catalog_path=self.root/self.f.catalog_ref['path'],
                data_manifest_path=self.root/self.dataset['path'],training_path=self.root/self.training['path'],
                prior_report_path=self.root/self.f.f.terminal_cost_ref['path'],prior_report_sha256=self.f.f.terminal_cost_ref['sha256'],
                root=self.root,clients=self.clients,clock=lambda:NOW,remaining_cells=0)
        self.assertEqual(self.calls,[])

    def test_frozen_scope_keeps_full_history_after_live_ledger_and_inventory_change(self):
        before=self.invoke()
        self.f.f.put(self.f.ledger_relative,{'changed-live-ledger':True})
        self.f.f.put(f'results/aws/{self.f.f.new_campaign}/inventory.json',{'changed-live-inventory':True})
        after=self.invoke()
        self.assertEqual(before['resources'],after['resources']);self.assertEqual(before['budget_lineage'],after['budget_lineage'])

    def test_CLI_retains_failed_observations_with_null_pricing_and_nonzero_exit(self):
        output=self.root/'failed-observation.json'
        observations={'tasks':[],'errors':[{'operation':'image_metadata','kind':'AccessDenied'}]}
        argv=['reconcile_current_campaign','--request',str(self.snapshot),'--prior-observations-report',str(self.root/self.f.f.terminal_cost_ref['path']),
            '--prior-observations-sha256',self.f.f.terminal_cost_ref['sha256'],'--output',str(output)]
        error=driver.CurrentObservationError('metadata incomplete',observations,[{'path':'retained.json','sha256':'a'*64}])
        with patch.object(driver,'ROOT',self.root),patch.object(driver,'build_report',side_effect=error),patch.object(sys,'argv',argv):
            self.assertEqual(driver.main(),1)
        report=json.loads(output.read_text());self.assertFalse(report['successful']);self.assertIsNone(report['pricing_totals'])
        self.assertEqual(report['current_observations'],observations);self.assertFalse(report['native_full_union_replay_verified'])


if __name__=='__main__':unittest.main()
