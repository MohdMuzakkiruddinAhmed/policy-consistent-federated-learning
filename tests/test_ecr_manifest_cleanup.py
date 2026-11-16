"""Content-addressed synthetic OCI graphs and fake ECR only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError

ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
sys.path[:0]=[str(ROOT/'scripts')]
import ecr_manifest_cleanup as cleanup

OCI_IMAGE='application/vnd.oci.image.manifest.v1+json'
OCI_INDEX='application/vnd.oci.image.index.v1+json'


def body(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False)
def digest(value):return 'sha256:'+hashlib.sha256(value.encode()).hexdigest()
def image(marker,*,attestation=False):
    return body({'schemaVersion':2,'mediaType':OCI_IMAGE,
        'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+'a'*64,'size':2},
        'layers':[{'mediaType':'application/vnd.in-toto+json' if attestation else 'application/vnd.oci.image.layer.v1.tar+gzip',
            'digest':'sha256:'+'b'*64,'size':20}], 'annotations':{'synthetic-marker':marker}})
def index(*children):
    return body({'schemaVersion':2,'mediaType':OCI_INDEX,'manifests':[{'digest':digest(item),'size':len(item.encode()),
        'mediaType':json.loads(item)['mediaType'],'platform':{'os':'unknown' if number else 'linux','architecture':'unknown' if number else 'amd64'},
        **({'annotations':{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':digest(children[0])}} if number else {})}
        for number,item in enumerate(children)]})


class ECRManifestCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.directory=Path(self.temp.name)
        self.account,self.region,self.project='123456789012','us-east-1','pcfl-fixture'
        self.name=self.project+'/coordinator';self.uri=f'{self.account}.dkr.ecr.{self.region}.amazonaws.com/{self.name}'
        self.arn=f'arn:aws:ecr:{self.region}:{self.account}:repository/{self.name}'
        self.leaf,self.attestation=image('runtime'),image('attestation',attestation=True)
        self.root=index(self.leaf,self.attestation);self.root_digest=digest(self.root)
        self.remote={digest(item):item for item in (self.root,self.leaf,self.attestation)}
        self.inventory={'account_id':self.account,'region':self.region,'project_id':self.project,'campaign_id':'synthetic-campaign',
            'foundation':{'image_repositories':{'coordinator':self.uri}},'image_history':[{'reference':self.uri+'@'+self.root_digest}],
            'image':{'reference':self.uri+'@'+self.root_digest}}
        self.exists=True;self.ecr=Mock();self.operations=[]
        self.ecr.meta.region_name=self.region
        self.ecr.describe_repositories.side_effect=self.describe
        self.ecr.list_tags_for_resource.return_value={'tags':[{'Key':'Project','Value':self.project}]}
        self.ecr.batch_get_image.side_effect=self.get
        self.ecr.list_images.side_effect=self.list
        self.ecr.batch_delete_image.side_effect=self.delete

    def target(self,kwargs):
        self.assertEqual(kwargs['registryId'],self.account)
        self.assertEqual(kwargs.get('repositoryName',kwargs.get('repositoryNames',[None])[0]),self.name)

    def describe(self,**kwargs):
        self.target(kwargs)
        if not self.exists:raise ClientError({'Error':{'Code':'RepositoryNotFoundException'}},'DescribeRepositories')
        return {'repositories':[{'registryId':self.account,'repositoryName':self.name,'repositoryUri':self.uri,'repositoryArn':self.arn}]}

    def get(self,**kwargs):
        self.target(kwargs);item=kwargs['imageIds'][0]['imageDigest'];self.operations.append(('get',item))
        if item not in self.remote:return {'images':[],'failures':[{'failureCode':'ImageNotFound','imageId':{'imageDigest':item}}]}
        value=self.remote[item]
        return {'images':[{'registryId':self.account,'repositoryName':self.name,'imageId':{'imageDigest':item},
            'imageManifest':value,'imageManifestMediaType':json.loads(value)['mediaType']}],'failures':[]}

    def list(self,**kwargs):
        self.target(kwargs);self.assertEqual(kwargs['filter'],{'tagStatus':'ANY'})
        return {'imageIds':[{'imageDigest':item} for item in sorted(self.remote)]}

    def delete(self,**kwargs):
        self.target(kwargs);item=kwargs['imageIds'][0]['imageDigest'];self.operations.append(('delete',item))
        for parent,value in self.remote.items():
            if parent!=item and item in [row['digest'] for row in json.loads(value).get('manifests',[])]:
                return {'imageIds':[],'failures':[{'failureCode':'ImageReferencedByManifestList','imageId':{'imageDigest':item}}]}
        if item not in self.remote:return {'imageIds':[],'failures':[{'failureCode':'ImageNotFound','imageId':{'imageDigest':item}}]}
        del self.remote[item]
        return {'imageIds':[{'imageDigest':item,'imageTag':'synthetic-tag'}],'failures':[]}

    def retain(self,prior=None):return cleanup.retain_image_graph(self.ecr,self.inventory,directory=self.directory,prior_graph=prior)
    def remove(self,binding):return cleanup.delete_image_graph(self.ecr,self.inventory,directory=self.directory,graph_binding=binding)

    def test_index_leaf_attestation_retained_before_parent_first_exact_deletion(self):
        binding=self.retain();path=Path(binding['path']);self.assertTrue(path.is_file())
        graph=cleanup.load_graph(binding,self.inventory,self.directory)
        self.assertEqual(set(graph['repositories'][self.uri]['nodes']),set(self.remote))
        self.assertEqual({item for kind,item in self.operations if kind=='get'},set(self.remote))
        self.assertNotIn('sha256:'+'a'*64,[item for _,item in self.operations])
        self.ecr.batch_delete_image.assert_not_called()
        receipt=self.remove(binding)
        self.assertTrue(receipt['successful']);self.assertFalse(receipt['force_delete_used']);self.assertFalse(self.remote)
        deleted=[item for kind,item in self.operations if kind=='delete']
        self.assertEqual(deleted[0],self.root_digest);self.assertEqual(set(deleted),{digest(self.root),digest(self.leaf),digest(self.attestation)})
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),binding['sha256'])

    def test_unknown_remote_digest_cannot_be_adopted_or_deleted(self):
        binding=self.retain();foreign=image('unrecorded');self.remote[digest(foreign)]=foreign
        with self.assertRaisesRegex(ValueError,'outside_verified'):self.remove(binding)
        self.ecr.batch_delete_image.assert_not_called();self.assertIn(digest(foreign),self.remote)

    def test_wrong_manifest_SHA_or_response_scope_fails_before_any_deletion(self):
        original_get=self.get
        for field in ('bytes','account','repository','digest','media'):
            def rebound(**kwargs):
                result=original_get(**kwargs);row=result['images'][0]
                if field=='bytes':row['imageManifest']+=' '
                if field=='account':row['registryId']='999999999999'
                if field=='repository':row['repositoryName']='foreign/repository'
                if field=='digest':row['imageId']['imageDigest']='sha256:'+'e'*64
                if field=='media':row['imageManifestMediaType']=OCI_IMAGE
                return result
            self.ecr.batch_get_image.side_effect=rebound
            with self.assertRaises(ValueError):self.retain()
        self.ecr.batch_delete_image.assert_not_called()

    def test_foreign_account_repo_or_project_tag_cannot_reach_deletion(self):
        for field in ('root','foundation','account'):
            changed=deepcopy(self.inventory)
            if field=='root':changed['image']['reference']='999999999999.dkr.ecr.us-east-1.amazonaws.com/foreign/coordinator@'+self.root_digest
            if field=='foundation':changed['foundation']['image_repositories']['coordinator']='999999999999.dkr.ecr.us-east-1.amazonaws.com/foreign/coordinator'
            if field=='account':changed['account_id']='999999999999'
            with self.assertRaises(ValueError):cleanup.retain_image_graph(self.ecr,changed,directory=self.directory)
        self.ecr.list_tags_for_resource.return_value={'tags':[{'Key':'Project','Value':'different-project'}]}
        with self.assertRaisesRegex(ValueError,'project_tag'):self.retain()
        self.ecr.batch_delete_image.assert_not_called()

    def test_partial_retry_uses_retained_graph_when_parent_already_deleted(self):
        binding=self.retain();original_delete=self.delete
        def interrupt(**kwargs):
            if kwargs['imageIds'][0]['imageDigest']!=self.root_digest:raise RuntimeError('synthetic_after_parent_deletion')
            return original_delete(**kwargs)
        self.ecr.batch_delete_image.side_effect=interrupt
        with self.assertRaisesRegex(RuntimeError,'synthetic_after_parent'):self.remove(binding)
        self.assertNotIn(self.root_digest,self.remote)
        recovered=self.retain(binding);self.assertEqual(recovered,binding)
        self.ecr.batch_delete_image.side_effect=self.delete
        self.assertTrue(self.remove(recovered)['successful']);self.assertFalse(self.remote)

    def test_missing_parent_without_raw_retained_graph_is_never_inferred_from_repository(self):
        del self.remote[self.root_digest]
        with self.assertRaisesRegex(ValueError,'without_retained_content'):self.retain()
        self.ecr.list_images.assert_not_called();self.ecr.batch_delete_image.assert_not_called()

    def test_corrupt_or_wrong_root_prior_graph_rejects_before_provider_reads(self):
        binding=self.retain();bad=deepcopy(binding);bad['sha256']='e'*64
        self.ecr.describe_repositories.reset_mock()
        with self.assertRaisesRegex(ValueError,'file_hash'):self.retain(bad)
        self.ecr.describe_repositories.assert_not_called()
        changed=deepcopy(self.inventory);changed['image_history']=[];changed['image']['reference']=self.uri+'@'+digest(self.leaf)
        with self.assertRaisesRegex(ValueError,'root_mismatch'):
            cleanup.retain_image_graph(self.ecr,changed,directory=self.directory,prior_graph=binding)

    def test_descriptor_size_and_unreachable_nodes_are_checked(self):
        value=json.loads(self.root);value['manifests'][0]['size']+=1;wrong=body(value)
        self.inventory['image_history']=[];self.inventory['image']['reference']=self.uri+'@'+digest(wrong);self.remote[digest(wrong)]=wrong
        with self.assertRaisesRegex(ValueError,'size_or_media'):self.retain()
        self.ecr.batch_delete_image.assert_not_called()

    def test_final_readback_never_claims_success_if_new_unknown_manifest_appears(self):
        binding=self.retain();original_delete=self.delete;unknown=image('late-unrecorded')
        def concurrent(**kwargs):
            result=original_delete(**kwargs)
            if kwargs['imageIds'][0]['imageDigest']==self.root_digest:self.remote[digest(unknown)]=unknown
            return result
        self.ecr.batch_delete_image.side_effect=concurrent
        with self.assertRaisesRegex(RuntimeError,'not_confirmed_empty'):self.remove(binding)
        self.assertIn(digest(unknown),self.remote)
        self.assertNotIn(digest(unknown),[item for kind,item in self.operations if kind=='delete'])

    def test_repository_absence_only_uses_exact_SDK_notfound_and_requires_prior_graph(self):
        binding=self.retain();self.exists=False;self.remote.clear()
        self.assertEqual(self.retain(binding),binding);self.assertTrue(self.remove(binding)['successful'])
        self.ecr.describe_repositories.side_effect=ClientError({'Error':{'Code':'AccessDeniedException'}},'DescribeRepositories')
        with self.assertRaises(ClientError):self.remove(binding)
        self.ecr.describe_repositories.side_effect=RuntimeError('RepositoryNotFoundException string is not an SDK response')
        with self.assertRaises(RuntimeError):self.remove(binding)

    def test_paginated_unknown_manifest_is_found_before_any_delete(self):
        binding=self.retain();unknown=digest(image('unknown-on-page-two'))
        def pages(**kwargs):
            self.target(kwargs)
            return {'imageIds':[{'imageDigest':unknown}]} if kwargs.get('nextToken') else {'imageIds':[{'imageDigest':self.root_digest}],'nextToken':'page-two'}
        self.ecr.list_images.side_effect=pages
        with self.assertRaisesRegex(ValueError,'outside_verified'):self.remove(binding)
        self.ecr.batch_delete_image.assert_not_called()

    def test_shared_child_and_second_recorded_root_are_deleted_once(self):
        second=index(self.leaf);second_digest=digest(second);self.remote[second_digest]=second
        self.inventory['image_history'].append({'reference':self.uri+'@'+second_digest})
        binding=self.retain();self.remove(binding)
        deleted=[item for kind,item in self.operations if kind=='delete']
        self.assertEqual(len(deleted),4);self.assertEqual(len(set(deleted)),4)
        self.assertLess(deleted.index(second_digest),deleted.index(digest(self.leaf)))

    def test_wrong_delete_acknowledgement_does_not_pass(self):
        binding=self.retain();self.ecr.batch_delete_image.return_value={'imageIds':[{'imageDigest':'sha256:'+'f'*64}],'failures':[]}
        self.ecr.batch_delete_image.side_effect=None
        with self.assertRaisesRegex(RuntimeError,'not_confirmed'):self.remove(binding)

    def test_weak_subject_and_blob_references_do_not_expand_cleanup_authority(self):
        value=json.loads(self.attestation);value['subject']={'mediaType':OCI_IMAGE,'digest':'sha256:'+'f'*64,'size':100}
        attestation=body(value);root=index(self.leaf,attestation)
        self.remote={digest(item):item for item in (root,self.leaf,attestation)}
        self.inventory['image_history']=[];self.inventory['image']['reference']=self.uri+'@'+digest(root)
        binding=self.retain();self.remove(binding)
        self.assertNotIn('sha256:'+'f'*64,[item for _,item in self.operations])

    def test_no_published_images_grants_empty_authority_not_missing_repository_adoption(self):
        empty=deepcopy(self.inventory);empty['foundation']['image_repositories']={};empty['image_history']=[];empty.pop('image')
        binding=cleanup.retain_image_graph(self.ecr,empty,directory=self.directory)
        receipt=cleanup.delete_image_graph(self.ecr,empty,directory=self.directory,graph_binding=binding)
        self.assertEqual(receipt['removed'],[]);self.assertEqual(receipt['repositories_confirmed_empty_or_absent'],[])
        self.ecr.describe_repositories.assert_not_called();self.ecr.batch_delete_image.assert_not_called()
        empty['image']={'reference':self.uri+'@'+self.root_digest}
        with self.assertRaisesRegex(ValueError,'outside_exact_recorded'):
            cleanup.retain_image_graph(self.ecr,empty,directory=self.directory)

    def test_all_read_and_delete_parameters_match_installed_official_SDK_models(self):
        from botocore.session import get_session
        from botocore.validate import validate_parameters
        model=get_session().get_service_model('ecr')
        names={'describe_repositories':'DescribeRepositories','list_tags_for_resource':'ListTagsForResource',
            'batch_get_image':'BatchGetImage','list_images':'ListImages','batch_delete_image':'BatchDeleteImage'}
        self.remove(self.retain())
        for call in self.ecr.method_calls:
            validate_parameters(call.kwargs,model.operation_model(names[call[0]]).input_shape)

    def test_duplicate_manifest_JSON_fields_fail_even_with_matching_recorded_digest(self):
        duplicate=self.root.replace('{"schemaVersion":2,','{"schemaVersion":2,"schemaVersion":2,',1)
        self.remote[digest(duplicate)]=duplicate
        self.inventory['image_history']=[];self.inventory['image']['reference']=self.uri+'@'+digest(duplicate)
        with self.assertRaisesRegex(ValueError,'duplicate_manifest_JSON_key'):self.retain()
        self.ecr.batch_delete_image.assert_not_called()

    def test_wrong_client_region_cannot_turn_other_region_notfound_into_absence(self):
        self.ecr.meta.region_name='us-west-2';self.exists=False
        with self.assertRaisesRegex(ValueError,'client_region'):self.retain()
        self.ecr.describe_repositories.assert_not_called();self.ecr.batch_delete_image.assert_not_called()
