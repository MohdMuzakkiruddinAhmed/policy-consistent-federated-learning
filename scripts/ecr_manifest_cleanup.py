"""Retain verified owned image-manifest closure before exact digest cleanup.

Only manifest descriptors in recorded roots extend cleanup authority. Config
and layer blobs, weak subject references and discovered repository contents do
not. Callers establish STS identity and the campaign operation lock first.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

DIGEST=re.compile(r'sha256:[0-9a-f]{64}')
INDEX={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}
IMAGE={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
MAX_NODES=1000
MAX_MANIFEST=4*1024*1024
MAX_TOTAL=16*1024*1024


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(body):return hashlib.sha256(body).hexdigest()


def strict_json(value):
    def unique(pairs):
        result={}
        for key,item in pairs:
            if key in result:raise ValueError('duplicate_manifest_JSON_key')
            result[key]=item
        return result
    def invalid(_):raise ValueError('nonfinite_manifest_JSON_value')
    return json.loads(value,object_pairs_hook=unique,parse_constant=invalid)


def scope(inventory):
    account,region,project,campaign=(inventory[key] for key in ('account_id','region','project_id','campaign_id'))
    if (not re.fullmatch(r'[0-9]{12}',account) or not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]',region)
            or not re.fullmatch(r'[a-z][a-z0-9-]{2,35}',project)):
        raise ValueError('owned_ECR_account_region_project_required')
    prefix=f'{account}.dkr.ecr.{region}.amazonaws.com/'
    repositories={}
    for uri in inventory['foundation']['image_repositories'].values():
        if (not isinstance(uri,str) or not uri.startswith(prefix+project+'/')
                or not re.fullmatch(r'[a-z0-9]+(?:[._/-][a-z0-9]+)*',uri[len(prefix):])):
            raise ValueError('ECR_repository_outside_recorded_owned_scope')
        name=uri[len(prefix):]
        repositories[uri]={'repository_name':name,'repository_arn':f'arn:aws:ecr:{region}:{account}:repository/{name}',
            'root_digests':[],'nodes':{}}
    # An explicit empty map grants no image authority. Any recorded root below
    # still fails membership; this supports cleanup before image publication.
    references={row['reference'] for row in inventory.get('image_history',[])}
    if inventory.get('image'):references.add(inventory['image']['reference'])
    for reference in sorted(references):
        parts=reference.split('@')
        if len(parts)!=2 or parts[0] not in repositories or not DIGEST.fullmatch(parts[1]):
            raise ValueError('ECR_root_outside_exact_recorded_repositories')
        repositories[parts[0]]['root_digests'].append(parts[1])
    return {'schema_version':'0.1.0','kind':'owned-ecr-image-manifest-closure','account_id':account,
        'region':region,'project_id':project,'campaign_id':campaign,'repositories':repositories}


def descriptor(value):
    if (not isinstance(value,dict) or not isinstance(value.get('digest'),str) or not DIGEST.fullmatch(value['digest'])
            or type(value.get('size')) is not int or not 0<value['size']<=MAX_MANIFEST
            or value.get('mediaType') not in INDEX|IMAGE):
        raise ValueError('supported_content_addressed_manifest_descriptor_required')
    return value['digest'],value['size'],value['mediaType']


def parse_manifest(digest,body,media_type=None):
    if not isinstance(body,str):raise ValueError('raw_UTF8_manifest_string_required')
    raw=body.encode('utf-8')
    if not raw or len(raw)>MAX_MANIFEST or 'sha256:'+sha(raw)!=digest:raise ValueError('ECR_manifest_SHA256_mismatch')
    value=strict_json(body)
    if (not isinstance(value,dict) or type(value.get('schemaVersion')) is not int or value['schemaVersion']!=2
            or value.get('mediaType') not in INDEX|IMAGE or (media_type is not None and value['mediaType']!=media_type)):
        raise ValueError('supported_ECR_manifest_media_type_required')
    children=[]
    if value['mediaType'] in INDEX:
        if not isinstance(value.get('manifests'),list):raise ValueError('index_manifest_descriptors_required')
        children=[descriptor(item) for item in value['manifests']]
    else:
        # These are blobs, not ECR image manifests. Never recurse into them.
        if not isinstance(value.get('config'),dict) or not isinstance(value.get('layers'),list):
            raise ValueError('image_config_and_layers_required')
    return {'manifest':body,'media_type':value['mediaType'],'size_bytes':len(raw),
        'children':sorted({item[0] for item in children})},children


def graph_order(nodes,roots):
    visiting,done,post=set(),set(),[]
    def visit(digest):
        if digest in visiting:raise ValueError('cyclic_manifest_closure')
        if digest in done:return
        if digest not in nodes:raise ValueError('incomplete_recorded_manifest_closure')
        visiting.add(digest)
        for child in nodes[digest]['children']:visit(child)
        visiting.remove(digest);done.add(digest);post.append(digest)
    for digest in sorted(roots):visit(digest)
    if done!=set(nodes):raise ValueError('manifest_graph_contains_unreachable_images')
    return list(reversed(post))


def validate_graph(graph,inventory):
    expected=scope(inventory)
    if (not isinstance(graph,dict) or set(graph)!=set(expected)
            or any(graph[key]!=expected[key] for key in expected if key!='repositories')
            or set(graph['repositories'])!=set(expected['repositories'])):
        raise ValueError('retained_manifest_graph_scope_mismatch')
    total,count=0,0
    for uri,record in graph['repositories'].items():
        base=expected['repositories'][uri]
        if (set(record)!=set(base) or any(record[key]!=base[key] for key in base if key!='nodes')
                or not isinstance(record['nodes'],dict)):
            raise ValueError('retained_manifest_repository_or_root_mismatch')
        for digest,node in record['nodes'].items():
            parsed,children=parse_manifest(digest,node.get('manifest'),node.get('media_type'))
            if parsed!=node:raise ValueError('retained_manifest_node_rebound')
            total+=node['size_bytes'];count+=1
            if count>MAX_NODES or total>MAX_TOTAL:raise ValueError('bounded_ECR_graph_required')
            for child,size,media in children:
                target=record['nodes'].get(child)
                if target is None or target.get('size_bytes')!=size or target.get('media_type')!=media:
                    raise ValueError('child_manifest_descriptor_size_or_media_mismatch')
        graph_order(record['nodes'],record['root_digests'])
    return graph


def owned_file(value,directory):
    directory=Path(directory).absolute();path=Path(value)
    if not path.is_absolute():path=directory/path
    if '..' in path.parts:raise ValueError('graph_path_traversal_forbidden')
    for item in (path,*path.parents):
        if item.is_symlink() or (hasattr(item,'is_junction') and item.is_junction()):raise ValueError('linked_graph_path_forbidden')
        if item==directory:break
    if not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):raise ValueError('owned_graph_file_required')
    return path


def load_graph(binding,inventory,directory):
    path=owned_file(binding['path'],directory)
    if path.stat().st_size>64*1024*1024:raise ValueError('bounded_graph_file_required')
    body=path.read_bytes()
    if sha(body)!=binding['sha256']:raise ValueError('retained_ECR_graph_file_hash_changed')
    return validate_graph(strict_json(body),inventory)


def store_graph(graph,directory):
    root=Path(directory).absolute()
    if not root.is_dir():raise ValueError('owned_campaign_directory_required')
    target=root/'ecr-manifests'
    for item in (target,*target.parents):
        if item.is_symlink() or (hasattr(item,'is_junction') and item.is_junction()):raise ValueError('linked_graph_directory_forbidden')
        if item==root:break
    target.mkdir(exist_ok=True)
    body=canonical(graph)+b'\n';digest=sha(body);path=target/(digest[:16]+'.json')
    if path.exists():
        if owned_file(path,root).read_bytes()!=body:raise ValueError('ECR_graph_path_collision')
    else:
        descriptor_fd,temporary=tempfile.mkstemp(prefix='.graph-',dir=target)
        pending=Path(temporary)
        try:
            with os.fdopen(descriptor_fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.link(pending,path)
        finally:
            if pending.exists():pending.unlink()
    return {'path':str(path),'sha256':digest,'size_bytes':len(body),'kind':graph['kind']}


def error_code(error):
    from botocore.exceptions import ClientError
    return error.response.get('Error',{}).get('Code') if isinstance(error,ClientError) else None


def repository(ecr,context,uri,record):
    if getattr(getattr(ecr,'meta',None),'region_name',None)!=context['region']:
        raise ValueError('ECR_client_region_does_not_match_owned_repository_region')
    try:response=ecr.describe_repositories(registryId=context['account_id'],repositoryNames=[record['repository_name']])
    except Exception as error:
        if error_code(error)=='RepositoryNotFoundException':return False
        raise
    rows=response.get('repositories')
    if (not isinstance(rows,list) or len(rows)!=1 or rows[0].get('registryId')!=context['account_id']
            or rows[0].get('repositoryName')!=record['repository_name'] or rows[0].get('repositoryUri')!=uri
            or rows[0].get('repositoryArn')!=record['repository_arn']):
        raise ValueError('actual_ECR_repository_identity_mismatch')
    tags=ecr.list_tags_for_resource(resourceArn=record['repository_arn']).get('tags',[])
    if {row['Key']:row['Value'] for row in tags}.get('Project')!=context['project_id']:
        raise ValueError('actual_ECR_repository_project_tag_mismatch')
    return True


def fetch_manifest(ecr,context,record,digest):
    response=ecr.batch_get_image(registryId=context['account_id'],repositoryName=record['repository_name'],imageIds=[{'imageDigest':digest}])
    images,failures=response.get('images'),response.get('failures',[])
    if images==[] and len(failures)==1 and failures[0].get('failureCode')=='ImageNotFound' and failures[0].get('imageId',{}).get('imageDigest')==digest:
        return None
    if (not isinstance(images,list) or len(images)!=1 or failures or images[0].get('registryId')!=context['account_id']
            or images[0].get('repositoryName')!=record['repository_name'] or images[0].get('imageId',{}).get('imageDigest')!=digest):
        raise ValueError('exact_ECR_manifest_response_required')
    return parse_manifest(digest,images[0].get('imageManifest'),images[0].get('imageManifestMediaType'))


def remote_digests(ecr,context,record):
    result,token,seen=set(),None,set()
    for _ in range(1000):
        request={'registryId':context['account_id'],'repositoryName':record['repository_name'],'filter':{'tagStatus':'ANY'},'maxResults':1000}
        if token:request['nextToken']=token
        response=ecr.list_images(**request)
        if not isinstance(response.get('imageIds'),list):raise ValueError('explicit_ECR_image_inventory_required')
        for item in response['imageIds']:
            digest=item.get('imageDigest')
            if not isinstance(digest,str) or not DIGEST.fullmatch(digest):raise ValueError('ECR_remote_digest_invalid')
            result.add(digest)
            if len(result)>MAX_NODES:raise ValueError('bounded_ECR_image_inventory_required')
        token=response.get('nextToken')
        if not token:return result
        if not isinstance(token,str) or token in seen:raise ValueError('ECR_image_inventory_pagination_invalid')
        seen.add(token)
    raise ValueError('bounded_ECR_image_inventory_pagination_exhausted')


def retain_image_graph(ecr,inventory,*,directory,prior_graph=None):
    graph=scope(inventory)
    prior=load_graph(prior_graph,inventory,directory) if prior_graph is not None else None
    total,count=0,0
    for uri,record in graph['repositories'].items():
        exists=repository(ecr,graph,uri,record)
        visiting=set()
        def visit(digest):
            nonlocal total,count
            if digest in visiting:raise ValueError('cyclic_ECR_graph')
            if digest in record['nodes']:return
            visiting.add(digest)
            fetched=fetch_manifest(ecr,graph,record,digest) if exists else None
            if fetched is None:
                if prior is None or digest not in prior['repositories'][uri]['nodes']:
                    raise ValueError('missing_ECR_manifest_without_retained_content_proof')
                cached=prior['repositories'][uri]['nodes'][digest]
                fetched=parse_manifest(digest,cached['manifest'],cached['media_type'])
            node,children=fetched
            count+=1;total+=node['size_bytes']
            if count>MAX_NODES or total>MAX_TOTAL:raise ValueError('bounded_ECR_graph_required')
            record['nodes'][digest]=node
            for child,_,_ in children:visit(child)
            visiting.remove(digest)
        for root in record['root_digests']:visit(root)
    validate_graph(graph,inventory)
    return store_graph(graph,directory)


def delete_image_graph(ecr,inventory,*,graph_binding,directory):
    graph=load_graph(graph_binding,inventory,directory)
    present={};absent=[]
    # Preflight ALL owned repositories before deleting any known digest.
    for uri,record in graph['repositories'].items():
        if not repository(ecr,graph,uri,record):absent.append(uri);present[uri]=set();continue
        present[uri]=remote_digests(ecr,graph,record)
        if not present[uri]<=set(record['nodes']):raise ValueError('refusing_ECR_digest_outside_verified_root_closure')
        for digest in sorted(present[uri]):
            fetched=fetch_manifest(ecr,graph,record,digest)
            if fetched is None or fetched[0]!=record['nodes'][digest]:raise ValueError('remote_ECR_manifest_disagrees_with_retained_graph')
    removed=[]
    for uri,record in graph['repositories'].items():
        for digest in graph_order(record['nodes'],record['root_digests']):
            if digest not in present[uri]:continue
            response=ecr.batch_delete_image(registryId=graph['account_id'],repositoryName=record['repository_name'],imageIds=[{'imageDigest':digest}])
            failures,deleted=response.get('failures',[]),response.get('imageIds',[])
            missing=(deleted==[] and len(failures)==1 and failures[0].get('failureCode')=='ImageNotFound'
                and failures[0].get('imageId',{}).get('imageDigest')==digest)
            confirmed=(isinstance(deleted,list) and bool(deleted) and not failures
                and all(isinstance(item,dict) and item.get('imageDigest')==digest
                    and set(item)<={'imageDigest','imageTag'} for item in deleted))
            if not missing and not confirmed:raise RuntimeError('exact_ECR_manifest_deletion_not_confirmed')
            removed.append({'repository_uri':uri,'digest':digest,'result':'already-absent' if missing else 'deleted'})
    for uri,record in graph['repositories'].items():
        if repository(ecr,graph,uri,record) and remote_digests(ecr,graph,record):
            raise RuntimeError('owned_ECR_repository_not_confirmed_empty')
    return {'schema_version':'0.1.0','kind':'owned-ecr-image-manifest-cleanup','successful':True,
        'account_id':graph['account_id'],'region':graph['region'],'project_id':graph['project_id'],'campaign_id':graph['campaign_id'],
        'graph':graph_binding,'removed':removed,'repositories_confirmed_empty_or_absent':sorted(graph['repositories']),
        'repositories_absent_at_preflight':absent,'force_delete_used':False,'unknown_digests_adopted':False}
