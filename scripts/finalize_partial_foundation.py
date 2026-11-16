"""One-off guarded foundation-only finalization after a retained failed destroy.

Default preview is zero-API. Apply inherits CampaignRunner.execute('teardown')
authorization, STS identity and campaign-operation locking. No S3/DDB writes,
image deletion, force-delete, task launch or runtime Terraform occurs here.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from aws_campaign import CampaignRunner, ROOT, file_sha256, load_request, write_json
from validate_campaign_teardown import local_custody, observe, resource_targets

SERVICES = ('sts', 's3', 'dynamodb', 'ecr', 'iam', 'secretsmanager', 'lambda',
    'scheduler', 'sqs', 'sns', 'budgets', 'servicediscovery', 'route53', 'logs', 'ec2', 'ecs')
REQUIRED_FILES = {'inventory.json', 'request.json', 'state/foundation.tfstate', 'state/runtime.tfstate',
    *(f'{stack}-destroy-{number}.log' for stack in ('foundation', 'runtime') for number in range(4)),
    'foundation-destroy.tfplan', 'runtime-destroy.tfplan'}


def owned(value, directory):
    directory = Path(directory).absolute()
    path = Path(value)
    if '..' in path.parts:
        raise ValueError('recovery_parent_traversal_forbidden')
    if not path.is_absolute(): path = ROOT / path
    path = path.absolute()
    for component in (path, *path.parents):
        if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
            raise ValueError('recovery_link_forbidden')
        if component == directory: break
    if not path.resolve().is_relative_to(directory.resolve()) or not path.is_file():
        raise ValueError('recovery_file_outside_owned_directory')
    return path


def bound(reference, directory):
    if not isinstance(reference, dict) or not {'path', 'sha256'} <= set(reference):
        raise ValueError('bound_recovery_file_required')
    path = owned(reference['path'], directory)
    if file_sha256(path) != reference['sha256']:
        raise ValueError('bound_recovery_file_changed')
    return json.loads(path.read_text(encoding='utf-8')), path


def _state_ids(state):
    return {(row.get('mode'), row.get('type'), row.get('name'), str(instance.get('index_key', '')),
        str(instance.get('attributes', {}).get('id', ''))) for row in state.get('resources', [])
        for instance in row.get('instances', [])}


def local_guards(runner, *, receipt_ref, closure_ref, expected_inventory_sha256, expected_request_sha256):
    directory = runner.directory
    inventory_path = owned(directory / 'inventory.json', directory)
    request_path = owned(directory / 'request.json', directory)
    if file_sha256(inventory_path) != expected_inventory_sha256 or file_sha256(request_path) != expected_request_sha256:
        raise ValueError('recovery_request_or_inventory_CAS_failed')
    canonical_request = json.loads(request_path.read_text())
    canonical_request.setdefault('schema_version', '0.1')
    loaded_request = dict(runner.request)
    loaded_request.setdefault('schema_version', '0.1')
    if loaded_request != canonical_request:
        raise ValueError('recovery_loaded_request_not_exact_pinned_canonical_request')
    disk = json.loads(inventory_path.read_text())
    if disk != runner.inventory:
        raise ValueError('recovery_runner_inventory_changed')
    scope = ('account_id', 'region', 'project_id', 'campaign_id')
    if any(disk.get(key) != runner.request.get(key) for key in scope) or disk.get('teardown_complete') is True:
        raise ValueError('partial_foundation_original_scope_required')
    shutdown = disk.get('shutdown_confirmation', {})
    recorded = set(disk.get('task_arns', []))
    if (shutdown.get('confirmed') is not True or shutdown.get('unresolved_task_arns') != []
            or shutdown.get('uncertain_launch_tokens') != []
            or any(row.get('state') not in {'accepted', 'rejected'}
                or (row['state'] == 'accepted' and row.get('task_arn') not in recorded)
                for row in disk.get('launch_intents', {}).values())
            or any(disk.get('shared_fleet_ledger', {}).get(arn, {}).get('last_status') != 'STOPPED' for arn in recorded)):
        raise ValueError('recovery_requires_confirmed_stopped_tasks_and_no_uncertain_launches')
    receipt, receipt_path = bound(receipt_ref, directory)
    if receipt.get('kind') != 'private-failed-cleanup-attempt-custody' or receipt.get('terminal_teardown_claimed') is not False:
        raise ValueError('retained_failed_cleanup_receipt_required')
    seen = set()
    for row in receipt.get('files', []):
        source = owned(row['source'], directory)
        relative = source.relative_to(directory).as_posix()
        retained = owned(row['retained'], receipt_path.parent)
        if (relative in seen or relative not in REQUIRED_FILES or retained.stat().st_size != row['size_bytes']
                or file_sha256(retained) != row['sha256'] or file_sha256(source) != row['sha256']):
            raise ValueError('retained_failed_cleanup_original_bytes_changed')
        seen.add(relative)
    if seen != REQUIRED_FILES:
        raise ValueError('all_fourteen_failed_attempt_files_required')
    if type(disk.get('removed_recorded_s3_versions')) is not int or disk['removed_recorded_s3_versions'] < 1:
        raise ValueError('prior_recorded_version_purge_required')
    roots = {row['reference'] for row in disk.get('image_history', [])}
    if disk.get('image'): roots.add(disk['image']['reference'])
    if not roots or set(disk.get('removed_owned_image_references', [])) != roots:
        raise ValueError('recorded_root_deletion_receipt_required')
    closure, _ = bound(closure_ref, ROOT)
    if (closure.get('kind') != 'read-only-recorded-OCI-index-ECR-manifest-closure-audit'
            or closure.get('account_id') != disk['account_id'] or closure.get('region') != disk['region']
            or closure.get('inventory', {}).get('sha256') != expected_inventory_sha256
            or closure.get('all_remaining_digests_are_verified_exact_recorded_descendants') is not True
            or closure.get('unknown_remaining_digests') != []):
        raise ValueError('exact_recorded_manifest_closure_audit_required')
    expected_repo = closure.get('repository')
    prefix = f"{disk['account_id']}.dkr.ecr.{disk['region']}.amazonaws.com/"
    if closure.get('repository_uri') != prefix + str(expected_repo) or not all(root.startswith(prefix + str(expected_repo) + '@') for root in roots):
        raise ValueError('recovery_repository_root_scope_mismatch')
    if {row['index_digest'] for row in closure.get('recorded_index_roots', [])} != {root.split('@')[1] for root in roots}:
        raise ValueError('exact_recorded_index_root_set_required')
    for row in closure.get('recorded_index_roots', []): bound_raw(row['raw_index'])
    for row in closure.get('remaining_images', []): bound_raw(row['raw_manifest'])
    for stack in ('foundation', 'runtime'):
        path = owned(disk['state_paths'][stack], directory)
        if path != (directory / 'state' / (stack + '.tfstate')).absolute():
            raise ValueError('recovery_state_path_outside_owned_stack')
        state = json.loads(path.read_text())
        prior, _ = bound(disk['pre_teardown_state_snapshots'][stack], directory)
        if (state.get('lineage') != prior.get('lineage') or state.get('serial', -1) < prior.get('serial', 0)
                or not _state_ids(state) <= _state_ids(prior)):
            raise ValueError('recovery_state_not_subset_of_immutable_original')
        if stack == 'runtime' and state.get('resources') != []:
            raise ValueError('recovery_runtime_must_already_be_empty')
        if stack == 'foundation':
            resources = state.get('resources')
            if not isinstance(resources, list) or not resources:
                raise ValueError('partial_foundation_state_required')
            repos = []
            for row in resources:
                if row.get('mode') != 'managed' or row.get('type') not in {'aws_ecr_repository', 'terraform_data'}:
                    raise ValueError('only_owned_ECR_and_terraform_data_may_remain')
                if row['type'] == 'aws_ecr_repository':
                    repos.extend(instance.get('attributes', {}) for instance in row.get('instances', []))
            if len(repos) != 1 or any(repos[0].get(key) != expected_repo for key in ('id', 'name')) or repos[0].get('repository_url') != prefix + expected_repo:
                raise ValueError('exact_single_remaining_repository_required')
            if closure.get('foundation_state', {}).get('sha256') != file_sha256(path):
                raise ValueError('closure_audit_foundation_state_changed')
    custody = local_custody(disk, directory)
    targets, states, unknown = resource_targets(disk, directory, allow_partial_foundation_ecr=True)
    if unknown: raise ValueError('unsupported_recorded_cleanup_resource')
    return {'repository': expected_repo, 'targets': targets, 'states': states, 'custody': custody}


def bound_raw(reference):
    path = owned(reference['path'], ROOT)
    if path.stat().st_size != reference['size_bytes'] or file_sha256(path) != reference['sha256']:
        raise ValueError('retained_manifest_bytes_changed')


class PartialFoundationRunner(CampaignRunner):
    """Use the standard guarded teardown dispatch, changing only its body."""
    recovery = None
    absence_clients = None

    def teardown(self):
        guards = local_guards(self, **self.recovery)
        if self.absence_clients is None:
            import boto3
            from botocore.config import Config
            options = {'region_name': self.request['region'], 'config': Config(ignore_configured_endpoint_urls=True,
                connect_timeout=3, read_timeout=10, retries={'max_attempts': 0})}
            self.absence_clients = {name: boto3.client(name, **options) for name in SERVICES}
        clients = self.absence_clients
        if clients['sts'].get_caller_identity().get('Account') != self.request['account_id']:
            raise ValueError('recovery_readback_account_mismatch')
        observations = [observe(target, clients, self.inventory) for target in guards['targets']]
        repository = guards['repository']
        for row in observations:
            if row['kind'] == 'repository' and row['identifier'] == repository:
                if row['state'] == 'unknown-error': raise ValueError('remaining_repository_readback_unknown')
            elif row['absent'] is not True:
                raise ValueError('other_recorded_resource_not_confirmed_absent:' + row['kind'])
        remaining = next((row for row in observations if row['kind'] == 'repository' and row['identifier'] == repository), None)
        if remaining is None: raise ValueError('remaining_repository_missing_from_exact_targets')
        if not remaining['absent']:
            response = clients['ecr'].list_images(registryId=self.request['account_id'], repositoryName=repository,
                maxResults=1000, filter={'tagStatus': 'ANY'})
            if response.get('imageIds') != [] or response.get('nextToken'):
                raise ValueError('remaining_repository_must_be_observed_empty')
        # Repeat local CAS immediately before fixed-name Terraform logs can be
        # overwritten; the immutable failed-attempt copies remain untouched.
        local_guards(self, **self.recovery)
        self.terraform_step('foundation', self.inventory['foundation_variables'], destroy=True)
        for stack, value in self.inventory['state_paths'].items():
            if json.loads(owned(value, self.directory).read_text()).get('resources') != []:
                raise ValueError('final_recovery_state_not_empty:' + stack)
        self.inventory['partial_foundation_recovery'] = {'kind': 'guarded-partial-foundation-finalization',
            'at_utc': datetime.now(timezone.utc).isoformat(), 'source': self.recovery,
            'independent_absence_observations': observations, 'local_custody': guards['custody'],
            'remaining_repository_empty_readback': {'registry_id': self.request['account_id'], 'repository': repository,
                'repository_already_absent': remaining['absent'], 'observed_image_ids': [], 'complete': True},
            'runtime_terraform_invoked': False, 'S3_or_DDB_mutations': False, 'image_deletion_performed': False}
        self.inventory['teardown_complete'] = True
        self.save()
        ownership_path = ROOT / 'results/aws/project-ownership.json'
        ownership = json.loads(ownership_path.read_text())
        target = ':'.join(self.request[key] for key in ('account_id', 'region', 'project_id'))
        if ownership.get(target) == self.request['campaign_id']:
            del ownership[target]
            write_json(ownership_path, ownership)
        return {'teardown_complete': True, 'foundation_only_recovery': True, 'cost_reconciliation_still_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--expected-request-sha256', required=True)
    parser.add_argument('--expected-inventory-sha256', required=True)
    parser.add_argument('--failed-attempt-receipt', required=True, type=Path)
    parser.add_argument('--failed-attempt-receipt-sha256', required=True)
    parser.add_argument('--closure-audit', required=True, type=Path)
    parser.add_argument('--closure-audit-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    runner = PartialFoundationRunner(load_request(args.request), apply=args.apply)
    runner.recovery = {'receipt_ref': {'path': str(args.failed_attempt_receipt), 'sha256': args.failed_attempt_receipt_sha256},
        'closure_ref': {'path': str(args.closure_audit), 'sha256': args.closure_audit_sha256},
        'expected_inventory_sha256': args.expected_inventory_sha256, 'expected_request_sha256': args.expected_request_sha256}
    local_guards(runner, **runner.recovery)
    result = runner.execute('teardown')
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__': main()
