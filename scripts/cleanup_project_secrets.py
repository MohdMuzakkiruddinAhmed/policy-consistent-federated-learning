"""Exact generated-task-secret cleanup; preview reads metadata, never values.

Apply requires a pinned preview and inherits the standard campaign teardown
authorization/operation lock. No RestoreSecret, ListSecrets or GetSecretValue.
The safe Terraform recovery-window default and strict final validator stay intact.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from botocore.exceptions import ClientError

from aws_campaign import CampaignRunner, ROOT, exclusive_file, file_sha256, load_request
from finalize_partial_foundation import bound, local_guards, owned

NAMES = {'root-ca', 'flower-server-cert', 'flower-server-key', 'coordinator-config', 'evaluation-config',
    'governance-config', 'opa-config', 'operator-config', *(f'node-org_0{i}' for i in range(1, 9))}


def sources(runner):
    inventory, request, directory = runner.inventory, runner.request, runner.directory
    secret_arns = inventory['runtime_contract']['secret_arns']
    entries = request.get('secrets', [])
    if (len(entries) != 16 or {x.get('logical_name') for x in entries} != NAMES
            or set(secret_arns) != NAMES or set(inventory.get('secret_versions', {})) != NAMES
            or any(set(x) != {'logical_name', 'payload_path'} for x in entries)):
        raise ValueError('exact_sixteen_generated_task_secret_bindings_required')
    state, _ = bound(inventory['pre_teardown_state_snapshots']['runtime'], directory)
    recorded = {}
    for resource in state['resources']:
        if resource.get('type') != 'aws_secretsmanager_secret': continue
        for item in resource['instances']:
            attrs = item['attributes']; logical = item.get('index_key')
            if logical in recorded: raise ValueError('duplicate_pre_destroy_secret_identity')
            recorded[logical] = attrs
    if set(recorded) != NAMES: raise ValueError('exact_pre_destroy_secret_registry_required')
    rows = []
    for entry in sorted(entries, key=lambda x: x['logical_name']):
        name = entry['logical_name']; arn = secret_arns[name]; previous = inventory['secret_versions'][name]
        attrs = recorded[name]; expected_name = request['project_id'] + '/runtime/' + name
        pattern = rf"arn:aws:secretsmanager:{re.escape(request['region'])}:{request['account_id']}:secret:{re.escape(expected_name)}-[A-Za-z0-9]{{6}}"
        if (not re.fullmatch(pattern, arn) or attrs.get('arn') != arn or attrs.get('name') != expected_name
                or attrs.get('tags_all', attrs.get('tags', {})).get('Project') != request['project_id']
                or type(attrs.get('recovery_window_in_days')) is not int or not 7 <= attrs['recovery_window_in_days'] <= 30
                or previous.get('arn') != arn or previous.get('version_id') != previous.get('sha256')
                or not re.fullmatch('[0-9a-f]{64}', previous.get('sha256', ''))):
            raise ValueError('secret_prestate_project_ARN_or_generated_version_binding_failed')
        payload = owned(entry['payload_path'], directory / 'secret-payloads')
        if payload != (directory / 'secret-payloads' / (name + '.json')).absolute():
            raise ValueError('canonical_project_generated_payload_path_required')
        # Match the original PutSecretValue text->UTF8 digest, without parsing,
        # displaying, exporting or requesting the value from AWS.
        digest = hashlib.sha256(payload.read_text(encoding='utf-8').encode()).hexdigest()
        if digest != previous['sha256']: raise ValueError('generated_secret_payload_binding_changed')
        rows.append({'logical_name': name, 'arn': arn, 'name': expected_name,
            'generated_payload_sha256': digest, 'version_id': previous['version_id'],
            'configured_recovery_window_in_days': attrs['recovery_window_in_days']})
    return rows


def metadata(client, row, project, *, allow_absent):
    try:
        response = client.describe_secret(SecretId=row['arn'])
    except Exception as error:
        code = error.response.get('Error', {}).get('Code') if isinstance(error, ClientError) else None
        if code == 'ResourceNotFoundException' and allow_absent:
            return {**row, 'state': 'explicit-not-found', 'absent': True}
        raise
    tags = {item['Key']: item['Value'] for item in response.get('Tags', [])}
    if (response.get('ARN') != row['arn'] or response.get('Name') != row['name']
            or tags.get('Project') != project or not response.get('DeletedDate')
            or response.get('OwningService') or response.get('ReplicationStatus')
            or 'AWSCURRENT' not in response.get('VersionIdsToStages', {}).get(row['version_id'], [])):
        raise ValueError('native_metadata_must_bind_scheduled_owned_generated_secret')
    return {**row, 'state': 'scheduled-deletion-still-describable', 'absent': False,
        'deleted_date': response['DeletedDate'].isoformat(), 'project_tag_verified': True,
        'generated_version_current_verified': True}


class SecretCleanupRunner(CampaignRunner):
    recovery = None
    preview_ref = None
    polls = 12
    interval = 2

    def _retry_read(self, service, operation, function, *args, **kwargs):
        # A read failure belongs in this operation's new receipt, never a live
        # inventory rewrite that invalidates its pinned CAS.
        return function(*args, **kwargs)

    def operation(self, *, delete):
        report = {'schema_version': '0.1.0', 'kind': 'exact-generated-task-secret-cleanup',
            'account_id': self.request['account_id'], 'region': self.request['region'],
            'project_id': self.request['project_id'], 'campaign_id': self.request['campaign_id'],
            'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'applied': delete,
            'successful': False, 'get_secret_value_calls': 0, 'restore_secret_calls': 0,
            'list_secrets_calls': 0, 'selected_sources': [], 'before': [], 'actions': [], 'readback': [], 'errors': [],
            'source': self.recovery, 'preview': self.preview_ref,
            'rationale': 'Finish authorized removal of generated runtime TLS/config secrets after confirmed task shutdown; preserve safe default recovery7 and strict actual-absence gate.'}
        try:
            local_guards(self, **self.recovery)
            selected = sources(self); report['selected_sources'] = selected
            clients = self.sdk()
            before = [metadata(clients['secretsmanager'], row, self.request['project_id'], allow_absent=delete) for row in selected]
            report['before'] = before
            if delete:
                preview, _ = bound(self.preview_ref, ROOT)
                if (preview.get('kind') != report['kind'] or preview.get('applied') is not False
                        or preview.get('successful') is not True or preview.get('source') != self.recovery
                        or preview.get('selected_sources') != selected or len(preview.get('before', [])) != 16
                        or any(row.get('absent') is not False for row in preview['before'])):
                    raise ValueError('exact_successful_reviewed_preview_required')
            # No mutation begins until all sixteen native descriptions passed,
            # local originals still match and all source payloads remain bound.
            local_guards(self, **self.recovery)
            if sources(self) != selected: raise ValueError('secret_source_bindings_changed_during_observation')
            if delete:
                for row in before:
                    if row['absent']: continue
                    action = {'arn': row['arn'], 'operation': 'DeleteSecret', 'ForceDeleteWithoutRecovery': True,
                        'acknowledged': False, 'absence_inferred_from_delete_success': False}
                    report['actions'].append(action)
                    response = clients['secretsmanager'].delete_secret(SecretId=row['arn'], ForceDeleteWithoutRecovery=True)
                    if response.get('ARN') != row['arn'] or response.get('Name') != row['name']:
                        raise ValueError('force_delete_response_scope_mismatch')
                    action.update(acknowledged=True, response_ARN=response['ARN'])
                for attempt in range(self.polls):
                    report['readback'] = [metadata(clients['secretsmanager'], row, self.request['project_id'], allow_absent=True) for row in selected]
                    report['readback_attempts'] = attempt + 1
                    if all(row['absent'] for row in report['readback']): break
                    if attempt + 1 < self.polls: self.sleep(self.interval)
                report['successful'] = all(row['absent'] for row in report['readback'])
            else:
                report['successful'] = True
        except Exception as error:
            code = getattr(error, 'response', {}).get('Error', {}).get('Code')
            report['errors'].append({'type': type(error).__name__, 'code': code or str(error)[:180]})
        report['inventory_unchanged'] = file_sha256(self.inventory_path) == self.recovery['expected_inventory_sha256']
        report['successful'] = report['successful'] and not report['errors'] and report['inventory_unchanged']
        report['aws_mutations'] = bool(report['actions'])
        report['aws_mutation_attempted'] = bool(report['actions'])
        report['all_selected_secrets_absent'] = bool(report['readback']) and all(row['absent'] for row in report['readback'])
        return report

    def teardown(self):
        return self.operation(delete=True)

    def preview(self):
        self.authorize(cleanup=True)
        with exclusive_file(ROOT / 'results/aws/campaign-operation.lock'):
            return self.operation(delete=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    for name in ('expected-request-sha256', 'expected-inventory-sha256', 'failed-attempt-receipt-sha256', 'closure-audit-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--failed-attempt-receipt', required=True, type=Path)
    parser.add_argument('--closure-audit', required=True, type=Path)
    parser.add_argument('--reviewed-preview', type=Path)
    parser.add_argument('--reviewed-preview-sha256')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.apply and (not args.reviewed_preview or not args.reviewed_preview_sha256):
        parser.error('--apply requires exact --reviewed-preview and SHA')
    if args.output.exists(): raise ValueError('new_versioned_cleanup_receipt_required')
    runner = SecretCleanupRunner(load_request(args.request), apply=args.apply)
    runner.recovery = {'receipt_ref': {'path': str(args.failed_attempt_receipt), 'sha256': args.failed_attempt_receipt_sha256},
        'closure_ref': {'path': str(args.closure_audit), 'sha256': args.closure_audit_sha256},
        'expected_inventory_sha256': args.expected_inventory_sha256, 'expected_request_sha256': args.expected_request_sha256}
    if args.reviewed_preview:
        runner.preview_ref = {'path': str(args.reviewed_preview), 'sha256': args.reviewed_preview_sha256}
    result = runner.execute('teardown') if args.apply else runner.preview()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')
    print(json.dumps({'successful': result['successful'], 'applied': result['applied'],
        'selected_count': len(result['selected_sources']), 'all_selected_secrets_absent': result['all_selected_secrets_absent'],
        'output_sha256': file_sha256(args.output)}, sort_keys=True))
    return 0 if result['successful'] else 1


if __name__ == '__main__': raise SystemExit(main())
