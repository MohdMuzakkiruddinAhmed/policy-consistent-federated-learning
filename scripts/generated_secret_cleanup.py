"""Scoped generated-secret teardown barrier, with retained attempt receipts.

Reuses only the pure source/native-metadata validators from the immutable
reviewed one-off module; no partial-foundation/ECR guards are called here.
Caller supplies normal teardown authorization and its campaign-operation lock.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from types import SimpleNamespace

from cleanup_project_secrets import metadata, sources
from finalize_partial_foundation import bound, owned
from validate_campaign_teardown import local_custody


def _scope(request, inventory, directory):
    if any(request.get(k) != inventory.get(k) for k in ('account_id', 'region', 'project_id', 'campaign_id')):
        raise ValueError('generated_secret_cleanup_scope_mismatch')
    if (not re.fullmatch('[0-9]{12}', request.get('account_id', ''))
            or not re.fullmatch('[a-z]{2}(?:-[a-z]+)+-[0-9]+', request.get('region', ''))):
        raise ValueError('generated_secret_cleanup_account_region_required')
    shutdown = inventory.get('shutdown_confirmation', {})
    recorded = set(inventory.get('task_arns', []))
    if (shutdown.get('confirmed') is not True or shutdown.get('unresolved_task_arns') != []
            or shutdown.get('uncertain_launch_tokens') != []
            or any(row.get('state') not in {'accepted', 'rejected'}
                or (row['state'] == 'accepted' and row.get('task_arn') not in recorded)
                for row in inventory.get('launch_intents', {}).values())):
        raise ValueError('generated_secret_cleanup_requires_confirmed_shutdown')
    if any(inventory.get('shared_fleet_ledger', {}).get(arn, {}).get('last_status') != 'STOPPED'
            for arn in inventory.get('task_arns', [])):
        raise ValueError('generated_secret_cleanup_unknown_task_stop')
    current = owned(inventory['state_paths']['runtime'], directory)
    if current != (directory / 'state/runtime.tfstate').absolute():
        raise ValueError('generated_secret_runtime_state_outside_owned_stack')
    after = json.loads(current.read_text())
    before, _ = bound(inventory['pre_teardown_state_snapshots']['runtime'], directory)
    if (after.get('resources') != [] or not isinstance(before.get('resources'), list)
            or before.get('lineage') != after.get('lineage') or after.get('serial', -1) < before.get('serial', 0)):
        raise ValueError('generated_secret_cleanup_requires_destroyed_bound_runtime')
    # Zero authority is explicit in all three original sources; missing fields
    # never turn into an empty allowlist or a synthetic success.
    zero = ('secrets' in request and request['secrets'] == []
        and 'secret_arns' in inventory['runtime_contract'] and inventory['runtime_contract']['secret_arns'] == {}
        and 'secret_versions' in inventory and inventory['secret_versions'] == {}
        and not any(row.get('type') == 'aws_secretsmanager_secret' for row in before['resources']))
    return zero


def cleanup_generated_secrets(clients, request, inventory, *, directory, root, sleep=time.sleep, max_polls=12, interval=2):
    if type(max_polls) is not int or not 1 <= max_polls <= 12 or type(interval) not in (int, float) or not 0 <= interval <= 5 or (max_polls - 1) * interval > 55:
        raise ValueError('bounded_generated_secret_readback_required')
    directory, root = Path(directory).absolute(), Path(root).absolute()
    report = {'schema_version': '0.1.0', 'kind': 'generated-runtime-secret-teardown-attempt',
        **{k: request.get(k) for k in ('account_id', 'region', 'project_id', 'campaign_id')},
        'at_utc': datetime.now(timezone.utc).isoformat(), 'successful': False,
        'explicit_zero_authority': False, 'selected_sources': [], 'before': [], 'actions': [], 'readback': [], 'errors': [],
        'get_secret_value_calls': 0, 'restore_secret_calls': 0, 'list_secrets_calls': 0,
        'aws_api_calls': False, 'aws_mutation_attempted': False, 'all_selected_secrets_absent': False,
        'local_custody': None, 'safe_configured_recovery_window_changed': False}
    operation, active_arn = 'local-scope-and-source-preflight', None
    try:
        if directory != (root / 'results/aws' / request['campaign_id']).absolute():
            raise ValueError('generated_secret_directory_outside_exact_campaign')
        zero = _scope(request, inventory, directory)
        runtime_path = owned(inventory['state_paths']['runtime'], directory)
        report['source_bindings'] = {'runtime_pre_destroy_state': inventory['pre_teardown_state_snapshots']['runtime'],
            'destroyed_runtime_state': {'path': str(runtime_path), 'sha256': hashlib.sha256(runtime_path.read_bytes()).hexdigest()},
            'generated_payload_directory': str(directory / 'secret-payloads')}
        if zero:
            report.update(successful=True, explicit_zero_authority=True, all_selected_secrets_absent=True)
            return report
        selected = sources(SimpleNamespace(request=request, inventory=inventory, directory=directory))
        report['selected_sources'] = selected
        report['local_custody'] = local_custody(inventory, directory)
        for name in ('sts', 'secretsmanager'):
            if clients[name].meta.region_name != request['region']:
                raise ValueError('generated_secret_client_region_mismatch')
        operation = 'STS.GetCallerIdentity'; report['aws_api_calls'] = True
        if clients['sts'].get_caller_identity().get('Account') != request['account_id']:
            raise ValueError('generated_secret_STS_account_mismatch')
        # Collect each observation as it is made, preserving the exact failed
        # ARN if a later preflight fails. No mutation occurs until all pass.
        operation = 'SecretsManager.DescribeSecret-preflight'
        for row in selected:
            active_arn = row['arn']
            report['before'].append(metadata(clients['secretsmanager'], row, request['project_id'], allow_absent=True))
        if sources(SimpleNamespace(request=request, inventory=inventory, directory=directory)) != selected:
            raise ValueError('generated_secret_source_changed_before_mutation')
        operation = 'SecretsManager.DeleteSecret-force'
        for row in report['before']:
            if row['absent']: continue
            active_arn = row['arn']
            action = {'arn': row['arn'], 'operation': 'DeleteSecret', 'ForceDeleteWithoutRecovery': True,
                'acknowledged': False, 'absence_inferred_from_delete_success': False}
            report['actions'].append(action); report['aws_mutation_attempted'] = True
            try:
                response = clients['secretsmanager'].delete_secret(SecretId=row['arn'], ForceDeleteWithoutRecovery=True)
                if response.get('ARN') != row['arn'] or response.get('Name') != row['name']:
                    raise ValueError('generated_secret_force_response_scope_mismatch')
                action.update(acknowledged=True, response_ARN=response['ARN'])
            except Exception as error:
                report['errors'].append(_error(operation, active_arn, error))
                break
        operation = 'SecretsManager.DescribeSecret-readback'
        for attempt in range(max_polls):
            report['readback'] = []; report['readback_attempts'] = attempt + 1
            for row in selected:
                active_arn = row['arn']
                report['readback'].append(metadata(clients['secretsmanager'], row, request['project_id'], allow_absent=True))
            if all(row['absent'] for row in report['readback']) or report['errors']: break
            if attempt + 1 < max_polls: sleep(interval)
        report['all_selected_secrets_absent'] = (len(report['readback']) == 16 and all(row['absent'] for row in report['readback']))
        report['successful'] = report['all_selected_secrets_absent'] and not report['errors']
    except Exception as error:
        report['errors'].append(_error(operation, active_arn, error))
    return report


def _error(operation, arn, error):
    return {'operation': operation, 'arn': arn, 'type': type(error).__name__,
        'code': getattr(error, 'response', {}).get('Error', {}).get('Code') or str(error)[:180]}


def retain_cleanup_receipt(report, *, directory):
    directory = Path(directory).absolute()
    # Check link ancestry before creating a new content-addressed directory.
    target = directory / 'secret-cleanup'
    for component in (target, *target.parents):
        if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
            raise ValueError('linked_generated_secret_receipt_directory_forbidden')
        if component == directory: break
    target.mkdir(exist_ok=True)
    body = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    digest = hashlib.sha256(body).hexdigest(); destination = target / (digest + '.json')
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != body:
            raise ValueError('generated_secret_receipt_content_collision')
    else:
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(body)
    return {'path': str(destination), 'sha256': digest, 'size_bytes': len(body)}
