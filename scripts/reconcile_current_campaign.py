"""Observe only frozen current MAIN; reconcile and replay its full B lineage.

Read-only AWS metadata, exclusive new local report. No approval, ledger, request,
inventory, catalog or quote is edited. A financial projection is not a gate or
spending authorization; the independent stratified forecast remains separate.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'pyproject.toml').is_file())
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]
import campaign_budget
import cost_scope_snapshot
import reconcile_campaign_cost as cost


class CurrentObservationError(ValueError):
    def __init__(self, reason, observations, source_inputs):
        super().__init__(reason)
        self.observations = observations
        self.source_inputs = source_inputs


def _current_scope(request, approval, ledger, inventories, root):
    if (request.get('kind') != 'frozen-campaign-cost-request' or 'cost_scope_snapshot' not in request
            or request.get('campaign_budget_kind') != campaign_budget.KIND or approval.get('kind') != campaign_budget.KIND):
        raise ValueError('frozen_complete_cumulative_B_scope_required')
    campaign_budget.validate_amendment(request, approval, root=root)
    campaign_budget.validate_ledger_lineage(request, ledger, root=root, campaign_inventories=inventories)
    current = request['campaign_id']
    if current not in inventories: raise ValueError('current_campaign_missing_from_complete_scope')
    inventory = inventories[current]
    if (inventory.get('teardown_complete') is True or any(inventory.get(k) != request[k] for k in ('account_id', 'region', 'project_id', 'campaign_id'))):
        raise ValueError('current_MAIN_scope_mismatch_or_closed')
    for name, old in inventories.items():
        if name != current and old.get('teardown_complete') is not True:
            raise ValueError('historical_project_must_already_be_closed')
        if name != current and old.get('project_id') == request['project_id']:
            raise ValueError('current_MAIN_project_must_be_distinct_from_retired_projects')
    for row in ledger.get('deployments', {}).values():
        if row['campaign_id'] != current and not row.get('finished_at'):
            raise ValueError('historical_endpoint_clock_must_be_closed')
    contract = inventory['runtime_contract']
    cluster = f"arn:aws:ecs:{request['region']}:{request['account_id']}:cluster/{request['project_id']}-runtime"
    endpoints = contract.get('interface_endpoint_ids')
    endpoints = set(endpoints.values()) if isinstance(endpoints, dict) else set(endpoints or [])
    if (contract.get('cluster_arn') != cluster or len(endpoints) != 5 or not contract.get('vpc_id')
            or not isinstance(contract.get('log_groups'), dict) or not contract['log_groups']):
        raise ValueError('complete_current_MAIN_metadata_contract_required')
    return current, inventory


def _complete_observations(request, inventory, observed):
    if observed.get('errors'):
        raise ValueError('current_metadata_observation_errors')
    contract = inventory['runtime_contract']
    endpoints = contract['interface_endpoint_ids']
    expected = set(endpoints.values()) if isinstance(endpoints, dict) else set(endpoints)
    actual = observed.get('endpoint_metadata', [])
    if (len(actual) != len(expected) or {row.get('id') for row in actual} != expected
            or type(contract.get('endpoint_az_count')) is not int or contract['endpoint_az_count'] < 1
            or any(row.get('state') != 'available' or type(row.get('az_eni_count')) is not int
                or row['az_eni_count'] != contract['endpoint_az_count'] for row in actual)):
        raise ValueError('complete_current_endpoint_metadata_required')
    groups = set(contract['log_groups'].values())
    logs = observed.get('logs', [])
    if len(logs) != len(groups) or {row.get('log_group') for row in logs} != groups:
        raise ValueError('complete_current_log_metadata_required')
    references = cost.owned_image_references(request, {request['campaign_id']: inventory})
    images = observed.get('images', [])
    if len(images) != len(references) or {row.get('reference') for row in images} != references:
        raise ValueError('complete_current_image_metadata_required')
    arns = set(inventory.get('task_arns', [])); tasks = observed.get('tasks', [])
    returned = {row.get('task_arn') for row in tasks}
    if len(tasks) != len(returned) or not returned <= arns:
        raise ValueError('current_task_observation_scope_mismatch')
    # Expired STOPPED metadata may legitimately be absent from DescribeTasks.
    # Such a row needs its original complete retained terminal observation.
    history = dict(inventory.get('task_observation_history', {}))
    history.update({row['task_arn']: row for row in inventory.get('observed_tasks', [])})
    for arn in arns - returned:
        row = history.get(arn, {})
        if (row.get('last_status') != 'STOPPED' or not row.get('billing_started_at') or not row.get('stopped_at')
                or type(row.get('cpu')) is not int or row['cpu'] <= 0
                or type(row.get('memory_mib')) is not int or row['memory_mib'] <= 0):
            raise ValueError('missing_current_task_has_no_retained_terminal_observation')
    return {'complete': True, 'fresh_current_task_observations': len(returned),
        'retained_current_STOPPED_observations': len(arns - returned),
        'current_image_observations': len(images), 'current_endpoint_observations': len(actual), 'current_log_observations': len(logs)}


def build_report(request_path, *, catalog_path, data_manifest_path, training_path, prior_report_path, prior_report_sha256,
        quote_path=None, pilot_campaigns=(), remaining_cells=279, remaining_deployments=2,
        application_launches=13, fault_events=30, root=ROOT, clients=None,
        clock=lambda: datetime.now(timezone.utc)):
    root = Path(root).resolve()
    request, approval, ledger, inventories, inputs = cost.load_scope(request_path, root=root)
    current, inventory = _current_scope(request, approval, ledger, inventories, root)
    quote_path = Path(quote_path) if quote_path else root / approval['proposal_path']
    quote, rates = cost.price_basis(quote_path, catalog_path, request=request, approval=approval)
    started = clock()
    # Validated exact terminal ancestor reference only, before any fresh SDK call.
    prior = cost.retained_image_observations(prior_report_path, prior_report_sha256, request=request, now=started, root=root)
    if not campaign_budget.accepts_predecessor_cost_report(request,
            {'path': str(prior_report_path), 'sha256': prior_report_sha256}, root=root):
        raise ValueError('exact_pinned_terminal_ancestor_observations_required')
    observed = cost.observe_resources(request, {current: inventory}, now=started, clients=clients)
    try:
        try:
            complete = _complete_observations(request, inventory, observed)
        except ValueError as error:
            raise CurrentObservationError(str(error), observed, inputs) from error
        prepared = cost.prepared_pilot_campaigns(request, inventories, pilot_campaigns)
        dataset = json.loads(Path(data_manifest_path).read_text())
        training = json.loads(Path(training_path).read_text())
        throughput = cost.pilot_throughput(inventories, dataset, training['num_rounds'], prepared)
        now = clock()
        kwargs = dict(root=root, now=now, throughput=throughput, remaining_cells=remaining_cells,
            remaining_deployments=remaining_deployments, application_launches=application_launches, fault_events=fault_events)
        report = cost.reconcile(request, approval, ledger, inventories, quote, rates,
            observations=observed, retained_observations=prior, **kwargs)
        union = {arn for inv in inventories.values() for arn in inv.get('task_arns', [])}
        if (report.get('current_spend_accounted') is not True or not union <= set(report['resources']['tasks'])
                or not set(ledger.get('tasks', {})) <= union
                or report['image_pull_endpoint_planning_envelope']['available'] is not True):
            raise ValueError('full_inherited_and_current_usage_not_accounted')
        # Exactly the retained-observation route used by the native P8 assessor.
        repeated = cost.reconcile(request, approval, ledger, inventories, quote, rates,
            observations=report['aws_observations'], **kwargs)
        if any(report.get(key) != value for key, value in repeated.items()):
            raise ValueError('native_full_union_pricing_replay_mismatch')
        report['source_inputs'] = [*inputs, *(cost.binding(p) for p in
            (quote_path, catalog_path, data_manifest_path, training_path, prior_report_path, *pilot_campaigns))]
        report['source_sha256'] = {'scripts/reconcile_campaign_cost.py': cost.file_sha256(cost.__file__),
            'scripts/campaign_budget.py': cost.file_sha256(campaign_budget.__file__),
            'scripts/cost_scope_snapshot.py': cost.file_sha256(cost_scope_snapshot.__file__),
            'scripts/reconcile_current_campaign.py': cost.file_sha256(__file__)}
        report['aws_api_calls'] = True
        report['current_scope_driver'] = {'kind': 'current-MAIN-observation-full-lineage-pricing',
            'observed_campaign_ids': [current], 'priced_campaign_ids': sorted(inventories),
            'prior_report': cost.binding(prior_report_path), 'current_observations': complete,
            'all_historical_and_current_tasks_priced': True, 'native_full_union_replay_verified': True,
            'legacy_flat_projection_is_scientific_gate': False, 'budget_or_authorization_changed': False}
        return report

    except CurrentObservationError:
        raise
    except Exception as error:
        raise CurrentObservationError(str(error), observed, inputs) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True, help='Immutable frozen full B cost request')
    parser.add_argument('--quote', type=Path)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'results/aws/pricing/AmazonECS-us-east-1.json')
    parser.add_argument('--data-manifest', type=Path, default=ROOT / 'data_manifests/dataset.json')
    parser.add_argument('--training', type=Path, default=ROOT / 'configs/experiments_training.json')
    parser.add_argument('--prior-observations-report', type=Path, required=True)
    parser.add_argument('--prior-observations-sha256', required=True)
    parser.add_argument('--pilot-campaigns', type=Path, nargs='*', default=[])
    parser.add_argument('--remaining-cells', type=int, default=279)
    parser.add_argument('--remaining-deployments', type=int, default=2)
    parser.add_argument('--application-launches', type=int, default=13)
    parser.add_argument('--fault-events', type=int, default=30)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    for part in (output, *output.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise ValueError('linked_current_cost_output_forbidden')
        if part == ROOT: break
    if '..' in args.output.parts or not output.resolve().is_relative_to(ROOT.resolve()) or output.exists():
        raise ValueError('new_owned_versioned_current_cost_report_required')
    failed = False
    try:
        report = build_report(args.request, quote_path=args.quote, catalog_path=args.catalog,
            data_manifest_path=args.data_manifest, training_path=args.training,
            prior_report_path=args.prior_observations_report, prior_report_sha256=args.prior_observations_sha256,
            pilot_campaigns=args.pilot_campaigns, remaining_cells=args.remaining_cells,
            remaining_deployments=args.remaining_deployments, application_launches=args.application_launches, fault_events=args.fault_events)
    except Exception as error:
        failed = True
        report = {'schema_version': '0.1.0', 'kind': 'current-MAIN-pricing-driver-failure', 'successful': False,
            'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'current_spend_accounted': False,
            'native_full_union_replay_verified': False, 'pricing_totals': None, 'aws_mutations': False,
            'error': {'type': type(error).__name__, 'code': getattr(error, 'response', {}).get('Error', {}).get('Code') or str(error)[:180]},
            'current_observations': getattr(error, 'observations', None), 'source_inputs': getattr(error, 'source_inputs', []),
            'request_path': str(args.request), 'prior_report': {'path': str(args.prior_observations_report), 'sha256': args.prior_observations_sha256}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')
    print(json.dumps({'current_spend_accounted': report['current_spend_accounted'],
        'native_full_union_replay_verified': not failed,
        'priced_campaign_ids': report.get('current_scope_driver', {}).get('priced_campaign_ids'),
        'legacy_projection_successful': report['successful'], 'actual_bill_reconciled': False,
        'output_sha256': cost.file_sha256(args.output)}, sort_keys=True))
    return 1 if failed else 0


if __name__ == '__main__': raise SystemExit(main())
