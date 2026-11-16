"""Prepare a successor ledger locally after actual approval and terminal cleanup.

Default is a read-only preview. This command never writes an approval, calls AWS,
changes caps, launches a task or modifies a predecessor ledger.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
from campaign_budget import campaign_inventories, new_ledger, proposed_retirement_registry, retirement_registry, validate_amendment, validate_ledger_lineage


def initialize(request, *, root=ROOT, apply=False):
    root = Path(root).resolve()
    if apply and ("cost_scope_snapshot" in request or request.get("kind") == "frozen-campaign-cost-request"):
        raise ValueError("frozen_cost_snapshot_request_is_read_only")
    if request.get("campaign_budget_kind") != "campaign-authorization-amendment":
        raise ValueError("amendment_requires_explicit_new_typed_request")
    registry_path = root / "results/aws/budget-authorization-retirements.json"
    registry_before = registry_path.read_bytes() if registry_path.exists() else None
    context = validate_amendment(request, root=root)
    retirement = proposed_retirement_registry(request, context, root=root)
    path = root / "results/aws" / ("budget-ledger-" + request["authorization"]["sha256"] + ".json")
    summary = {"kind": "successor-budget-ledger-local-preparation", "aws_calls": False,
        "approval_created": False, "mutations_enabled": apply, "successor_created": False,
        "predecessor_tasks": len(context["tasks"]), "predecessor_deployments": len(context["deployments"]),
        "budget_family_id": context["budget_family_id"], "usage_floors": context["usage_floors"],
        "authorization_sha256": request["authorization"]["sha256"]}
    if path.exists():
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("successor_ledger_outside_owned_root")
        old = path.read_bytes()
        ledger = json.loads(old)
        current_path = root / "results/aws" / request["campaign_id"] / "inventory.json"
        current = json.loads(current_path.read_bytes()) if current_path.is_file() else {
            key: request[key] for key in ("account_id", "region", "project_id", "campaign_id")}
        inventories = campaign_inventories(request, ledger, root=root, current_inventory=current)
        validate_ledger_lineage(request, ledger, root=root, campaign_inventories=inventories)
        if path.read_bytes() != old: raise ValueError("successor_ledger_changed_during_reuse_check")
        if apply:
            _register_retirement(registry_path, registry_before, retirement)
        return {**summary, "existing_valid_successor_reused": True}
    if not apply: return {**summary, "existing_valid_successor_reused": False}
    ledger = new_ledger(request, root=root)
    # Re-read all immutable terminal refs immediately before exclusive create.
    if validate_amendment(request, root=root) != context:
        raise ValueError("terminal_amendment_context_changed_before_create")
    for component in (path, *path.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("linked_successor_ledger_path_forbidden")
        if component == root: break
    path.parent.mkdir(parents=True, exist_ok=True)
    # Retire old execution BEFORE exposing the new ledger. A crash in between
    # leaves A blocked and B uninitialized; a same-B retry safely finishes.
    _register_retirement(registry_path, registry_before, retirement)
    _publish_exclusive_bytes(path, (json.dumps(ledger, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())
    return {**summary, "successor_created": True, "existing_valid_successor_reused": False}


def _register_retirement(path, before, value):
    current = path.read_bytes() if path.exists() else None
    if current != before: raise ValueError("budget_retirement_registry_changed_before_cas")
    from aws_campaign import write_json
    write_json(path, value)
    body = path.read_bytes()
    archive = path.parent / "budget-lineage-history" / (hashlib.sha256(body).hexdigest() + ".json")
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        if archive.read_bytes() != body: raise ValueError("budget_retirement_history_collision")
    else:
        _publish_exclusive_bytes(archive, body)
    required = path.parent / "budget-lineage-required.json"
    marker = {"schema_version": "0.1.0", "kind": "campaign-budget-lineage-registry-required"}
    if required.exists():
        if json.loads(required.read_bytes()) != marker: raise ValueError("budget_lineage_required_marker_changed")
    else:
        _publish_exclusive_bytes(required, (json.dumps(marker, sort_keys=True) + "\n").encode())


def _publish_exclusive_bytes(path, body):
    """Publish complete bytes atomically without replacing a progressed file."""
    descriptor, temporary = tempfile.mkstemp(prefix=".budget-init-", suffix=".tmp", dir=path.parent)
    pending = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        # Same-directory hardlink creation is atomic and fails if destination
        # already exists. Unsupported filesystems fail closed; no overwrite
        # rename fallback is permitted.
        os.link(pending, path)
    finally:
        if pending.exists():
            if pending.parent.resolve() != path.parent.resolve():
                raise ValueError("refusing_unowned_budget_pending_file_cleanup")
            pending.unlink()


def main():
    from aws_campaign import exclusive_file, load_request, validate_authorization
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    request = load_request(args.request)
    validate_authorization(request)
    ledger = ROOT / "results/aws" / ("budget-ledger-" + request["authorization"]["sha256"] + ".json")
    if not args.apply:
        result = initialize(request)
    else:
        with exclusive_file(ROOT / "results/aws/campaign-operation.lock"):
            with exclusive_file(ledger.with_suffix(".lock")):
                result = initialize(request, apply=True)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__": main()
