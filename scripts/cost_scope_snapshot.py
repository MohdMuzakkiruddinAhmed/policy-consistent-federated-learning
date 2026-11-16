"""Owned immutable cost-input snapshots. No AWS or executable request is made.

Snapshot files are read-only evidence. Runner guards reject their typed request
or marker before mutation/status collection. Original request bytes are retained
inside a non-executable envelope; no plain runnable original clone is emitted.
"""
import argparse
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

KIND = "frozen-campaign-cost-request"
MANIFEST_KIND = "campaign-cost-scope-snapshot"
ENVELOPE_KIND = "frozen-campaign-source-request-bytes"
ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
SHA = re.compile(r"[0-9a-f]{64}\Z")


def owned(root, value, *, must_exist=True):
    root, path = Path(root).resolve(), Path(value)
    if not path.is_absolute(): path = root / path
    if ".." in path.parts or not path.resolve().is_relative_to(root):
        raise ValueError("owned_cost_snapshot_path_required")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_cost_snapshot_path_forbidden")
    if must_exist and (not path.is_file() or path.stat().st_size > 64 * 1024**2):
        raise ValueError("bounded_regular_cost_snapshot_source_required")
    return path.resolve()


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference(path, root):
    path = owned(root, path)
    return {"path": path.relative_to(Path(root).resolve()).as_posix(), "sha256": sha(path)}


def read_bound(value, root):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"} or not SHA.fullmatch(value.get("sha256", "")):
        raise ValueError("exact_cost_snapshot_reference_required")
    path = owned(root, value["path"])
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != value["sha256"]:
        raise ValueError("cost_snapshot_source_digest_mismatch")
    return json.loads(body), path


def scope_names(request, ledger):
    names = {request["campaign_id"], *(row["campaign_id"] for row in ledger.get("deployments", {}).values()),
        *(row["campaign_id"] for row in ledger.get("tasks", {}).values() if row.get("campaign_id"))}
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", name) for name in names):
        raise ValueError("bounded_snapshot_campaign_identity_required")
    return names


def load_scope(request_path, *, root, approval_loader, state_validator=None, request_validator=None):
    path = owned(root, request_path)
    frozen = json.loads(path.read_bytes())
    marker = frozen.get("cost_scope_snapshot")
    if (frozen.get("kind") != KIND or not isinstance(marker, dict)
            or set(marker) != {"schema_version", "kind", "manifest", "execution_disabled"}
            or marker.get("schema_version") != "0.1.0" or marker.get("kind") != MANIFEST_KIND
            or marker.get("execution_disabled") is not True):
        raise ValueError("strict_nonexecutable_cost_snapshot_request_required")
    manifest, manifest_path = read_bound(marker["manifest"], root)
    if (manifest.get("kind") != MANIFEST_KIND or manifest.get("schema_version") != "0.1.0"
            or manifest.get("execution_disabled") is not True
            or any(manifest.get(key) != frozen.get(key) for key in ("account_id", "region", "campaign_id"))):
        raise ValueError("cost_snapshot_manifest_identity_mismatch")
    envelope, envelope_path = read_bound(manifest["source_request_envelope"], root)
    if envelope.get("kind") != ENVELOPE_KIND or envelope.get("cost_scope_snapshot") is not True:
        raise ValueError("nonexecutable_source_request_envelope_required")
    try:
        source_bytes = base64.b64decode(envelope["original_request_bytes_base64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("exact_source_request_bytes_required") from None
    if (hashlib.sha256(source_bytes).hexdigest() != envelope.get("original_request_sha256")
            or envelope.get("original_request_sha256") != manifest.get("original_request_sha256")):
        raise ValueError("original_request_byte_identity_mismatch")
    source = json.loads(source_bytes)
    if "cost_scope_snapshot" in source or source.get("kind") == KIND:
        raise ValueError("nested_cost_snapshot_forbidden")
    expected = {**source, "kind": KIND, "cost_scope_snapshot": marker}
    if frozen != expected:
        raise ValueError("frozen_request_changed_original_scope_fields")
    if manifest.get("authorization") != source.get("authorization"):
        raise ValueError("snapshot_authorization_identity_rebound")
    if request_validator is not None:
        request_validator(path)
    approval = approval_loader(frozen)
    ledger, ledger_path = read_bound(manifest["ledger"], root)
    if ledger.get("authorization_sha256") != source["authorization"]["sha256"]:
        raise ValueError("snapshot_ledger_authorization_mismatch")
    inventories, inputs = {}, [reference(path, root), reference(manifest_path, root), reference(envelope_path, root), reference(ledger_path, root)]
    for entry in manifest.get("inventories", []):
        inventory, inventory_path = read_bound(entry["reference"], root)
        campaign = entry["campaign_id"]
        if (campaign in inventories or inventory.get("campaign_id") != campaign
                or any(inventory.get(key) != source.get(key) for key in ("account_id", "region"))):
            raise ValueError("snapshot_inventory_scope_or_uniqueness_failed")
        inventories[campaign] = inventory
        inputs.append(reference(inventory_path, root))
    if set(inventories) != scope_names(source, ledger):
        raise ValueError("complete_snapshot_campaign_union_required")
    if state_validator is not None:
        state_validator(frozen, approval, ledger, inventories)
    # Authorization/quote decisions are independently immutable; bind their
    # identity rather than retaining a pointer to mutable original request state.
    _, authorization_path = read_bound(source["authorization"], root)
    inputs.append(reference(authorization_path, root))
    return frozen, approval, ledger, inventories, inputs


def create(request_path, output, *, root=ROOT, loader=None):
    root, source_path = Path(root).resolve(), owned(root, request_path)
    output = owned(root, output, must_exist=False)
    if output.exists(): raise ValueError("new_cost_snapshot_directory_required")
    if loader is None:
        from reconcile_campaign_cost import load_scope as loader
    source_bytes = source_path.read_bytes()
    source = json.loads(source_bytes)
    if "cost_scope_snapshot" in source or source.get("kind") == KIND:
        raise ValueError("snapshot_only_original_live_scope_once")
    request, approval, ledger, inventories, inputs = loader(source_path, root=root)
    # Read every bound source once, then recheck all hashes after construction.
    records = []
    for value in inputs:
        body, path = read_bound(value, root)
        records.append((value, body, path.read_bytes()))
    ledger_records = [(value, body, raw) for value, body, raw in records if body == ledger]
    if len({value["sha256"] for value, body, raw in ledger_records}) != 1:
        raise ValueError("one_exact_loaded_ledger_source_required")
    if scope_names(source, ledger) != set(inventories):
        raise ValueError("loaded_cost_scope_union_mismatch")
    # Only new evidence is written. Source/live ledgers and requests are untouched.
    output.mkdir(parents=True, exist_ok=False)
    def put(name, body=None, raw=None):
        destination = output / name
        content = raw if raw is not None else (json.dumps(body, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
        with destination.open("xb") as stream: stream.write(content)
        return reference(destination, root)
    envelope = {"kind": ENVELOPE_KIND, "cost_scope_snapshot": True,
        "original_request_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "original_request_bytes_base64": base64.b64encode(source_bytes).decode("ascii")}
    envelope_ref = put("request-source-envelope.json", envelope)
    ledger_ref = put("ledger.json", raw=ledger_records[0][2])
    inv_refs = []
    for index, (campaign, inventory) in enumerate(sorted(inventories.items())):
        candidates = [(value, raw) for value, body, raw in records if body == inventory]
        if not candidates: raise ValueError("loaded_inventory_original_bytes_missing")
        inv_refs.append({"campaign_id": campaign, "reference": put(f"{index:02d}-inventory.json", raw=candidates[0][1])})
    if source_path.read_bytes() != source_bytes:
        raise ValueError("live_request_changed_during_cost_snapshot")
    for value, body, raw in records:
        read_bound(value, root)
    manifest = {"schema_version": "0.1.0", "kind": MANIFEST_KIND, "execution_disabled": True,
        **{key: source[key] for key in ("account_id", "region", "campaign_id")},
        "authorization": deepcopy(source["authorization"]), "original_request_sha256": envelope["original_request_sha256"],
        "source_request_envelope": envelope_ref, "ledger": ledger_ref, "inventories": inv_refs}
    manifest_ref = put("manifest.json", manifest)
    marker = {"schema_version": "0.1.0", "kind": MANIFEST_KIND, "manifest": manifest_ref, "execution_disabled": True}
    frozen_ref = put("request.json", {**source, "kind": KIND, "cost_scope_snapshot": marker})
    return {"schema_version": "0.1.0", "kind": "cost-scope-snapshot-receipt", "request": frozen_ref,
        "manifest": manifest_ref, "campaign_ids": sorted(inventories), "aws_calls": False, "execution_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(create(args.request, args.output_directory), sort_keys=True))


if __name__ == "__main__": main()
