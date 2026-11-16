"""Verify and retain only already-recorded protected witness versions.

No object writes, signing, DynamoDB access or pointer changes occur here. The
apply CLI performs read-only STS/S3 calls and a guarded local custody update.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
SHA = re.compile(r"[0-9a-f]{64}")
MAX_WITNESS_BYTES = 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(body): return hashlib.sha256(body).hexdigest()


def owned_file(value, directory):
    directory = Path(directory).absolute()
    path = Path(value)
    if not path.is_absolute(): path = directory / path
    if ".." in path.parts:
        raise ValueError("witness_custody_path_outside_owned_campaign")
    for component in (path, *path.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("linked_witness_custody_forbidden")
        if component == directory: break
    # Windows may expose the same owned directory through an 8.3 alias. Check
    # ancestry for links first, then compare canonical paths rather than labels.
    if not path.resolve().is_relative_to(directory.resolve()):
        raise ValueError("witness_custody_path_outside_owned_campaign")
    if not path.is_file():
        raise ValueError("owned_regular_witness_custody_file_required")
    return path


def _scope(inventory):
    account, region, project, campaign = (inventory[key] for key in ("account_id", "region", "project_id", "campaign_id"))
    if (not re.fullmatch(r"\d{12}", account) or not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", region)
            or not re.fullmatch(r"[a-z][a-z0-9-]{2,35}", project)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", campaign)
            or inventory["foundation"]["bucket_name"] != f"{project}-{account}-{region}"):
        raise ValueError("exact_owned_witness_bucket_and_campaign_required")
    return account, region, project, campaign, inventory["foundation"]["bucket_name"]


def _raw_binding(inventory, *, directory, bucket, application, cell, expected_sha):
    key = f"evidence/campaigns/{application}/{cell}/runtime_result.json"
    matches = [row for row in inventory.get("retained_artifact_versions", [])
        if row.get("bucket") == bucket and row.get("key") == key and row.get("sha256") == expected_sha
        and row.get("version_id") not in {None, "", "null"}]
    if not matches: raise ValueError("signed_witness_raw_result_not_in_exact_retained_custody")
    for row in matches:
        path = owned_file(row["local_path"], directory)
        body = path.read_bytes()
        if type(row.get("size_bytes")) is not int or len(body) != row["size_bytes"] or digest(body) != expected_sha:
            raise ValueError("retained_signed_witness_raw_result_changed")
    return json.loads(body)


def retain_recorded_witnesses(inventory, s3, *, directory, public_key_pem, expected_public_key_sha256):
    """Return an updated copy plus content-addressed verification receipt.

    The caller establishes STS identity first. Every recorded witness receives an
    exact-version GET with ExpectedBucketOwner; no anchor discovery is allowed.
    """
    from anchor_evidence import verify_witness
    if not isinstance(expected_public_key_sha256, str) or not SHA.fullmatch(expected_public_key_sha256):
        raise ValueError("external_operator_public_key_pin_required")
    account, region, project, campaign, bucket = _scope(inventory)
    if s3.get_bucket_versioning(Bucket=bucket, ExpectedBucketOwner=account).get("Status") != "Enabled":
        raise ValueError("versioned_witness_bucket_required")
    previous, identities = deepcopy(inventory.get("retained_artifact_versions", [])), {}
    for row in previous:
        identity = row.get("bucket"), row.get("key"), row.get("version_id")
        if identity in identities: raise ValueError("duplicate_existing_retained_version")
        identities[identity] = row
    records, normalized, verified, seen, added = inventory.get("protected_operator_witnesses", []), [], [], set(), []
    if not isinstance(records, list) or not records or len(records) > 10000:
        raise ValueError("bounded_recorded_protected_witness_list_required")
    for original in records:
        record = deepcopy(original)
        key, version, sha = (record.get(name) for name in ("key", "version_id", "sha256"))
        cell = record.get("cell_id")
        if (not isinstance(cell, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", cell)
                or not isinstance(sha, str) or not SHA.fullmatch(sha)
                or key != f"anchors/{campaign}/{hashlib.sha256(cell.encode()).hexdigest()[:24]}/{sha}.json"
                or record.get("bucket", bucket) != bucket or not isinstance(version, str) or not version or version == "null"
                or record.get("kind") == "operator-probe-only-anchor-sentinel"):
            raise ValueError("recorded_protected_witness_identity_invalid")
        identity = bucket, key, version
        if identity in seen: raise ValueError("duplicate_recorded_protected_witness")
        seen.add(identity)
        local = owned_file(record["local_path"], directory)
        local_body = local.read_bytes()
        if not local_body or len(local_body) > MAX_WITNESS_BYTES or digest(local_body) != sha:
            raise ValueError("recorded_witness_local_body_changed")
        response = s3.get_object(Bucket=bucket, Key=key, VersionId=version, ExpectedBucketOwner=account)
        try:
            body = response["Body"].read(MAX_WITNESS_BYTES + 1)
        finally:
            response["Body"].close()
        if (response.get("VersionId") != version or response.get("ServerSideEncryption") != "AES256"
                or type(response.get("ContentLength")) is not int or response["ContentLength"] != len(body)
                or len(body) > MAX_WITNESS_BYTES or body != local_body or digest(body) != sha):
            raise ValueError("exact_remote_witness_version_body_size_or_SSE_mismatch")
        witness = json.loads(body)
        try:
            valid = verify_witness(witness, public_key_pem, expected_public_key_sha256=expected_public_key_sha256)
        except (KeyError, TypeError, ValueError): valid = False
        if not valid or record.get("public_key_sha256", expected_public_key_sha256) != expected_public_key_sha256:
            raise ValueError("external_pinned_witness_signature_failed")
        payload = witness["payload"]
        application = record.get("application_campaign_id", campaign)
        raw_sha = record.get("raw_result_sha256", payload.get("raw_result_sha256"))
        if (payload.get("campaign_id") != campaign or payload.get("application_campaign_id", campaign) != application
                or payload.get("cell_id") != cell or payload.get("raw_result_sha256") != raw_sha
                or not isinstance(raw_sha, str) or not SHA.fullmatch(raw_sha)):
            raise ValueError("signed_witness_record_scope_mismatch")
        raw = _raw_binding(inventory, directory=directory, bucket=bucket, application=application, cell=cell, expected_sha=raw_sha)
        manifests = raw.get("published_manifests", [])
        last = manifests[-1] if manifests else None
        if (payload.get("run_id") != raw.get("persistent_run_id") or payload.get("anchor") != raw.get("anchor")
                or payload.get("model_schema_hash") != raw.get("model_schema_hash")
                or payload.get("manifest_id") != (last["manifest_id"] if last else None)
                or payload.get("model_digest") != (last["model_digest"] if last else None)
                or payload.get("commit_order") != (last["commit_order"] if last else 0)
                or ("execution_successful" in payload and payload["execution_successful"] is not (raw.get("successful") is True))):
            raise ValueError("signed_witness_original_raw_or_model_binding_failed")
        if "size_bytes" in record and record["size_bytes"] != len(body):
            raise ValueError("recorded_witness_size_changed")
        for name, value in (("bucket", bucket), ("size_bytes", len(body)), ("application_campaign_id", application),
                ("raw_result_sha256", raw_sha), ("public_key_sha256", expected_public_key_sha256)):
            record.setdefault(name, value)
        normalized.append(record)
        old = identities.get(identity)
        if old is not None:
            path = owned_file(old["local_path"], directory)
            if (old.get("sha256") != sha or old.get("size_bytes") != len(body) or path.read_bytes() != body
                    or old.get("operator_probe_sentinel") is True):
                raise ValueError("existing_retained_witness_conflict_or_corruption")
        else:
            old = {"bucket": bucket, "key": key, "version_id": version, "sha256": sha, "size_bytes": len(body),
                "local_path": str(local), "protected_operator_witness": True}
            previous.append(old); identities[identity] = old; added.append({"key": key, "version_id": version})
        verified.append({"bucket": bucket, "key": key, "version_id": version, "sha256": sha, "size_bytes": len(body),
            "local_path": str(local), "cell_id": cell, "application_campaign_id": application,
            "raw_result_sha256": raw_sha, "public_key_sha256": expected_public_key_sha256,
            "server_side_encryption": "AES256", "signature_verified": True})
    updated = deepcopy(inventory)
    updated["protected_operator_witnesses"], updated["retained_artifact_versions"] = normalized, previous
    receipt = {"schema_version": "0.1.0", "kind": "operator-protected-witness-retention-verification",
        "account_id": account, "region": region, "project_id": project, "campaign_id": campaign, "bucket": bucket,
        "expected_public_key_sha256": expected_public_key_sha256, "scope": "already-recorded-exact-witness-versions-only",
        "verified_references": verified, "S3_object_writes": False, "signatures_created": False,
        "raw_results_or_model_pointers_changed": False}
    return updated, receipt, {"witnesses_verified": len(verified), "versions_added": len(added), "added_versions": added}


def persist_retention(inventory_path, before, updated, receipt):
    """CAS the local inventory; retain a stable receipt without duplicate retries."""
    from aws_campaign import write_json
    path = Path(inventory_path)
    digest_value = digest(canonical(receipt))
    destination = path.parent / "witness-retention" / (digest_value[:16] + ".json")
    for component in (destination.parent, *destination.parent.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("linked_witness_retention_receipt_directory_forbidden")
        if component == path.parent: break
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if owned_file(destination, path.parent).read_bytes() != canonical(receipt) + b"\n":
            raise ValueError("witness_retention_receipt_collision")
    else:
        with destination.open("xb") as stream: stream.write(canonical(receipt) + b"\n")
    binding = {"path": str(destination), "sha256": digest(destination.read_bytes()), "verification_digest": digest_value}
    bindings = list(updated.get("operator_witness_retention_receipts", []))
    if not any(row == binding for row in bindings): bindings.append(binding)
    updated["operator_witness_retention_receipts"] = bindings
    if path.read_bytes() != before: raise ValueError("inventory_changed_before_witness_retention_CAS")
    if updated != json.loads(before): write_json(path, updated)
    return binding


def backfill_inventory(inventory_path, *, public_key_path, expected_public_key_sha256,
        expected_inventory_sha256=None, apply=False, clients=None):
    candidate = Path(inventory_path)
    if ".." in candidate.parts:
        raise ValueError("witness_custody_path_outside_owned_campaign")
    # CLI paths are relative to the process working directory. Custody refs
    # inside inventory records remain relative to their campaign directory.
    # Do not resolve before owned_file has checked link ancestry.
    candidate = candidate.absolute()
    path = owned_file(candidate, candidate.parent)
    before = path.read_bytes(); inventory = json.loads(before)
    account, region, _, _, _ = _scope(inventory)
    if not apply:
        return {"aws_calls": False, "local_inventory_changes": False,
            "recorded_witnesses_proposed": len(inventory.get("protected_operator_witnesses", []))}
    if expected_inventory_sha256 != digest(before): raise ValueError("expected_inventory_SHA_required_before_backfill")
    public = Path(public_key_path).read_bytes()
    if len(public) > 65536: raise ValueError("bounded_public_key_required")
    from aws_campaign import exclusive_file
    with exclusive_file(ROOT / "results/aws/campaign-operation.lock"):
        if path.read_bytes() != before: raise ValueError("inventory_changed_while_waiting_for_backfill_lock")
        if clients is None:
            import boto3
            from botocore.config import Config
            config = Config(ignore_configured_endpoint_urls=True, connect_timeout=3, read_timeout=3, retries={"max_attempts": 0})
            clients = {name: boto3.client(name, region_name=region, config=config) for name in ("sts", "s3")}
        if clients["sts"].get_caller_identity().get("Account") != account:
            raise ValueError("witness_retention_STS_account_mismatch")
        updated, receipt, result = retain_recorded_witnesses(inventory, clients["s3"], directory=path.parent,
            public_key_pem=public, expected_public_key_sha256=expected_public_key_sha256)
        binding = persist_retention(path, before, updated, receipt)
        return {"successful": True, "aws_mutations": False, "signatures_created": False,
            "inventory_sha256_before": digest(before), "inventory_sha256_after": digest(path.read_bytes()),
            "receipt": binding, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--expected-inventory-sha256")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(backfill_inventory(args.inventory, public_key_path=args.public_key,
        expected_public_key_sha256=args.expected_public_key_sha256, expected_inventory_sha256=args.expected_inventory_sha256,
        apply=args.apply), sort_keys=True))


if __name__ == "__main__": main()
