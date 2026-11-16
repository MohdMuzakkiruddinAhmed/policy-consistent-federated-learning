"""Operator-owned IAM probe target; never a signed model or audit witness.

Default CLI performs no API calls. --apply uses the existing campaign budget,
account and operation lock. No task role gains anchor-write permissions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

KIND = "operator-probe-only-anchor-sentinel"
FIELDS = ("bucket", "key", "version_id", "sha256")


def payload(inventory):
    for name in ("campaign_id", "project_id"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", inventory[name]):
            raise ValueError("probe_sentinel_owned_scope_required")
    if not re.fullmatch(r"[0-9]{12}", inventory["account_id"]) or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", inventory["region"]):
        raise ValueError("probe_sentinel_account_region_required")
    if inventory["foundation"]["bucket_name"] != f"{inventory['project_id']}-{inventory['account_id']}-{inventory['region']}":
        raise ValueError("probe_sentinel_bucket_not_owned")
    return {"schema_version": "0.1.0", "kind": KIND,
        **{name: inventory[name] for name in ("account_id", "region", "project_id", "campaign_id")},
        "purpose": "existing-key-IAM-PutObject-denial-probe-only", "model_or_audit_evidence": False}


def expected(inventory):
    body = json.dumps(payload(inventory), sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(body).hexdigest()
    return body, f"anchors/{inventory['campaign_id']}/probe/{digest}.json", digest


def owned_bytes(record, directory):
    root, path = Path(directory).absolute(), Path(record["local_path"])
    if not path.is_absolute(): path = root / path
    if ".." in path.parts or not path.absolute().is_relative_to(root):
        raise ValueError("probe_sentinel_path_outside_campaign")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("probe_sentinel_link_forbidden")
        if part == root: break
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("probe_sentinel_custody_missing")
    return path.read_bytes()


def sentinel_references(inventory, directory):
    """Verify separate sentinel custody before selecting any probe target."""
    records = inventory.get("operator_probe_sentinels", [])
    if not isinstance(records, list) or len(records) > 1:
        raise ValueError("single_owned_probe_sentinel_required")
    if not records: return []
    body, key, digest = expected(inventory)
    result = []
    for record in records:
        if (set(record) != {"kind", *FIELDS, "size_bytes", "local_path"} or record.get("kind") != KIND
                or record["bucket"] != inventory["foundation"]["bucket_name"] or record["key"] != key
                or record["sha256"] != digest or record["size_bytes"] != len(body)
                or not isinstance(record["version_id"], str) or not record["version_id"].strip() or record["version_id"] == "null"
                or owned_bytes(record, directory) != body):
            raise ValueError("probe_sentinel_exact_reference_or_body_mismatch")
        if any(row.get("key") == key for row in inventory.get("protected_operator_witnesses", [])):
            raise ValueError("probe_sentinel_must_not_be_model_witness")
        matches = [row for row in inventory.get("retained_artifact_versions", [])
                   if all(row.get(name) == record[name] for name in (*FIELDS, "size_bytes"))]
        if len(matches) != 1 or matches[0].get("operator_probe_sentinel") is not True or matches[0].get("protected_operator_witness") is not False or owned_bytes(matches[0], directory) != body:
            raise ValueError("probe_sentinel_exact_version_not_retained")
        result.append({name: record[name] for name in FIELDS})
    return result


def custody(inventory, directory, *, require_purge=False):
    references = sentinel_references(inventory, directory)
    if require_purge and inventory.get("removed_operator_probe_sentinel_versions", []) != references:
        raise ValueError("probe_sentinel_exact_purge_receipt_required")
    return {"operator_probe_sentinels_checked": len(references)}


def select_target(inventory, directory):
    # Existing projects retain their original signed-witness preference.
    if inventory.get("protected_operator_witnesses"):
        row = inventory["protected_operator_witnesses"][0]
        return {name: row.get(name, inventory["foundation"]["bucket_name"] if name == "bucket" else None) for name in FIELDS}
    references = sentinel_references(inventory, directory)
    return references[0] if references else None


def create(runner):
    """Called only by the explicit, authorized --apply CLI (SDK-injected in tests)."""
    inventory, directory = runner.inventory, runner.directory
    body, key, digest = expected(inventory)
    original = runner.inventory_path.read_bytes()
    if json.loads(original) != inventory:
        raise ValueError("probe_sentinel_inventory_changed_before_operation")
    references = sentinel_references(inventory, directory)
    clients, bucket, account = runner.sdk(), inventory["foundation"]["bucket_name"], inventory["account_id"]
    s3 = clients["s3"]
    if s3.get_bucket_versioning(Bucket=bucket, ExpectedBucketOwner=account).get("Status") != "Enabled":
        raise ValueError("probe_sentinel_versioning_required")
    tags = s3.get_bucket_tagging(Bucket=bucket, ExpectedBucketOwner=account)["TagSet"]
    if {row["Key"]: row["Value"] for row in tags}.get("Project") != inventory["project_id"]:
        raise ValueError("probe_sentinel_project_tag_required")
    def get(version=None):
        response = s3.get_object(Bucket=bucket, Key=key, ExpectedBucketOwner=account,
                                 **({"VersionId": version} if version else {}))
        try: observed = response["Body"].read(4097)
        finally: response["Body"].close()
        version = response.get("VersionId")
        if (observed != body or response.get("ServerSideEncryption") != "AES256"
                or not isinstance(version, str) or not version or version == "null"):
            raise ValueError("probe_sentinel_remote_version_or_body_mismatch")
        return version
    if references:
        if get(references[0]["version_id"]) != references[0]["version_id"]:
            raise ValueError("probe_sentinel_remote_version_changed")
        if get() != references[0]["version_id"]:
            raise ValueError("probe_sentinel_latest_key_not_recorded_version")
        return {"probe_only": True, "model_or_audit_witness": False, "reference": references[0], "created": False}
    try:
        version = get()  # Recover the deterministic own key after an ambiguous prior Put.
    except Exception as error:
        if getattr(error, "response", {}).get("Error", {}).get("Code") not in {"NoSuchKey", "404", "NotFound"}:
            raise
        try:
            response = s3.put_object(Bucket=bucket, Key=key, Body=body, IfNoneMatch="*", ServerSideEncryption="AES256",
                ContentType="application/json", ExpectedBucketOwner=account)
            version = response.get("VersionId")
            if not isinstance(version, str) or not version or version == "null":
                raise ValueError("probe_sentinel_put_did_not_return_immutable_version")
            if get(version) != version: raise ValueError("probe_sentinel_put_version_not_confirmed")
        except Exception as write_error:
            if getattr(write_error, "response", {}).get("Error", {}).get("Code") not in {"PreconditionFailed", "412"}: raise
            version = get()
    if runner.inventory_path.read_bytes() != original:
        raise ValueError("probe_sentinel_inventory_changed_no_cas_merge")
    path = directory / "operator-probes" / (digest[:16] + ".json")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("probe_sentinel_link_forbidden")
        if part == directory: break
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and owned_bytes({"local_path": str(path)}, directory) != body:
        raise ValueError("probe_sentinel_local_collision")
    if not path.exists():
        with path.open("xb") as stream: stream.write(body)
    record = {"kind": KIND, "bucket": bucket, "key": key, "version_id": version, "sha256": digest,
              "size_bytes": len(body), "local_path": str(path.absolute())}
    retained = {name: record[name] for name in (*FIELDS, "size_bytes", "local_path")}
    retained.update(operator_probe_sentinel=True, protected_operator_witness=False)
    inventory["operator_probe_sentinels"] = [record]
    inventory.setdefault("retained_artifact_versions", []).append(retained)
    sentinel_references(inventory, directory)
    runner.save()
    return {"probe_only": True, "model_or_audit_witness": False,
            "reference": {name: record[name] for name in FIELDS}, "created": True}


def main():
    from aws_campaign import CampaignRunner, exclusive_file, load_request, ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    request = load_request(args.request)
    if not args.apply:
        print(json.dumps({"aws_api_calls": False, "mutations_enabled": False, "probe_only": True,
            "model_or_audit_witness": False, "campaign_id": request["campaign_id"]}))
        return
    with exclusive_file(ROOT / "results/aws/campaign-operation.lock"):
        runner = CampaignRunner(request, apply=True)
        runner.authorize()
        print(json.dumps(create(runner), sort_keys=True))


if __name__ == "__main__": main()
