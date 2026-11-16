"""Create an independently verified operator witness outside task-writable prefixes."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def create_witness(payload, private_key):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP384R1):
        raise ValueError("P384_operator_witness_key_required")
    public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"schema_version": "0.1.0", "algorithm": "ECDSA-P384-SHA384", "payload": payload,
            "payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "signature_base64": base64.b64encode(private_key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))).decode()}


def verify_witness(witness, public_key_pem, *, expected_public_key_sha256):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        return False
    public = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(public).hexdigest()
    if (witness.get("algorithm") != "ECDSA-P384-SHA384" or fingerprint != expected_public_key_sha256
            or witness.get("public_key_sha256") != fingerprint
            or witness.get("payload_sha256") != hashlib.sha256(canonical(witness["payload"])).hexdigest()):
        return False
    try:
        key.verify(base64.b64decode(witness["signature_base64"], validate=True), canonical(witness["payload"]), ec.ECDSA(hashes.SHA384()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def observed_payload(result, *, raw_sha256, cell_id, campaign_id, application_id, head, pointer):
    """Witness observed durable state even when execution failed before a model."""
    anchor = {"count": int(head.get("count", {}).get("N", "0")),
              "head": head.get("head", {}).get("S", "0" * 64)}
    if anchor != result["anchor"]:
        raise ValueError("operator_strong_read_disagrees_with_exported_anchor")
    manifests = result.get("published_manifests", [])
    last = manifests[-1] if manifests else None
    if ((last is None and pointer) or
            (last is not None and pointer.get("manifest_id", {}).get("S") != last["manifest_id"])):
        raise ValueError("operator_strong_read_disagrees_with_exported_pointer")
    return {"schema_version": "0.1.0", "campaign_id": campaign_id, "application_campaign_id": application_id,
        "cell_id": cell_id, "run_id": result["persistent_run_id"], "raw_result_sha256": raw_sha256,
        "anchor": anchor, "manifest_id": last["manifest_id"] if last else None,
        "model_schema_hash": result["model_schema_hash"], "model_digest": last["model_digest"] if last else None,
        "commit_order": last["commit_order"] if last else 0,
        "execution_successful": result.get("successful") is True,
        "operator_observed_at_utc": datetime.now(timezone.utc).isoformat()}


def retained_cases(inventory, inventory_path):
    export = inventory["export"]
    directory = Path(export.get("export_root", inventory_path.parent / "r")).resolve()
    if not directory.is_relative_to(inventory_path.parent):
        raise ValueError("export_root_outside_inventory")
    raw_index = (directory / "campaign_result.json").read_bytes()
    if hashlib.sha256(raw_index).hexdigest() != export["index_sha256"]:
        raise ValueError("retained_campaign_index_changed")
    index = json.loads(raw_index)
    application = export.get("application_campaign_id", inventory["campaign_id"])
    if index["campaign_id"] != application:
        raise ValueError("retained_application_mismatch")
    seen, result = set(), []
    for case in index["cases"]:
        cell_id = case["cell_id"]
        if cell_id in seen:
            raise ValueError("duplicate_retained_case")
        seen.add(cell_id)
        case_directory = directory / hashlib.sha256(cell_id.encode()).hexdigest()[:8]
        raw = (case_directory / "runtime_result.json").read_bytes()
        key = f"evidence/campaigns/{application}/{cell_id}/runtime_result.json"
        refs = [ref for ref in case["artifacts"] if ref["key"] == key]
        sha256 = hashlib.sha256(raw).hexdigest()
        if (len(refs) != 1 or refs[0]["sha256"] != sha256 or refs[0]["size_bytes"] != len(raw)
                or refs[0]["bucket"] != inventory["foundation"]["bucket_name"] or refs[0].get("version_id") in {None, "null"}):
            raise ValueError("exact_retained_result_required_before_witness")
        result.append((cell_id, case_directory, json.loads(raw), sha256))
    return application, result


def _anchor_inventory(inventory_path, *, apply=False):
    inventory_path = Path(inventory_path).resolve()
    inventory_before = inventory_path.read_bytes()
    inventory = json.loads(inventory_before)
    application, cases = retained_cases(inventory, inventory_path)
    if not apply:
        return {"aws_calls": False, "case_witnesses_proposed": len(cases), "protected_prefix": "anchors/"}
    import boto3
    from botocore.config import Config
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    common = {"region_name": inventory["region"], "config": Config(ignore_configured_endpoint_urls=True)}
    if boto3.client("sts", **common).get_caller_identity()["Account"] != inventory["account_id"]:
        raise ValueError("operator_witness_account_mismatch")
    s3, ddb = boto3.client("s3", **common), boto3.client("dynamodb", **common)
    key_path = inventory_path.parent / "operator-witness.key"
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP384R1())
        raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(raw)
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (inventory_path.parent / "operator-witness-public.pem").write_bytes(public_pem)
    witnesses = list(inventory.get("protected_operator_witnesses", []))
    created = []
    for cell_id, directory, result, result_sha in cases:
        if any(old.get("cell_id") == cell_id and old.get("raw_result_sha256") == result_sha
               and old.get("application_campaign_id", inventory["campaign_id"]) == application for old in witnesses):
            continue
        run_id = result["persistent_run_id"]
        def read(sk):
            return ddb.get_item(TableName=inventory["foundation"]["state_table_name"],
                Key={"PK": {"S": "RUN#" + run_id}, "SK": {"S": sk}}, ConsistentRead=True).get("Item", {})
        head, pointer = read("AUDIT_HEAD"), read("POINTER")
        payload = observed_payload(result, raw_sha256=result_sha, cell_id=cell_id, campaign_id=inventory["campaign_id"],
            application_id=application, head=head, pointer=pointer)
        witness = create_witness(payload, key)
        if not verify_witness(witness, public_pem, expected_public_key_sha256=witness["public_key_sha256"]):
            raise ValueError("operator_signature_self_check_failed")
        body = canonical(witness)
        digest = hashlib.sha256(body).hexdigest()
        object_key = f"anchors/{inventory['campaign_id']}/{hashlib.sha256(cell_id.encode()).hexdigest()[:24]}/{digest}.json"
        response = s3.put_object(Bucket=inventory["foundation"]["bucket_name"], Key=object_key, Body=body,
            ExpectedBucketOwner=inventory["account_id"], ServerSideEncryption="AES256", IfNoneMatch="*")
        version = response.get("VersionId")
        if not version or version == "null":
            raise ValueError("protected_witness_requires_versioned_object")
        path = directory / ("operator_witness-" + digest[:8] + ".json")
        path.write_bytes(body)
        record = {"cell_id": cell_id, "application_campaign_id": application, "raw_result_sha256": result_sha,
                  "key": object_key, "version_id": version, "sha256": digest,
                  "public_key_sha256": witness["public_key_sha256"], "local_path": str(path)}
        witnesses.append(record)
        created.append(record)
        # Retain the exact newly created version binding before verification.
        # A GET failure leaves a recoverable recorded witness, never an allowlist
        # entry or a reason to create a second signature on retry.
        from aws_campaign import write_json
        inventory["protected_operator_witnesses"] = witnesses
        if inventory_path.read_bytes() != inventory_before:
            raise ValueError("inventory_changed_before_new_witness_record_CAS")
        write_json(inventory_path, inventory)
        inventory_before = inventory_path.read_bytes()
    inventory["protected_operator_witnesses"] = witnesses
    from witness_retention import retain_recorded_witnesses, persist_retention
    public_pin = hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    inventory, receipt, retention = retain_recorded_witnesses(inventory, s3, directory=inventory_path.parent,
        public_key_pem=public_pem, expected_public_key_sha256=public_pin)
    retention_binding = persist_retention(inventory_path, inventory_before, inventory, receipt)
    witnesses = inventory["protected_operator_witnesses"]
    output = {"successful": True, "campaign_id": inventory["campaign_id"], "witnesses": witnesses,
        "anchor_state_separate_from_task_writable_prefixes": True,
        "limitations": ["The operator/public verification key are trusted; account administrator compromise remains outside this claim",
                        "A signed observation is not a successful execution or full-protocol verification; failed and partial runs remain identified",
                        "Task-role denial of anchors/ writes must also be demonstrated by actual IAM probes"]}
    destination = ROOT / "reports/protected_anchor_validation.json"
    destination.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return {"successful": True, "protected_witnesses_created": len(created), "protected_witnesses_retained": len(witnesses),
        "protected_witness_versions_newly_retained": retention["versions_added"], "retention_receipt": retention_binding}


def anchor_inventory(inventory_path, *, apply=False):
    if not apply:
        return _anchor_inventory(inventory_path, apply=False)
    from aws_campaign import exclusive_file
    with exclusive_file(ROOT / "results/aws/campaign-operation.lock"):
        return _anchor_inventory(inventory_path, apply=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(anchor_inventory(args.inventory, apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
