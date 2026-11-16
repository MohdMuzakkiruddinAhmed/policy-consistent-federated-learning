"""Exact partial-index recovery tests using real synthetic NPZ verification."""

from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from collect_partial_cloud import collect, digest, latest_index, operator_snapshot
from test_runtime_verify import persistent_fixture


class S3:
    def __init__(self, objects, calls):
        self.objects, self.calls = objects, calls

    def get_object(self, **args):
        self.calls.append(("get_object", args))
        body = self.objects[(args["Key"], args["VersionId"])]
        return {"Body": io.BytesIO(body), "ContentLength": len(body), "VersionId": args["VersionId"]}

    def head_object(self, **args):
        self.calls.append(("head_object", args))
        matches = [(version, body) for (key, version), body in self.objects.items() if key == args["Key"] and (not args.get("VersionId") or args["VersionId"] == version)]
        version, body = matches[-1]
        return {"VersionId": version, "ContentLength": len(body)}

    def list_object_versions(self, **args):
        self.calls.append(("list_object_versions", args))
        return {"Versions": [{"Key": key, "VersionId": version, "IsLatest": True}
            for key, version in self.objects if key.startswith(args["Prefix"])], "IsTruncated": False}


class STS:
    def __init__(self, calls, account="111111111111"): self.calls, self.account = calls, account
    def get_caller_identity(self):
        self.calls.append(("get_caller_identity", {}))
        return {"Account": self.account}


class DDB:
    def __init__(self, *, moving=False):
        self.calls, self.reads, self.moving = [], 0, moving
    def get_item(self, **args):
        self.calls.append(("get_item", args)); self.reads += 1
        order = 1 if self.moving and self.reads == 1 else 2
        return {"Item": {"PK": {"S": "AUTHORITY"}, "SK": {"S": "SEQUENCE"}, "order": {"N": str(order)}}}
    def query(self, **args):
        self.calls.append(("query", args))
        pk = args["ExpressionAttributeValues"][":pk"]["S"]
        if not pk.startswith("RUN#"): return {"Items": []}
        task = {"update_id": "update-1", "task_id": "task-1", "issue_order": 1, "start_order": 2}
        return {"Items": [{"PK": {"S": pk}, "SK": {"S": "ISSUE#task-1"}, "task_json": {"S": json.dumps(task)}},
            {"PK": {"S": pk}, "SK": {"S": "TASK#task-1"}, "update_id": {"S": "update-1"}},
            {"PK": {"S": pk}, "SK": {"S": "AUDIT_HEAD"}, "count": {"N": "0"}, "head": {"S": "0" * 64}}]}


def fixture(directory, *, empty_failed=False):
    source = directory / "source"
    source.mkdir()
    raw = persistent_fixture(source)
    app, cell, account, project, region = "synthetic-app", "synthetic-P1-S0", "111111111111", "independent", "us-east-1"
    bucket = "independent-model-bucket"
    objects, artifacts = {}, []
    def put(key, version, content):
        objects[(key, version)] = content
        return {"bucket": bucket, "key": key, "version_id": version, "sha256": digest(content), "size_bytes": len(content)}
    raw.update(cell_id=cell, cloud_campaign_id=app)
    for record in raw["updates"] + raw["published_manifests"]:
        ref = record["artifact"]
        objects[(ref["key"], ref["version_id"])] = Path(ref["local_export"]["path"]).read_bytes()
    raw_bytes = json.dumps(raw).encode()
    raw_ref = put(f"evidence/campaigns/{app}/{cell}/runtime_result.json", "v-raw", raw_bytes)
    campaign = {"campaign_id": app, "cases": [{"cell_id": cell, "runtime": {"persistent_run_id": raw["persistent_run_id"], "table_name": "pcfl-synthetic-state"}},
        {"cell_id": "synthetic-not-indexed", "runtime": {"persistent_run_id": "unfinished-run", "table_name": "pcfl-synthetic-state"}}]}
    campaign_bytes = json.dumps(campaign).encode()
    metadata = put(f"metadata/{app}/campaign.json", "v-meta", campaign_bytes)
    case = {"cell_id": cell, "successful": not empty_failed, "status": "failed" if empty_failed else "completed", "artifacts": [] if empty_failed else [raw_ref]}
    index = {"campaign_id": app, "successful": False, "cases": [case]}
    index_bytes = json.dumps(index).encode()
    key = f"evidence/campaigns/{app}/index-0000.json"
    put(key, "v-index", index_bytes)
    inventory = {"account_id": account, "region": region, "project_id": project,
                 "foundation": {"bucket_name": bucket, "state_table_name": "pcfl-synthetic-state"}, "uploads": [metadata]}
    inventory_path, campaign_path = directory / "inventory.json", directory / "campaign.json"
    inventory_path.write_text(json.dumps(inventory)); campaign_path.write_bytes(campaign_bytes)
    calls = []
    sdk = {"sts": STS(calls, account), "s3": S3(objects, calls)}
    return inventory_path, campaign_path, sdk, calls, app, key, index_bytes


class PartialCloudTests(unittest.TestCase):
    def test_real_array_case_verifies_without_inventing_campaign_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, key, original = fixture(directory)
            before = inv.read_bytes()
            report = collect(inv, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk)
            self.assertTrue(report["cases"][0]["verified"], report["cases"])
            self.assertTrue(report["collection_complete"])
            self.assertFalse(report["successful"])
            self.assertFalse(report["campaign_complete"])
            self.assertEqual(len(report["not_in_source_index"]), 1)
            self.assertEqual((directory / "recovery/source_index.json").read_bytes(), original)
            self.assertEqual(inv.read_bytes(), before)
            self.assertEqual(calls[0][0], "get_caller_identity")
            self.assertTrue(all(name in {"get_caller_identity", "get_object", "head_object"} for name, _ in calls))

    def test_failed_empty_artifact_case_retained_without_synthetic_raw(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, key, _ = fixture(directory, empty_failed=True)
            report = collect(inv, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk)
            self.assertFalse(report["cases"][0]["verified"])
            self.assertEqual(report["cases"][0]["producer_status"], "failed")
            self.assertEqual(list((directory / "recovery").rglob("runtime_result.json")), [])
            self.assertFalse(report["successful"])

    def test_wrong_index_scope_and_wrong_account_reject_before_evidence_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, key, _ = fixture(directory)
            with self.assertRaisesRegex(ValueError, "scope"):
                collect(inv, campaign, application=app, index_key="evidence/other/index-0000.json", output=directory / "bad-scope", clients=sdk)
            self.assertEqual(calls, [])
            sdk["sts"].account = "wrong"
            with self.assertRaises(ValueError):
                collect(inv, campaign, application=app, index_key=key, output=directory / "bad-account", clients=sdk)
            self.assertEqual([name for name, _ in calls], ["get_caller_identity"])

    def test_wrong_index_hash_or_returned_version_rejects(self):
        for mode in ("hash", "version"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                inv, campaign, sdk, calls, app, key, _ = fixture(directory)
                options = {"expected_index_sha256": "0" * 64} if mode == "hash" else {}
                if mode == "version":
                    original = sdk["s3"].get_object
                    def altered(**args):
                        result = original(**args)
                        if args["Key"] == key: result["VersionId"] = "wrong-version"
                        return result
                    sdk["s3"].get_object = altered
                with self.assertRaisesRegex(ValueError, "digest|version"):
                    collect(inv, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk, **options)

    def test_csv_or_other_run_model_never_gets_downloaded(self):
        for mode in ("csv", "other-run"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                inv, campaign, sdk, calls, app, key, _ = fixture(directory)
                index = json.loads(sdk["s3"].objects[(key, "v-index")])
                if mode == "csv":
                    index["cases"][0]["artifacts"].append({"bucket": "independent-model-bucket", "key": f"evidence/campaigns/{app}/synthetic-P1-S0/private.csv", "version_id": "v-csv", "sha256": "a" * 64})
                else:
                    raw_key = index["cases"][0]["artifacts"][0]["key"]
                    body = json.loads(sdk["s3"].objects[(raw_key, "v-raw")])
                    body["updates"][0]["artifact"]["key"] = "models/candidates/other-run/stolen.npz"
                    raw = json.dumps(body).encode()
                    sdk["s3"].objects[(raw_key, "v-raw")] = raw
                    index["cases"][0]["artifacts"][0].update(sha256=digest(raw), size_bytes=len(raw))
                sdk["s3"].objects[(key, "v-index")] = json.dumps(index).encode()
                result = collect(inv, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk)
                self.assertFalse(result["collection_complete"])
                self.assertFalse(result["cases"][0]["verified"])
                self.assertFalse(any(args.get("Key", "").endswith(".csv") or "other-run" in args.get("Key", "") for name, args in calls if name == "get_object"))

    def test_operator_snapshot_retains_indeterminate_counts_and_retries_global_fence(self):
        ddb = DDB(moving=True)
        value = operator_snapshot(ddb, "exact-owned-table", "unfinished-run")
        self.assertEqual(value["fence_attempt"], 2)
        self.assertFalse(value["successful"])
        self.assertFalse(value["producer_runtime_result"])
        self.assertEqual(value["observed_counts"]["assigned_tasks"], 1)
        self.assertEqual(value["observed_counts"]["acknowledged_tasks"], 1)
        self.assertEqual(value["observed_counts"]["indeterminate_tasks"], 1)
        self.assertEqual(value["authority_order"], 2)
        self.assertTrue(all(args["ConsistentRead"] is True for _, args in ddb.calls))
        self.assertTrue(all(args["TableName"] == "exact-owned-table" for _, args in ddb.calls))

    def test_completed_case_cannot_be_relabelled_as_operator_unfinished_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, key, _ = fixture(directory)
            sdk["dynamodb"] = DDB()
            with self.assertRaisesRegex(ValueError, "unfinished"):
                collect(inv, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk, observe_runs=["independent-runtime"])
            self.assertEqual(sdk["dynamodb"].calls, [])
            self.assertTrue(any((directory / "recovery").rglob("operator_case_assessment.json")))

    def test_unfinished_operator_observation_is_separately_typed_and_locally_witnessed(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError:
            self.skipTest("optional-signature-runtime-unavailable")
        from anchor_evidence import verify_witness
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, index_key, _ = fixture(directory, empty_failed=True)
            sdk["dynamodb"] = DDB()
            key = ec.generate_private_key(ec.SECP384R1())
            key_path = directory / "operator.key"
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            pin = digest(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            result = collect(inv, campaign, application=app, index_key=index_key, output=directory / "recovery", clients=sdk,
                observe_runs=["unfinished-run"], witness_key=key_path, witness_pin=pin)
            self.assertFalse(result["successful"])
            observation = result["operator_observations"][0]
            self.assertEqual(observation["kind"], "operator-observed-partial-persistent-state")
            self.assertEqual(observation["observed_counts"]["indeterminate_tasks"], 1)
            witness = json.loads(Path(observation["local_witness"]["path"]).read_text())
            self.assertTrue(verify_witness(witness, public, expected_public_key_sha256=pin))
            self.assertIsNone(witness["payload"]["model_pointer"])
            self.assertEqual(list((directory / "recovery").rglob("runtime_result.json")), [])

    def test_latest_discovery_is_finite_exact_application_prefix_and_keeps_abort_context(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            inv, campaign, sdk, calls, app, key, _ = fixture(directory)
            result = collect(inv, campaign, application=app, index_key=None, output=directory / "recovery", clients=sdk,
                             discover_latest=True, operator_context="operator-controlled-abort-observation")
            self.assertTrue(result["cases"][0]["verified"])
            self.assertFalse(result["successful"])
            self.assertEqual(result["operator_context"], "operator-controlled-abort-observation")
            query = next(args for name, args in calls if name == "list_object_versions")
            self.assertEqual(query["Prefix"], f"evidence/campaigns/{app}/index-")
            self.assertIn("ExpectedBucketOwner", query)
            sdk["s3"].objects[(f"evidence/campaigns/{app}/index-9999.json", "unregistered")] = b"{}"
            with self.assertRaisesRegex(ValueError, "finite"):
                latest_index(sdk["s3"], bucket="independent-model-bucket", account="111111111111", application=app, registered_cases=2)


if __name__ == "__main__":
    unittest.main()
