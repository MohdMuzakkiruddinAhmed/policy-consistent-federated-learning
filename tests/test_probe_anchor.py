"""Mocked fresh-project probe target/custody; never clinical execution evidence."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_anchor as anchor
import cloud_io


class AwsError(Exception):
    def __init__(self, code): self.response = {"Error": {"Code": code}}


def fixture(directory):
    directory = Path(directory)
    inventory = {"account_id": "111111111111", "region": "us-east-1", "project_id": "pcfl-test",
        "campaign_id": "fresh-main", "foundation": {"bucket_name": "pcfl-test-111111111111-us-east-1"},
        "retained_artifact_versions": []}
    path = directory / "inventory.json"
    path.write_text(json.dumps(inventory))
    s3 = Mock()
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "Project", "Value": "pcfl-test"}]}
    body, key, _ = anchor.expected(inventory)
    response = lambda version="v-sentinel", content=body: {"VersionId": version, "ServerSideEncryption": "AES256", "Body": io.BytesIO(content)}
    s3.get_object.side_effect = [AwsError("NoSuchKey"), response()]
    s3.put_object.return_value = {"VersionId": "v-sentinel"}
    runner = SimpleNamespace(inventory=inventory, directory=directory, inventory_path=path,
        sdk=Mock(return_value={"s3": s3}), save=lambda: path.write_text(json.dumps(inventory)))
    return runner, s3, response


class ProbeAnchorTests(unittest.TestCase):
    def test_fresh_versioned_sentinel_is_separate_and_immediately_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, _ = fixture(directory)
            result = anchor.create(runner)
            self.assertTrue(result["probe_only"])
            self.assertFalse(result["model_or_audit_witness"])
            self.assertNotIn("protected_operator_witnesses", runner.inventory)
            self.assertEqual(anchor.select_target(runner.inventory, directory), result["reference"])
            body = json.loads(Path(runner.inventory["operator_probe_sentinels"][0]["local_path"]).read_bytes())
            self.assertFalse(body["model_or_audit_evidence"])
            self.assertNotIn("signature_base64", body)
            self.assertNotIn("run_id", body)
            kwargs = s3.put_object.call_args.kwargs
            self.assertEqual(kwargs["IfNoneMatch"], "*")
            self.assertEqual(kwargs["ExpectedBucketOwner"], runner.inventory["account_id"])
            self.assertEqual(kwargs["ServerSideEncryption"], "AES256")
            self.assertTrue(kwargs["Key"].startswith("anchors/fresh-main/probe/"))
            self.assertEqual(s3.get_object.call_args.kwargs["VersionId"], "v-sentinel")
            self.assertEqual(anchor.custody(runner.inventory, directory)["operator_probe_sentinels_checked"], 1)

    def test_idempotent_resend_verifies_exact_version_without_put(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, response = fixture(directory)
            anchor.create(runner)
            s3.reset_mock(); s3.get_object.side_effect = [response(), response()]
            result = anchor.create(runner)
            self.assertFalse(result["created"])
            s3.put_object.assert_not_called()
            self.assertEqual(len(runner.inventory["retained_artifact_versions"]), 1)

    def test_recorded_version_alone_does_not_prove_current_existing_key(self):
        for current in ("missing", "unknown-version"):
            with self.subTest(current=current), tempfile.TemporaryDirectory() as directory:
                runner, s3, response = fixture(directory); anchor.create(runner)
                s3.put_object.reset_mock()
                s3.get_object.side_effect = [response(), AwsError("NoSuchKey") if current == "missing" else response(version="unrecorded-v2")]
                with self.assertRaises((ValueError, AwsError)): anchor.create(runner)
                s3.put_object.assert_not_called()

    def test_ambiguous_prior_put_recovers_only_exact_deterministic_body(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, response = fixture(directory)
            s3.get_object.side_effect = [response()]
            anchor.create(runner)
            s3.put_object.assert_not_called()
            self.assertEqual(anchor.sentinel_references(runner.inventory, directory)[0]["version_id"], "v-sentinel")

    def test_existing_signed_witness_preference_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, _, _ = fixture(directory)
            anchor.create(runner)
            witness = {"key": "anchors/fresh-main/cell/real.json", "version_id": "v-model", "sha256": "a" * 64}
            runner.inventory["protected_operator_witnesses"] = [witness]
            self.assertEqual(anchor.select_target(runner.inventory, directory), {"bucket": runner.inventory["foundation"]["bucket_name"], **witness})

    def test_owner_versioning_tag_and_remote_body_fail_closed(self):
        for mutation in ("bucket", "versioning", "tag", "body", "version", "encryption", "denied"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                runner, s3, response = fixture(directory)
                if mutation == "bucket": runner.inventory["foundation"]["bucket_name"] = "foreign-bucket"
                if mutation == "versioning": s3.get_bucket_versioning.return_value = {}
                if mutation == "tag": s3.get_bucket_tagging.return_value = {"TagSet": []}
                if mutation == "body": s3.get_object.side_effect = [response(content=b'{"signed":"fake"}')]
                if mutation == "version": s3.get_object.side_effect = [response(version="null")]
                if mutation == "encryption":
                    value = response(); value.pop("ServerSideEncryption"); s3.get_object.side_effect = [value]
                if mutation == "denied": s3.get_object.side_effect = AwsError("AccessDenied")
                with self.assertRaises((ValueError, AwsError)): anchor.create(runner)
                s3.put_object.assert_not_called()
                self.assertNotIn("operator_probe_sentinels", runner.inventory)

    def test_inventory_cas_rejects_parallel_update_after_remote_write(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, response = fixture(directory)
            def changed(**kwargs):
                runner.inventory_path.write_text('{"other":"writer"}')
                return response()
            s3.get_object.side_effect = [AwsError("NoSuchKey"), changed]
            # Mock side_effect list returns callables rather than invoking them.
            counter = iter([False, True])
            def get(**kwargs):
                if not next(counter): raise AwsError("NoSuchKey")
                return changed(**kwargs)
            s3.get_object.side_effect = get
            with self.assertRaisesRegex(ValueError, "no_cas_merge"): anchor.create(runner)
            self.assertEqual(runner.inventory_path.read_text(), '{"other":"writer"}')
            self.assertNotIn("operator_probe_sentinels", runner.inventory)

    def test_inventory_drift_before_operation_stops_before_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, _, _ = fixture(directory)
            runner.inventory_path.write_text('{"another":"writer"}')
            with self.assertRaisesRegex(ValueError, "changed_before_operation"): anchor.create(runner)
            runner.sdk.assert_not_called()

    def test_corrupt_foreign_or_witness_promoted_local_record_is_rejected(self):
        for mutation in ("body", "outside", "version", "scope", "witness", "marker", "unretained"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                runner, _, _ = fixture(directory); anchor.create(runner)
                row = runner.inventory["operator_probe_sentinels"][0]
                if mutation == "body": Path(row["local_path"]).write_text("{}")
                if mutation == "outside": row["local_path"] = str(Path(directory).parent / "foreign.json")
                if mutation == "version": row["version_id"] = "null"
                if mutation == "scope": row["key"] = "anchors/foreign/probe/x.json"
                if mutation == "witness": runner.inventory["protected_operator_witnesses"] = [deepcopy(row)]
                if mutation == "marker": runner.inventory["retained_artifact_versions"][0]["protected_operator_witness"] = True
                if mutation == "unretained": runner.inventory["retained_artifact_versions"] = []
                with self.assertRaises(ValueError): anchor.sentinel_references(runner.inventory, directory)

    def test_purge_receipt_required_separately_from_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, _, _ = fixture(directory); anchor.create(runner)
            with self.assertRaisesRegex(ValueError, "purge_receipt"): anchor.custody(runner.inventory, directory, require_purge=True)
            runner.inventory["removed_operator_probe_sentinel_versions"] = anchor.sentinel_references(runner.inventory, directory)
            self.assertEqual(anchor.custody(runner.inventory, directory, require_purge=True)["operator_probe_sentinels_checked"], 1)
            runner.inventory["removed_operator_probe_sentinel_versions"][0]["version_id"] = "unrelated"
            with self.assertRaises(ValueError): anchor.custody(runner.inventory, directory, require_purge=True)

    def test_collector_reuses_sentinel_exact_version_without_mislabeling_witness(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, _ = fixture(directory); anchor.create(runner)
            s3.reset_mock(); s3.list_object_versions.return_value = {"Versions": []}
            old = runner.inventory["retained_artifact_versions"][0]
            s3.head_object.return_value = {"VersionId": old["version_id"], "ContentLength": old["size_bytes"]}
            result = cloud_io.export_owned_versions(s3, bucket=old["bucket"], account=runner.inventory["account_id"],
                destination=Path(directory) / "r/v", protected_anchors=runner.inventory["operator_probe_sentinels"],
                prior_records=[old], cache_root=directory, anchor_prefix="anchors/fresh-main/")
            self.assertEqual(result, [old]); s3.get_object.assert_not_called()
            self.assertFalse(result[0]["protected_operator_witness"])
            self.assertTrue(result[0]["operator_probe_sentinel"])

    def test_fresh_sentinel_export_has_distinct_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, response = fixture(directory); anchor.create(runner)
            s3.list_object_versions.return_value = {"Versions": []}; s3.get_object.side_effect = [response()]
            result = cloud_io.export_owned_versions(s3, bucket=runner.inventory["foundation"]["bucket_name"], account=runner.inventory["account_id"],
                destination=Path(directory) / "r/v", protected_anchors=runner.inventory["operator_probe_sentinels"], anchor_prefix="anchors/fresh-main/")
            self.assertFalse(result[0]["protected_operator_witness"])
            self.assertTrue(result[0]["operator_probe_sentinel"])

    def test_only_exact_retained_sentinel_version_can_be_purged(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, s3, _ = fixture(directory); anchor.create(runner)
            row = runner.inventory["retained_artifact_versions"][0]
            s3.list_object_versions.return_value = {"Versions": [{"Key": row["key"], "VersionId": row["version_id"]}]}
            s3.delete_objects.return_value = {}
            self.assertEqual(cloud_io.purge_recorded_versions(s3, bucket=row["bucket"], account=runner.inventory["account_id"], project=runner.inventory["project_id"], references=[row]), 1)
            self.assertEqual(s3.delete_objects.call_args.kwargs["Delete"]["Objects"], [{"Key": row["key"], "VersionId": row["version_id"]}])
            for response in ({"Versions": [{"Key": row["key"], "VersionId": "unknown-newer"}]},
                             {"DeleteMarkers": [{"Key": row["key"], "VersionId": "unknown-marker"}]}):
                s3.delete_objects.reset_mock(); s3.list_object_versions.return_value = response
                with self.assertRaises(ValueError): cloud_io.purge_recorded_versions(s3, bucket=row["bucket"], account=runner.inventory["account_id"], project=runner.inventory["project_id"], references=[row])
                s3.delete_objects.assert_not_called()

    def test_probe_only_teardown_custody_needs_no_producer_raw_or_signature(self):
        from validate_campaign_teardown import local_custody
        with tempfile.TemporaryDirectory() as directory:
            runner, _, _ = fixture(directory); anchor.create(runner)
            runner.inventory["teardown_complete"] = True
            with self.assertRaisesRegex(ValueError, "purge_receipt"): local_custody(runner.inventory, Path(directory))
            runner.inventory["removed_operator_probe_sentinel_versions"] = anchor.sentinel_references(runner.inventory, directory)
            result = local_custody(runner.inventory, Path(directory))
            self.assertEqual(result["operator_probe_sentinels_checked"], 1)
            self.assertEqual(result["witnesses_checked"], 0)
            self.assertEqual(result["raw_cases_checked"], 0)

    def test_fresh_placement_recognizes_only_retained_sentinel_and_all_nine_denials(self):
        import validate_cloud_placement as placement
        from test_cloud_placement import complete_fixture
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "results/aws/campaign-one"
            directory.mkdir(parents=True)
            inventory = complete_fixture(directory)
            bucket = f"{inventory['project_id']}-{inventory['account_id']}-{inventory['region']}"
            inventory["foundation"]["bucket_name"] = bucket
            body, key, digest = anchor.expected(inventory)
            path = directory / "operator-probes/sentinel.json"
            path.parent.mkdir(); path.write_bytes(body)
            record = {"kind": anchor.KIND, "bucket": bucket, "key": key, "version_id": "sentinel-v1",
                "sha256": digest, "size_bytes": len(body), "local_path": str(path)}
            inventory["operator_probe_sentinels"] = [record]
            inventory["retained_artifact_versions"] = [{key: value for key, value in record.items() if key != "kind"} |
                {"operator_probe_sentinel": True, "protected_operator_witness": False}]
            reference = anchor.sentinel_references(inventory, directory)[0]
            templates = [*inventory["runtime_plan"]["client_access_probe_templates"], inventory["runtime_plan"]["coordinator_access_probe_template"]]
            for template, row in zip(templates, inventory["client_probe_tasks"]):
                environment = template["overrides"]["containerOverrides"][0]["environment"][0]
                config = json.loads(environment["value"])
                config.update(bucket=bucket, protected_anchor_object=reference)
                environment["value"] = json.dumps(config)
                row["probe_response"]["anchor_write_denied"] = True
                row["probe_log_reference"]["response_sha256"] = hashlib.sha256(json.dumps(row["probe_response"], sort_keys=True).encode()).hexdigest()
            index_path = directory / "campaign_result.json"
            index = json.loads(index_path.read_text())
            index["cases"][0]["artifacts"][0]["bucket"] = bucket
            index_path.write_text(json.dumps(index))
            inventory["export"]["index_sha256"] = cloud_io.file_sha256(index_path)
            with patch.object(placement, "ROOT", root):
                report = placement.validate_placement(inventory, export_root=directory)
                self.assertTrue(report["checks"]["protected_operator_anchor_write_denied"])
                self.assertTrue(report["successful"])
                self.assertEqual(inventory.get("protected_operator_witnesses", []), [])
                missing = deepcopy(inventory); del missing["operator_probe_sentinels"]
                self.assertFalse(placement.validate_placement(missing, export_root=directory)["checks"]["protected_operator_anchor_write_denied"])
                corrupt = deepcopy(inventory); corrupt["operator_probe_sentinels"][0]["version_id"] = "foreign-version"
                self.assertFalse(placement.validate_placement(corrupt, export_root=directory)["checks"]["protected_operator_anchor_write_denied"])
                denied = deepcopy(inventory)
                denied["client_probe_tasks"][0]["probe_response"]["anchor_write_denied"] = False
                self.assertFalse(placement.validate_placement(denied, export_root=directory)["checks"].get("protected_operator_anchor_write_denied", False))


if __name__ == "__main__": unittest.main()
