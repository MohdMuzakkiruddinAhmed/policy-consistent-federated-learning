"""Offline checks of the bounded cloud-smoke adapter's trust boundaries."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import aws_smoke
from aws_smoke import CloudSmoke
from pcfl.contracts import ACTIONS, canonical, digest


def policy_records(org, order):
    event = {"event_id": f"grant-{org}", "org_id": org, "order": order, "epoch": 1,
             "kind": "GRANT", "rules": [{"purpose": "readmission", "action": action,
                                           "effect": "allow"} for action in ACTIONS]}
    return [{"SK": "CURRENT", "epoch": 1, "policy_hash": digest(event)},
            {"SK": f"EVENT#{order:020d}", "event_json": json.dumps(event)}]


def offline_snapshot_model(pending_count=1):
    cloud = CloudSmoke.__new__(CloudSmoke)
    cloud.run_id, cloud.round_id = "offline-test", "round-1"
    cloud.order = Mock(return_value=4)
    partitions = {
        "POLICY#org_01": policy_records("org_01", 1),
        "POLICY#org_02": policy_records("org_02", 2),
        "RUN#offline-test": [
            {"SK": "POINTER"}, {"SK": "ROUND#round-1", "pending_count": pending_count, "generation": 1},
            {"SK": "UPDATE#update-1", "status": "pending", "org_id": "org_01"},
        ],
    }
    cloud.query = Mock(side_effect=lambda pk: partitions[pk])
    return cloud, partitions


class CloudSmokeAdapterTests(unittest.TestCase):
    def candidate_fixture(self):
        cloud, partitions = offline_snapshot_model()
        pending = partitions["RUN#offline-test"][-1]
        pending.update({"update_id": "update-1", "task_id": "task-1", "purpose": "readmission",
                        "start_order": 3, "sample_count": 10, "weights_digest": digest([1.0, 3.0])})
        cloud.stage = Mock(side_effect=AssertionError("must_not_stage_invalid_update"))
        return cloud, cloud.snapshot()

    def test_snapshot_returns_complete_stable_pending_membership(self):
        cloud, _ = offline_snapshot_model()
        snapshot = cloud.snapshot()
        self.assertEqual(snapshot["order"], 4)
        self.assertEqual(snapshot["epochs"], {"org_01": 1, "org_02": 1})
        self.assertEqual(len(snapshot["pending"]), 1)
        self.assertEqual(cloud.order.call_count, 2)
        self.assertEqual(cloud.query.call_count, 3)

    def test_snapshot_rejects_history_tail_missing_from_authoritative_current(self):
        cloud, partitions = offline_snapshot_model()
        partitions["POLICY#org_01"][0]["epoch"] = 2
        with self.assertRaisesRegex(ValueError, "incomplete_authoritative_history"):
            cloud.snapshot()

    def test_snapshot_rejects_wrong_tail_hash_even_with_matching_epoch(self):
        cloud, partitions = offline_snapshot_model()
        partitions["POLICY#org_01"][0]["policy_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "incomplete_authoritative_history"):
            cloud.snapshot()

    def test_snapshot_rejects_partial_pending_query(self):
        cloud, _ = offline_snapshot_model(pending_count=2)
        with self.assertRaisesRegex(ValueError, "pending_membership_incomplete"):
            cloud.snapshot()

    def test_snapshot_retries_incoherent_read_and_bounds_retry_exhaustion(self):
        cloud, _ = offline_snapshot_model()
        cloud.order = Mock(side_effect=[4, 5, 5, 5])
        self.assertEqual(cloud.snapshot()["order"], 5)
        self.assertEqual(cloud.query.call_count, 6)
        cloud, _ = offline_snapshot_model()
        cloud.order = Mock(side_effect=[4, 5, 6, 7, 8, 9])
        with self.assertRaisesRegex(RuntimeError, "coherent_snapshot_retry_exhausted"):
            cloud.snapshot()

    def test_stage_checks_fetched_version_bytes_and_bucket_owner_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            cloud = CloudSmoke.__new__(CloudSmoke)
            cloud.directory = Path(temporary)
            cloud.run_id, cloud.bucket, cloud.account = "offline-test", "synthetic-bucket", "123456789012"
            cloud.objects = []
            body = canonical([1.0, 2.0])
            calls = []

            def fake_call(args, request=None):
                calls.append(args)
                if args[1] == "put-object":
                    return {"VersionId": "synthetic-version"}
                if args[1] == "head-object":
                    return {"ContentLength": len(body), "VersionId": "synthetic-version"}
                if args[1] == "get-object":
                    Path(args[-1]).write_bytes(b"modified-synthetic-bytes")
                    return {}
                raise AssertionError("unexpected_aws_call")

            cloud.call = Mock(side_effect=fake_call)
            with self.assertRaisesRegex(ValueError, "staged_object_confirmation_failed"):
                cloud.stage([1.0, 2.0])
            self.assertEqual(len(calls), 3)
            for args in calls:
                self.assertEqual(args[args.index("--expected-bucket-owner") + 1], cloud.account)
            for args in calls[1:]:
                self.assertEqual(args[args.index("--version-id") + 1], "synthetic-version")

    def test_candidate_rejects_changed_update_payload_before_any_s3_stage(self):
        cloud, snapshot = self.candidate_fixture()
        with self.assertRaisesRegex(ValueError, "update_payload_digest_shape_or_finiteness_mismatch"):
            cloud.candidate(snapshot, {"update-1": [9.0, 3.0]})
        cloud.stage.assert_not_called()

    def test_candidate_rejects_invalid_shape_and_nonfinite_before_any_s3_stage(self):
        for bad in ([1.0], [1.0, 2.0, 3.0], [float("nan"), 3.0], [float("inf"), 3.0], [True, 3.0], "invalid"):
            with self.subTest(payload=repr(bad)):
                cloud, snapshot = self.candidate_fixture()
                with self.assertRaisesRegex(ValueError, "update_payload_digest_shape_or_finiteness_mismatch"):
                    cloud.candidate(snapshot, {"update-1": bad})
                cloud.stage.assert_not_called()

    def test_execution_and_cleanup_trace_files_cannot_overwrite_each_other(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            source_names = ("scripts/aws_smoke.py", "src/pcfl/aws_transactions.py", "src/pcfl/contracts.py",
                            "src/pcfl/reference.py", "src/pcfl/oracle.py", "src/pcfl/verifier.py")
            for name in source_names:
                path = temporary_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# synthetic source fixture\n", encoding="utf-8")
            response = Mock(returncode=0, stdout="{}", stderr="")
            with patch.object(aws_smoke, "ROOT", temporary_root), patch.object(aws_smoke.subprocess, "run", return_value=response):
                account, region = "123456789012", "us-east-1"
                args = ("offline-aws", account, region, f"pcfl-research-{account}-{region}", "pcfl-research-state", "offline-test")
                execution = CloudSmoke(*args, trace_phase="execution")
                cleanup = CloudSmoke(*args, trace_phase="cleanup")
                execution.call(["dynamodb", "get-item"], {"fixture": "retained-execution"})
                cleanup.call(["dynamodb", "get-item"], {"fixture": "cleanup"})
            self.assertNotEqual(execution.directory, cleanup.directory)
            self.assertEqual(execution.directory.parent, cleanup.directory.parent)
            self.assertEqual(json.loads((execution.directory / "request-001.json").read_text(encoding="utf-8")),
                             {"fixture": "retained-execution"})
            self.assertEqual(json.loads((cleanup.directory / "request-001.json").read_text(encoding="utf-8")),
                             {"fixture": "cleanup"})


if __name__ == "__main__":
    unittest.main()
