"""Guarded local custody adoption with mocked read-only AWS clients."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from register_recovery_custody import adopt
from cloud_io import file_sha256
from collect_partial_cloud import collect
from test_partial_cloud import fixture, STS


class ECS:
    def __init__(self): self.active, self.calls = False, []
    def list_tasks(self, **args):
        self.calls.append(("list_tasks", args))
        return {"taskArns": ["unexpected-active"] if self.active else []}
    def describe_tasks(self, **args):
        self.calls.append(("describe_tasks", args))
        return {"tasks": [{"taskArn": arn, "lastStatus": "STOPPED"} for arn in args["tasks"]]}
    def describe_services(self, **args):
        self.calls.append(("describe_services", args))
        return {"services": [{"serviceArn": arn, "desiredCount": 0, "runningCount": 0, "pendingCount": 0} for arn in args["services"]]}


def setup(directory):
    path, campaign, sdk, calls, app, key, _ = fixture(directory)
    collect(path, campaign, application=app, index_key=key, output=directory / "recovery", clients=sdk)
    inv = json.loads(path.read_text())
    inv.update(campaign_id="synthetic-master", untouched={"preserve": True}, retained_artifact_versions=[])
    cluster = "arn:aws:ecs:us-east-1:111111111111:cluster/independent-runtime"
    inv["runtime_contract"] = {"cluster_arn": cluster, "service_names": {"opa": "independent-opa"}}
    inv["task_arns"] = [cluster.replace(":cluster/", ":task/") + "/stopped-task"]
    path.write_text(json.dumps(inv))
    sdk["ecs"] = ECS()
    return path, directory / "recovery/recovery_report.json", sdk


class RecoveryCustodyTests(unittest.TestCase):
    def test_known_versions_copied_inside_campaign_partial_status_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path, report, sdk = setup(directory)
            original, source = json.loads(path.read_text()), report.read_bytes()
            receipt = adopt(path, report, sdk, expected_inventory_sha256=file_sha256(path))
            updated = json.loads(path.read_text())
            self.assertTrue(receipt["successful"])
            self.assertEqual(updated["untouched"], original["untouched"])
            self.assertEqual(report.read_bytes(), source)
            record = updated["operator_recoveries"][0]
            self.assertFalse(record["campaign_successful"])
            self.assertFalse(record["orphan_discovery_complete"])
            self.assertEqual(record["verified_completed_cases"], 1)
            self.assertNotIn("export", updated)
            self.assertTrue(all(Path(row["local_path"]).resolve().is_relative_to(directory.resolve() / "r") for row in updated["retained_artifact_versions"]))

    def test_active_compute_or_wrong_account_prevents_master_update(self):
        for condition in ("active", "account"):
            with tempfile.TemporaryDirectory() as temp:
                path, report, sdk = setup(Path(temp)); before = path.read_bytes()
                if condition == "active": sdk["ecs"].active = True
                else: sdk["sts"].account = "222222222222"
                with self.assertRaises(ValueError): adopt(path, report, sdk, expected_inventory_sha256=file_sha256(path))
                self.assertEqual(path.read_bytes(), before)

    def test_CAS_does_not_overwrite_a_late_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            path, report, sdk = setup(Path(temp))
            def writer():
                value = json.loads(path.read_text()); value["external_writer"] = True
                path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "CAS"):
                adopt(path, report, sdk, expected_inventory_sha256=file_sha256(path), before_commit=writer)
            value = json.loads(path.read_text())
            self.assertTrue(value["external_writer"])
            self.assertNotIn("operator_recoveries", value)

    def test_changed_source_version_prevents_master_update(self):
        with tempfile.TemporaryDirectory() as temp:
            path, report, sdk = setup(Path(temp)); before = path.read_bytes()
            value = json.loads(report.read_text())
            source = Path(value["retained_versions"][0]["local_path"])
            source.write_bytes(source.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "source_bytes"):
                adopt(path, report, sdk, expected_inventory_sha256=file_sha256(path))
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__": unittest.main()
