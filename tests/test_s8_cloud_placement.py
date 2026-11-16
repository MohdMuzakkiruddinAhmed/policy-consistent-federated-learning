"""Real exception-envelope shape; no clinical data or AWS calls."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

STAGE = Path(__file__).resolve().parent
ROOT = next(p for p in STAGE.parents if (p / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests"), str(ROOT / "src")]
import test_cloud_placement as fixtures
SOURCE = STAGE / "validate_cloud_placement.py" if (STAGE / "validate_cloud_placement.py").is_file() else ROOT / "scripts/validate_cloud_placement.py"
spec = importlib.util.spec_from_file_location("s8_placement", SOURCE)
placement = importlib.util.module_from_spec(spec); spec.loader.exec_module(placement)
placement.ROOT = ROOT


class FailedEnvelopePlacementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inventory = fixtures.complete_fixture(self.root)
        self.index_path = self.root / "campaign_result.json"
        self.index = json.loads(self.index_path.read_text())
        self.full = json.loads((self.root / "case-one/runtime_result.json").read_text())
        self.failed = []
        for seed, fault, reason in ((296, "opa_transport_unavailable", "policy_evaluator_unavailable_or_invalid_response"),
                                    (593, "audit_transport_unavailable", "transaction_not_confirmed")):
            cell = f"synthetic-S8-{seed}"
            raw = {"successful": False, "cloud_campaign_id": "campaign-one", "cell_id": cell,
                "scripted_fault": fault, "reason": reason,
                "tasks": [{**task, "round_id": f"round-{round_id}"} for round_id in (1, 2) for task in self.full["tasks"]]}
            self.failed.append((cell, raw))
        self.bind()

    def bind(self):
        self.index["cases"] = self.index["cases"][:1]
        self.inventory["export"]["case_directories"] = {"case-one": str(self.root / "case-one")}
        for cell, raw in self.failed:
            directory = self.root / cell; directory.mkdir(exist_ok=True)
            path = directory / "runtime_result.json"; path.write_text(json.dumps(raw))
            self.index["cases"].append({"cell_id": cell, "successful": False, "artifacts": [{
                "bucket": "test-bucket", "key": f"evidence/campaigns/campaign-one/{cell}/runtime_result.json",
                "version_id": "synthetic-version", "sha256": placement.file_sha256(path), "size_bytes": path.stat().st_size}]})
            self.inventory["export"]["case_directories"][cell] = str(directory)
        self.index["successful"] = False
        self.index_path.write_text(json.dumps(self.index))
        self.inventory["export"].update(index_sha256=placement.file_sha256(self.index_path), cases=3)

    def validate(self): return placement.validate_placement(deepcopy(self.inventory), export_root=self.root)

    def test_two_actual_shaped_S8_exceptions_keep_eight_actor_registry_bindings(self):
        result = self.validate()
        self.assertTrue(result["successful"], result["checks"])
        self.assertTrue(result["checks"]["coordinator_registry_and_actual_learning_bindings"])
        self.assertTrue(result["checks"]["eight_distinct_learning_clients"])
        self.assertTrue(all(raw["successful"] is False and "node_registry" not in raw for _, raw in self.failed))

    def test_missing_registry_is_allowed_only_for_explicit_false_failure(self):
        for value in (True, None, 0, "false"):
            with self.subTest(value=value):
                self.failed[0][1]["successful"] = value; self.bind()
                self.assertFalse(self.validate()["checks"]["coordinator_registry_and_actual_learning_bindings"])
        self.failed[0][1].pop("successful"); self.bind()
        self.assertFalse(self.validate()["checks"]["coordinator_registry_and_actual_learning_bindings"])

    def test_provided_wrong_registry_and_forged_actual_node_or_org_remain_rejected(self):
        for mutation in ("registry", "node", "org", "string-node", "empty-tasks"):
            with self.subTest(mutation=mutation):
                old = deepcopy(self.failed[0][1]); raw = self.failed[0][1]
                if mutation == "registry": raw["node_registry"] = {"999": "org_01"}
                elif mutation == "node": raw["tasks"][0]["node_id"] = 999
                elif mutation == "org": raw["tasks"][0]["org_id"] = "org_08"
                elif mutation == "string-node": raw["tasks"][0]["node_id"] = "1"
                else: raw["tasks"] = []
                self.bind(); self.assertFalse(self.validate()["checks"]["coordinator_registry_and_actual_learning_bindings"])
                self.failed[0] = (self.failed[0][0], old)

    def test_missing_physical_actor_or_index_registry_is_not_relaxed(self):
        self.index["node_registry"].pop("8"); self.bind()
        self.assertFalse(self.validate()["checks"]["coordinator_registry_and_actual_learning_bindings"])
        self.index["node_registry"] = self.full["node_registry"]; self.bind()
        snapshot = self.inventory["learning_placement_snapshots"][0]
        snapshot["tasks"] = [task for task in snapshot["tasks"] if task["name"] != "org_08"]
        snapshot["snapshot_sha256"] = placement.sha({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
        result = self.validate()
        self.assertFalse(result["checks"]["eight_distinct_learning_clients"])
        self.assertFalse(result["successful"])


if __name__ == "__main__": unittest.main()
