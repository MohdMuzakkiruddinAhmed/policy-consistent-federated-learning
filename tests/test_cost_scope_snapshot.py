"""Synthetic cost-scope persistence tests; no AWS, approval or clinical rows."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(path for path in STAGE.parents if (path / "pyproject.toml").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(STAGE))
import cost_scope_snapshot as snapshot
COST_SOURCE = STAGE / "reconcile_campaign_cost.py" if (STAGE / "reconcile_campaign_cost.py").is_file() else ROOT / "scripts/reconcile_campaign_cost.py"
spec = importlib.util.spec_from_file_location("snapshot_cost", COST_SOURCE)
cost = importlib.util.module_from_spec(spec); spec.loader.exec_module(cost)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class CostScopeSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.approval = {"approved": True, "source": "user-conversation", "authorization_scope": "remaining-phases-cloud-campaign-including-replication",
            "account_id": "123456789012", "region": "us-east-1", "approved_total_usd": 20,
            "max_cumulative_fleet_hours": 32, "max_vcpu": 4, "max_memory_gib": 14, "per_deployment_max_hours": 24}
        self.auth_path = self.root / "authorization.json"; write(self.auth_path, self.approval)
        self.auth = {"path": str(self.auth_path), "sha256": snapshot.sha(self.auth_path)}
        self.request = {"schema_version": "0.1.0", "account_id": self.approval["account_id"], "region": "us-east-1",
            "project_id": "pcfl-current", "campaign_id": "campaign-current", "namespace": "synthetic.local",
            "foundation_vars": "unopened.json", "runtime_vars": "unopened.json", "local_image_tag": "synthetic:not-run",
            "authorization": self.auth, "data_uploads": [], "secrets": []}
        self.request_path = self.root / "request.json"; write(self.request_path, self.request)
        self.ledger = {"authorization_sha256": self.auth["sha256"],
            "tasks": {"old-task": {"campaign_id": "campaign-older", "vcpu_hours": 2, "gib_hours": 8, "last_status": "STOPPED"},
                "new-task": {"campaign_id": "campaign-current", "vcpu_hours": .5, "gib_hours": 2, "last_status": "STOPPED"}},
            "deployments": {"older": {"campaign_id": "campaign-older"}, "current": {"campaign_id": "campaign-current"}}}
        self.ledger_path = self.root / "results/aws" / ("budget-ledger-" + self.auth["sha256"] + ".json")
        write(self.ledger_path, self.ledger)
        self.inventory_paths = []
        for campaign, task in (("campaign-older", "old-task"), ("campaign-current", "new-task")):
            path = self.root / "results/aws" / campaign / "inventory.json"
            write(path, {"account_id": self.request["account_id"], "region": "us-east-1", "campaign_id": campaign,
                "project_id": "pcfl-current" if campaign == "campaign-current" else "pcfl-older", "task_arns": [task],
                "source_marker": "immutable-copy-test"})
            self.inventory_paths.append(path)

    def tearDown(self): self.temp.cleanup()

    def create(self):
        return snapshot.create(self.request_path, self.root / "retained/scope-01", root=self.root, loader=cost.load_scope)

    def frozen_path(self, receipt): return self.root / receipt["request"]["path"]

    def test_replay_keeps_original_ledger_inventories_and_request_after_live_source_mutates(self):
        before = {path: path.read_bytes() for path in [self.request_path, self.ledger_path, *self.inventory_paths]}
        receipt = self.create()
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        frozen_path = self.frozen_path(receipt)
        original = cost.load_scope(frozen_path, root=self.root)
        self.request["application_campaign_id"] = "campaign-later-primary"
        write(self.request_path, self.request)
        self.ledger["tasks"]["new-task"]["vcpu_hours"] = 99
        write(self.ledger_path, self.ledger)
        for path in self.inventory_paths: write(path, {"corrupted-live-copy": True})
        repeated = cost.load_scope(frozen_path, root=self.root)
        self.assertEqual(original, repeated)
        self.assertEqual(repeated[2]["tasks"]["new-task"]["vcpu_hours"], .5)
        self.assertEqual(set(repeated[3]), {"campaign-current", "campaign-older"})
        retained_paths = {Path(value["path"]).name for value in repeated[4]}
        self.assertNotIn(self.ledger_path.name, retained_paths)
        self.assertFalse(any(Path(value["path"]).resolve() == self.request_path for value in repeated[4]))

    def test_only_nonexecutable_envelope_retains_exact_original_request_bytes(self):
        original = self.request_path.read_bytes()
        receipt = self.create()
        manifest, _ = snapshot.read_bound(receipt["manifest"], self.root)
        envelope, _ = snapshot.read_bound(manifest["source_request_envelope"], self.root)
        import base64
        self.assertEqual(base64.b64decode(envelope["original_request_bytes_base64"]), original)
        self.assertEqual(envelope["cost_scope_snapshot"], True)
        frozen = json.loads(self.frozen_path(receipt).read_bytes())
        self.assertEqual(frozen["kind"], snapshot.KIND)
        self.assertTrue(frozen["cost_scope_snapshot"]["execution_disabled"])
        self.assertNotIn("request", manifest)  # no manifest/request hash cycle

    def test_scope_field_rebinding_even_with_same_manifest_is_rejected(self):
        receipt = self.create(); path = self.frozen_path(receipt)
        changed = json.loads(path.read_bytes()); changed["namespace"] = "forged.local"
        write(path, changed)
        with self.assertRaisesRegex(ValueError, "original_scope_fields"):
            cost.load_scope(path, root=self.root)

    def test_missing_campaign_or_changed_ledger_bytes_cannot_replay(self):
        receipt = self.create(); path = self.frozen_path(receipt)
        manifest, _ = snapshot.read_bound(receipt["manifest"], self.root)
        ledger_path = self.root / manifest["ledger"]["path"]
        write(ledger_path, {"authorization_sha256": self.auth["sha256"], "tasks": {}, "deployments": {}})
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            cost.load_scope(path, root=self.root)

    def test_coherently_rehashed_manifest_still_requires_entire_campaign_union(self):
        receipt = self.create(); path = self.frozen_path(receipt)
        manifest, manifest_path = snapshot.read_bound(receipt["manifest"], self.root)
        manifest["inventories"].pop(); write(manifest_path, manifest)
        frozen = json.loads(path.read_bytes()); frozen["cost_scope_snapshot"]["manifest"] = snapshot.reference(manifest_path, self.root)
        write(path, frozen)
        with self.assertRaisesRegex(ValueError, "campaign_union"):
            cost.load_scope(path, root=self.root)

    def test_malformed_marker_never_falls_back_to_live_ledger(self):
        for marker in (False, None, {}, {"execution_disabled": False}):
            changed = deepcopy(self.request); changed["cost_scope_snapshot"] = marker
            write(self.root / "malformed.json", changed)
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, "nonexecutable"):
                cost.load_scope(self.root / "malformed.json", root=self.root)

    def test_outside_paths_and_source_junctions_are_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "owned_cost_snapshot"):
            snapshot.create(self.request_path, self.root.parent / "outside", root=self.root, loader=cost.load_scope)
        receipt = self.create()
        manifest, manifest_path = snapshot.read_bound(receipt["manifest"], self.root)
        with patch.object(Path, "is_symlink", return_value=True), self.assertRaisesRegex(ValueError, "linked"):
            snapshot.read_bound(receipt["manifest"], self.root)

    def test_source_change_during_copy_never_publishes_a_frozen_request(self):
        original = snapshot.read_bound
        calls = 0
        def changing(value, root):
            nonlocal calls
            result = original(value, root); calls += 1
            if calls == 1:
                altered = deepcopy(self.ledger); altered["tasks"]["new-task"]["vcpu_hours"] = 3
                write(self.ledger_path, altered)
            return result
        with patch.object(snapshot, "read_bound", side_effect=changing), self.assertRaises(ValueError):
            self.create()
        self.assertFalse((self.root / "retained/scope-01/request.json").exists())

    def test_existing_output_and_snapshot_of_snapshot_are_rejected(self):
        receipt = self.create()
        with self.assertRaisesRegex(ValueError, "new_cost_snapshot"):
            self.create()
        with self.assertRaisesRegex(ValueError, "original_live_scope"):
            snapshot.create(self.frozen_path(receipt), self.root / "retained/scope-02", root=self.root, loader=cost.load_scope)


if __name__ == "__main__": unittest.main()
