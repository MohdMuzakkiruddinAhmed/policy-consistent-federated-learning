import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
from ingest_experiments import retained_export_scope, concurrent_client_ids, case_window


class IngestionScopeTests(unittest.TestCase):
    def test_application_specific_export_is_resolved_without_legacy_path_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inventory = {"campaign_id": "master", "application_campaign_id": "child",
                "export": {"export_root": str(root/"r/childhash"), "application_campaign_id": "child",
                    "index_key": "evidence/campaigns/child/campaign_result.json", "index_version_id": "version-one"}}
            self.assertEqual(retained_export_scope(root/"child-inventory.json", inventory), ("child", (root/"r/childhash").resolve()))
            inventory["export"]["application_campaign_id"] = "other-child"
            with self.assertRaisesRegex(ValueError, "application_or_version"):
                retained_export_scope(root/"inventory.json", inventory)
            inventory["export"]["application_campaign_id"] = "child"
            inventory["export"]["export_root"] = str(root.parent)
            with self.assertRaisesRegex(ValueError, "outside_owned"):
                retained_export_scope(root/"inventory.json", inventory)

    def test_snapshot_ids_preserve_eight_concurrent_clients_despite_replacement_history(self):
        tasks = [{"name": f"org_{i:02d}", "task_arn": f"task-{i}",
            "effective_commands": {f"org_{i:02d}": ["client"]}} for i in range(1,9)]
        placement = {"successful": True, "source_snapshot": {"tasks": tasks}}
        self.assertEqual(len(concurrent_client_ids(placement)), 8)
        # A mixed snapshot with both old and replacement actors is never used.
        placement["source_snapshot"]["tasks"] = tasks+[dict(tasks[0], task_arn="replacement-task")]
        self.assertEqual(concurrent_client_ids(placement), [])
        placement["source_snapshot"]["tasks"] = tasks
        placement["successful"] = False
        self.assertEqual(concurrent_client_ids(placement), [])

    def test_case_wall_clock_is_usage_metadata_and_crosschecked_with_monotonic_duration(self):
        index = {"started_at_utc": "2026-01-01T00:00:00Z", "finished_at_utc": "2026-01-01T01:00:00Z"}
        raw = {"case_started_at_utc": "2026-01-01T00:10:00Z", "case_finished_at_utc": "2026-01-01T00:11:00Z", "elapsed_seconds": 60.01}
        start, end, scope = case_window(raw, index)
        self.assertEqual(start, raw["case_started_at_utc"])
        self.assertIn("usage-only", scope)
        self.assertIn("not-per-case", case_window({}, index)[2])
        raw["elapsed_seconds"] = float("nan")
        with self.assertRaises(ValueError):
            case_window(raw, index)


if __name__ == "__main__":
    unittest.main()
