import os
from pathlib import Path
import sys
import tempfile
import unittest

from pcfl.scenarios import ScenarioSignal, ScenarioWatcher, transitions
from pcfl.runtime_observer import RuntimeObserver


class ScenarioContractTests(unittest.TestCase):
    def test_regrant_preserves_original_revoke_and_deterministic_request_identity(self):
        actions = transitions("run-01", "S4", "after_dispatch", "round-1")
        self.assertEqual([item["kind"] for item in actions], ["REVOKE", "GRANT"])
        self.assertNotEqual(actions[0]["event_id"], actions[1]["event_id"])
        self.assertEqual(actions, transitions("run-01", "S4", "after_dispatch", "round-1"))
        self.assertEqual(transitions("run-01", "S4", "after_dispatch", "round-2"), [])

    def test_purpose_change_retains_other_purpose_but_removes_authorized_purpose(self):
        change, = transitions("run-01", "S5", "after_dispatch", "round-1", policy_action="CHANGE")
        self.assertEqual(change["kind"], "CHANGE")
        self.assertEqual({item["purpose"] for item in change["rules"]}, {"unrelated_research"})

    def test_schedule_rejects_duplicate_run_identity_and_noninteger_rounds(self):
        valid = {"run_id": "run-01", "scenario_id": "S0", "rounds": 2}
        with self.assertRaises(ValueError):
            ScenarioWatcher(None, {"runs": [valid, valid]})
        with self.assertRaises(ValueError):
            ScenarioWatcher(None, {"runs": [{**valid, "rounds": True}]})


@unittest.skipUnless(os.environ.get("PCFL_LOCAL_INTEGRATION") == "1", "explicit local service integration")
class ScenarioActorIntegrationTests(unittest.TestCase):
    def test_separate_writer_controls_all_main_barriers_and_replays_without_new_epochs(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from integration_services import LocalIntegrationServices
        from pcfl.governance_service import PolicyWriter
        from pcfl.oracle import evaluate_interval
        with tempfile.TemporaryDirectory() as directory, LocalIntegrationServices(directory) as services:
            writer = PolicyWriter(services.ddb, services.table)
            writer.initialize()
            campaign = {"runs": [{"run_id": f"scenario-{i}", "scenario_id": f"S{i}", "rounds": 2} for i in range(7)]}
            watcher = ScenarioWatcher(writer, campaign).start()
            try:
                for run in campaign["runs"]:
                    observer = RuntimeObserver(run["run_id"])
                    signal = ScenarioSignal(services.ddb, services.table, run["run_id"], run["scenario_id"], timeout=5,
                                            observer=observer)
                    signal.reach("before_run")
                    before = writer.item("AUTHORITY", "SEQUENCE")["order"]
                    signal.reach("before_run")
                    self.assertEqual(writer.item("AUTHORITY", "SEQUENCE")["order"], before)
                    for number in (1, 2):
                        for phase in ("before_round", "after_dispatch", "before_commit"):
                            signal.reach(phase, f"round-{number}")
                    tail = writer.item("POLICY#org_01", "CURRENT")
                    expected = "GRANT" if run["scenario_id"] in {"S0", "S4"} else "EXPIRE" if run["scenario_id"] == "S5" else "REVOKE"
                    import json
                    self.assertEqual(json.loads(tail["event_json"])["kind"], expected)
                    observed = observer.export()
                    self.assertEqual(observed["errors"], [])
                    replayed = [item for item in observed["policy_windows"] if item["status"] == "preexisting-or-replayed"]
                    self.assertEqual(len(replayed), 8)
                    for window in observed["policy_windows"]:
                        actual = json.loads(writer.item("AUTHORITY", "TXN#" + window["event_id"])["result_json"])["event"]
                        self.assertTrue(all(window[key] == actual[key] for key in ("event_id", "org_id", "kind", "order", "epoch")))
                        if window["status"] == "bracketed-new-commit":
                            self.assertLessEqual(window["signal_start_ms"], window["observed_end_ms"])
                self.assertIsNone(watcher.error)
            finally:
                watcher.stop()


if __name__ == "__main__":
    unittest.main()
