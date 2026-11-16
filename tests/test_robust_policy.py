"""Policy barrier integrity/error boundaries; real SDK happy paths are separate."""
import json
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from pcfl.robustness import DEFAULTS, PROTOCOL
from pcfl.robust_policy import RobustScenarioSignal, RobustScenarioWatcher


class PolicyBarrierBoundaryTests(unittest.TestCase):
    def test_rebound_control_item_is_rejected_without_mutating_any_policy(self):
        ddb = SimpleNamespace(get_item=Mock(return_value={"Item": {"protocol_digest": {"S": "wrong-schedule"}}}))
        writer = SimpleNamespace(ddb=ddb, table="synthetic-table", mutate=Mock())
        watcher = RobustScenarioWatcher(writer, {"protocol_id": PROTOCOL,
            "runs": [{"run_id": "synthetic-run", "seed": 296, "rounds": 5, "factors": DEFAULTS}]}).start()
        try:
            watcher.thread.join(timeout=1)
            self.assertFalse(watcher.thread.is_alive())
            self.assertEqual(watcher.error, "ValueError")
            writer.mutate.assert_not_called()
        finally: watcher.stop()

    def test_marker_write_success_never_substitutes_for_actual_committed_policy(self):
        ddb = SimpleNamespace(transact_write_items=Mock(return_value={}), get_item=Mock(return_value={}))
        signal = RobustScenarioSignal(ddb, "synthetic-table", "synthetic-run", "robustness", value=DEFAULTS,
            seed=296, rounds=5, timeout=.02)
        with self.assertRaises(TimeoutError): signal.reach("before_run")
        ddb.transact_write_items.assert_called_once()
        self.assertTrue(all(call.kwargs.get("ConsistentRead") is True for call in ddb.get_item.call_args_list))

    def test_failed_marker_write_cannot_recover_from_different_durable_binding(self):
        ddb = SimpleNamespace(transact_write_items=Mock(side_effect=RuntimeError("synthetic-connection-failure")),
            get_item=Mock(return_value={"Item": {"ready": {"BOOL": True}}}))
        signal = RobustScenarioSignal(ddb, "synthetic-table", "synthetic-run", "robustness", value=DEFAULTS, seed=296, rounds=5)
        with self.assertRaisesRegex(RuntimeError, "connection-failure"): signal.reach("before_run")


if __name__ == "__main__": unittest.main()
