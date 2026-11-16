"""Synthetic clock/barrier regressions; no clinical data or external services."""
from copy import deepcopy
import json
import unittest

from pcfl.runtime_observer import RuntimeObserver, timed_stage
from pcfl.scenarios import ScenarioSignal, transitions


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class BarrierStore:
    """Wire-shaped conditional signal and exact policy transaction outcomes."""
    def __init__(self, clock, scenario="S4"):
        self.clock, self.control, self.current, self.outcomes = clock, {}, {}, {}
        self.changes = transitions("observer-run", scenario, "after_dispatch", "round-1")
        self.failed_observation_reads, self.omit_intermediate = False, False

    def get_item(self, *, Key, ConsistentRead, **_):
        assert ConsistentRead is True
        pk, sk = Key["PK"]["S"], Key["SK"]["S"]
        if pk == "AUTHORITY":
            if self.failed_observation_reads:
                raise OSError("observer metadata read unavailable")
            return {"Item": deepcopy(self.outcomes.get(sk, {}))}
        if pk.startswith("POLICY#"):
            return {"Item": deepcopy(self.current)}
        return {"Item": deepcopy(self.control)}

    def transact_write_items(self, **request):
        if self.control:
            raise RuntimeError("conditional signal already exists")
        self.control = deepcopy(request["TransactItems"][0]["Put"]["Item"])
        self.clock.advance(.010)
        for index, change in enumerate(self.changes):
            # Deliberate gaps: intermediate event order cannot be inferred as final-1.
            event = {**change, "order": 41 + 9 * index, "epoch": 2 + index}
            self.current = {"event_json": {"S": json.dumps(event)}}
            if not (self.omit_intermediate and index == 0):
                self.outcomes["TXN#" + event["event_id"]] = {"result_json": {"S": json.dumps({"event": event})}}
        self.clock.advance(.020)
        return {}


class RuntimeObserverTests(unittest.TestCase):
    def test_new_revoke_regrant_uses_exact_transactions_and_replay_is_unbracketed(self):
        clock = Clock()
        observer = RuntimeObserver("observer-run", clock=clock)
        store = BarrierStore(clock)
        signal = ScenarioSignal(store, "table", "observer-run", "S4", observer=observer)
        signal.reach("after_dispatch", "round-1")
        windows = observer.export()["policy_windows"]
        self.assertEqual([item["order"] for item in windows], [41, 50])
        self.assertEqual([item["kind"] for item in windows], ["REVOKE", "GRANT"])
        self.assertTrue(all(item["status"] == "bracketed-new-commit" for item in windows))
        self.assertAlmostEqual(windows[0]["signal_start_ms"], 0)
        self.assertAlmostEqual(windows[0]["observed_end_ms"], 30)
        signal.reach("after_dispatch", "round-1")
        replay = observer.export()["policy_windows"][2:]
        self.assertEqual(len(replay), 2)
        self.assertTrue(all(item["status"] == "preexisting-or-replayed" and
                            item["signal_start_ms"] is None and item["observed_end_ms"] is None for item in replay))

    def test_observer_read_outage_does_not_change_barrier_but_cannot_claim_commit_bracket(self):
        clock = Clock()
        observer = RuntimeObserver("observer-run", clock=clock)
        store = BarrierStore(clock, "S2")
        store.failed_observation_reads = True
        ScenarioSignal(store, "table", "observer-run", "S2", observer=observer).reach("after_dispatch", "round-1")
        result = observer.export()
        self.assertEqual(result["policy_windows"][0]["status"], "preexisting-or-replayed")
        self.assertIsNone(result["policy_windows"][0]["signal_start_ms"])
        self.assertEqual(result["errors"][0]["source"], "policy-window-before")
        self.assertEqual(len(store.outcomes), 1)

    def test_missing_intermediate_outcome_is_missing_and_never_guessed(self):
        clock = Clock()
        observer = RuntimeObserver("observer-run", clock=clock)
        store = BarrierStore(clock)
        store.omit_intermediate = True
        ScenarioSignal(store, "table", "observer-run", "S4", observer=observer).reach("after_dispatch", "round-1")
        result = observer.export()
        self.assertEqual([item["kind"] for item in result["policy_windows"]], ["GRANT"])
        self.assertEqual(result["errors"][0]["event_id"], store.changes[0]["event_id"])

    def test_actual_return_exception_and_error_run_end_are_preserved_without_secret_payload(self):
        clock = Clock()
        observer = RuntimeObserver("observer-run", clock=clock)
        def receive():
            clock.advance(.025)
            return "rejected"
        result = observer.call("receive", receive, round_id="round-1", org_id="org_01", task_id="task", update_id="update")
        self.assertEqual(result, "rejected")
        with self.assertRaises(OSError), timed_stage(observer, "publication", round_id="round-1"):
            observer.call("publish", lambda: (_ for _ in ()).throw(OSError("storage")), round_id="round-1")
        observer.close(status="error")
        raw = observer.export()
        self.assertEqual([item["sequence"] for item in raw["operations"]], [1, 2])
        self.assertEqual([item["outcome"] for item in raw["operations"]], ["rejected", "exception"])
        self.assertAlmostEqual(raw["operations"][0]["end_ms"] - raw["operations"][0]["start_ms"], 25)
        self.assertEqual([(item["name"], item["status"]) for item in raw["stages"]], [("publication", "error"), ("run", "error")])
        raw["operations"][0]["outcome"] = "forged"
        self.assertEqual(observer.export()["operations"][0]["outcome"], "rejected")

    def test_description_failure_is_missing_observation_and_leaves_real_call_return_unchanged(self):
        observer = RuntimeObserver("observer-run", clock=Clock())
        actual = {"nonce": "must-not-export"}
        result = observer.call("issue", lambda: actual, round_id="round-1",
            describe=lambda _: (_ for _ in ()).throw(KeyError("missing metadata")))
        self.assertIs(result, actual)
        raw = observer.export()
        self.assertEqual(raw["operations"], [])
        self.assertEqual(raw["errors"][0]["source"], "operation-description")
        self.assertNotIn("must-not-export", json.dumps(raw))
