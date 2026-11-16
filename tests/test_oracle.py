"""Golden traces and malformed-input checks for the independent oracle."""

import copy
import json
from pathlib import Path
import unittest

from pcfl.oracle import evaluate_interval


ROOT = Path(__file__).resolve().parents[1]


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = json.loads(
            (ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8")
        )
        self.stable = self.scenarios[0]

    def test_golden_traces(self):
        for trace in self.scenarios:
            with self.subTest(trace=trace["id"]):
                result = evaluate_interval(trace["events"], trace["query"])
                self.assertEqual(result["valid"], trace["expected_valid"])

    def test_delivery_order_does_not_change_authority_order(self):
        trace = next(item for item in self.scenarios if item["id"] == "revoke_regrant")
        self.assertEqual(
            evaluate_interval(list(reversed(trace["events"])), trace["query"]),
            evaluate_interval(trace["events"], trace["query"]),
        )

    def test_duplicate_ids_and_orders_fail_closed(self):
        for field in ("event_id", "order"):
            events = copy.deepcopy(self.stable["events"])
            extra = copy.deepcopy(events[0])
            extra.update(event_id="duplicate", order=4, epoch=2)
            extra[field] = events[0][field]
            events.append(extra)
            with self.subTest(field=field):
                self.assertFalse(evaluate_interval(events, self.stable["query"])["valid"])

    def test_epoch_gap_or_missing_initial_epoch_fails_closed(self):
        for epoch in (0, 2, True, "1"):
            events = copy.deepcopy(self.stable["events"])
            events[0]["epoch"] = epoch
            with self.subTest(epoch=epoch):
                self.assertFalse(evaluate_interval(events, self.stable["query"])["valid"])

    def test_absent_history_fails_closed(self):
        result = evaluate_interval([], self.stable["query"])
        self.assertEqual(result["reason"], "missing_start_policy")

    def test_only_eight_fictional_organizations_are_recognized(self):
        for organization in ("org_00", "org_09", "org_99", "hospital_01", " org_01"):
            trace = copy.deepcopy(self.stable)
            trace["events"][0]["org_id"] = organization
            trace["query"]["org_id"] = organization
            with self.subTest(organization=organization):
                self.assertFalse(evaluate_interval(trace["events"], trace["query"])["valid"])

    def test_unknown_organization_in_history_fails_closed(self):
        events = copy.deepcopy(self.stable["events"])
        events[0]["org_id"] = "org_99"
        self.assertFalse(evaluate_interval(events, self.stable["query"])["valid"])

    def test_future_payload_does_not_change_past_publication(self):
        events = copy.deepcopy(self.stable["events"])
        events.append({"order": self.stable["query"]["commit_order"] + 1, "kind": None})
        self.assertTrue(evaluate_interval(events, self.stable["query"])["valid"])

    def test_unknown_event_order_fails_closed(self):
        for order in (None, True, 0, -1, "9"):
            with self.subTest(order=order):
                self.assertFalse(
                    evaluate_interval([{"order": order}], self.stable["query"])["valid"]
                )

    def test_malformed_payloads_fail_closed_without_raising(self):
        event = self.stable["events"][0]
        mutations = [
            {"org_id": ""},
            {"event_id": []},
            {"event_id": "   "},
            {"kind": []},
            {"kind": "UNKNOWN"},
            {"rules": None},
            {"rules": [{}]},
            {"rules": [{"purpose": "readmission", "action": [], "effect": "allow"}]},
            {"rules": [{"purpose": "readmission", "action": "train", "effect": []}]},
            {"kind": "EXPIRE"},
        ]
        for mutation in mutations:
            changed = copy.deepcopy(event)
            changed.update(mutation)
            with self.subTest(mutation=mutation):
                self.assertFalse(evaluate_interval([changed], self.stable["query"])["valid"])

    def test_query_requires_full_lifecycle_and_valid_interval(self):
        mutations = [
            {"start_order": 11},
            {"start_order": True},
            {"commit_order": None},
            {"actions": ["train"]},
            {"actions": ["train", "train", "aggregate"]},
            {"actions": [[], "submit_update", "aggregate"]},
            {"purpose": ""},
            {"purpose": "   "},
        ]
        for mutation in mutations:
            query = dict(self.stable["query"], **mutation)
            with self.subTest(mutation=mutation):
                self.assertEqual(evaluate_interval(self.stable["events"], query)["reason"], "malformed_query")

    def test_revocation_at_commit_is_in_interval(self):
        trace = next(item for item in self.scenarios if item["id"] == "mid_round_revoke")
        query = dict(trace["query"], commit_order=trace["events"][-1]["order"])
        self.assertFalse(evaluate_interval(trace["events"], query)["valid"])

    def test_first_invalid_order_is_retained_after_regrant(self):
        trace = next(item for item in self.scenarios if item["id"] == "revoke_regrant")
        self.assertEqual(evaluate_interval(trace["events"], trace["query"])["invalid_order"], 5)


if __name__ == "__main__":
    unittest.main()
