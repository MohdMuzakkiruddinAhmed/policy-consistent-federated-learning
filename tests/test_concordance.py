"""Compare independently implemented interval decisions over a bounded state space.

This checks finite executable examples, not a universal proof or an AWS race test.
The oracle and candidate enforcement share only this test's plain input records.
"""

import copy
import itertools
import json
from pathlib import Path
import unittest

from pcfl.oracle import evaluate_interval
from pcfl.reference import evaluate_history


ROOT = Path(__file__).resolve().parents[1]
ACTIONS = ["train", "submit_update", "aggregate"]


def _allow_rules(purpose="readmission"):
    return [{"purpose": purpose, "action": action, "effect": "allow"} for action in ACTIONS]


def _history(transitions):
    history = [{
        "event_id": "event_1", "org_id": "org_01", "order": 1,
        "epoch": 1, "kind": "GRANT", "rules": _allow_rules(),
    }]
    for epoch, transition in enumerate(transitions, start=2):
        if transition == "revoke":
            kind, rules = "REVOKE", []
        elif transition == "deny":
            kind = "CHANGE"
            rules = _allow_rules() + [{
                "purpose": "readmission", "action": "aggregate", "effect": "deny",
            }]
        elif transition == "unrelated":
            kind, rules = "CHANGE", _allow_rules() + _allow_rules("another_purpose")
        else:
            kind = "GRANT" if transition == "regrant" else "CHANGE"
            rules = _allow_rules()
        history.append({
            "event_id": f"event_{epoch}", "org_id": "org_01", "order": 2 * epoch - 1,
            "epoch": epoch, "kind": kind, "rules": rules,
        })
    return history


class ConcordanceTests(unittest.TestCase):
    def test_invalid_identity_and_whitespace_validation_concordance(self):
        fixtures = json.loads(
            (ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8")
        )
        for case in ("unknown_org", "unknown_history_org", "blank_purpose", "blank_event_id"):
            trace = copy.deepcopy(fixtures[0])
            if case == "unknown_org":
                trace["events"][0]["org_id"] = "org_99"
                trace["query"]["org_id"] = "org_99"
            elif case == "unknown_history_org":
                trace["events"][0]["org_id"] = "org_99"
            elif case == "blank_purpose":
                trace["query"]["purpose"] = "   "
                for rule in trace["events"][0]["rules"]:
                    rule["purpose"] = "   "
            else:
                trace["events"][0]["event_id"] = "   "
            with self.subTest(case=case):
                self.assertFalse(evaluate_interval(trace["events"], trace["query"])["valid"])
                self.assertFalse(evaluate_history(trace["events"], trace["query"])["valid"])

    def test_golden_fixture_concordance(self):
        fixtures = json.loads(
            (ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8")
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture["id"]):
                actual = evaluate_history(fixture["events"], fixture["query"])
                expected = evaluate_interval(fixture["events"], fixture["query"])
                self.assertEqual(actual["valid"], expected["valid"])
                self.assertEqual(actual["valid"], fixture["expected_valid"])
        self.assertEqual(len(fixtures), 16)

    def test_exhaustive_four_transition_concordance(self):
        alphabet = ("allow", "revoke", "regrant", "unrelated", "deny")
        case_count = 0
        history_count = 0
        for length in range(5):
            for transitions in itertools.product(alphabet, repeat=length):
                events = _history(transitions)
                history_count += 1
                horizon = 2 * len(events)
                for start in range(1, horizon + 1):
                    for commit in range(start, horizon + 1):
                        query = {
                            "org_id": "org_01", "purpose": "readmission",
                            "start_order": start, "commit_order": commit, "actions": ACTIONS,
                        }
                        oracle = evaluate_interval(events, query)
                        candidate = evaluate_history(events, query)
                        self.assertEqual(
                            candidate["valid"], oracle["valid"],
                            f"transitions={transitions}; interval=[{start},{commit}]; "
                            f"candidate={candidate}; oracle={oracle}",
                        )
                        case_count += 1
        self.assertEqual(history_count, 781)
        self.assertEqual(case_count, 39453)


if __name__ == "__main__":
    unittest.main()
