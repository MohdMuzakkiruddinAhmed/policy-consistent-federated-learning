from copy import deepcopy
import io
import json
import os
from pathlib import Path
import random
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

from pcfl.opa import OPA_VERSION, OpaClient, OpaUnavailable, PROTOCOL_REVISION, policy_hash, validate_input

ROOT = Path(__file__).resolve().parents[1]


class Response(io.BytesIO):
    status = 200


class OpaClientTests(unittest.TestCase):
    def setUp(self):
        self.traces = json.loads((ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8"))
        self.trace = self.traces[0]
        self.client = OpaClient("http://127.0.0.1:8181", allow_loopback_http=True)

    def reply(self, request, timeout, mutate=None):
        payload = json.loads(request.data)["input"]
        envelope = {"decision_id": "actual-opa-decision-id", "provenance": {"version": OPA_VERSION}, "result": {
            "valid": True, "reason": "continuous_authorization", "invalid_order": None,
            "rule_hash": self.client.rule_hash, "protocol_revision": PROTOCOL_REVISION,
            "query": payload["query"], "request_binding": payload["request_binding"],
            "request_hash": payload["request_hash"], "history_digest": payload["history_digest"]}}
        if mutate:
            mutate(envelope)
        return Response(json.dumps(envelope).encode())

    def test_rule_metadata_matches_actual_source_and_golden_fixture_copy(self):
        metadata = json.loads((ROOT / "policies/rego/data.json").read_text(encoding="utf-8"))["pcfl_meta"]
        self.assertEqual(metadata["policy_sha256"], policy_hash())
        self.assertEqual(metadata["protocol_revision"], PROTOCOL_REVISION)
        copied = json.loads((ROOT / "policies/rego/fixtures.json").read_text(encoding="utf-8"))["pcfl_testdata"]["traces"]
        self.assertEqual(copied, self.traces)

    def test_bound_native_opa_decision_is_returned(self):
        with patch.object(self.client._opener, "open", side_effect=self.reply) as opened:
            decision = self.client.evaluate(self.trace["events"], self.trace["query"])
        self.assertTrue(decision["valid"])
        self.assertEqual(decision["decision_id"], "actual-opa-decision-id")
        self.assertEqual(opened.call_args.kwargs["timeout"], 3.0)
        self.assertNotIn('"allow"', opened.call_args.args[0].data.decode().split('"query"')[1])

    def test_plain_http_requires_explicit_loopback_only(self):
        for endpoint, enabled in (("http://127.0.0.1:8181", False), ("http://opa.example:8181", True),
                                  ("http://localhost.attacker:8181", True), ("file:///tmp/policy", True),
                                  ("https://user:password@opa.example", False)):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                OpaClient(endpoint, allow_loopback_http=enabled)
        OpaClient("https://opa.example:8181")

    def test_missing_undefined_or_unattributable_result_fails_closed(self):
        mutations = [lambda doc: doc.pop("result"), lambda doc: doc.pop("decision_id"),
                     lambda doc: doc["result"].pop("invalid_order"),
                     lambda doc: doc.update(provenance=[]), lambda doc: doc["provenance"].update(version="other"),
                     lambda doc: doc["result"].update(valid=1), lambda doc: doc["result"].update(rule_hash="f" * 64),
                     lambda doc: doc["result"].update(protocol_revision="old"),
                     lambda doc: doc["result"].update(request_binding="other"),
                     lambda doc: doc["result"].update(history_digest="f" * 64),
                     lambda doc: doc["result"].update(query={}),
                     lambda doc: doc["result"].update(reason="authorization_interrupted"),
                     lambda doc: doc["result"].update(valid=False, reason="unknown_revision_reason")]
        for mutation in mutations:
            with self.subTest(mutation=mutation), patch.object(self.client._opener, "open",
                    side_effect=lambda request, timeout: self.reply(request, timeout, mutation)):
                with self.assertRaises(OpaUnavailable):
                    self.client.evaluate(self.trace["events"], self.trace["query"])

    def test_unavailable_invalid_json_and_oversized_response_fail_closed(self):
        for effect in (URLError("offline"), Response(b"not json"), Response(b" " * 1_000_001)):
            kwargs = {"side_effect": effect} if isinstance(effect, Exception) else {"return_value": effect}
            with self.subTest(effect=type(effect).__name__), patch.object(self.client._opener, "open", **kwargs):
                with self.assertRaises(OpaUnavailable):
                    self.client.evaluate(self.trace["events"], self.trace["query"])

    def test_malformed_histories_fail_before_network(self):
        for mutation in ({"epoch": 2}, {"order": True}, {"event_id": []}, {"org_id": []},
                         {"rules": [{}]}, {"kind": "UNKNOWN"}):
            events = deepcopy(self.trace["events"])
            events[0].update(mutation)
            with self.subTest(mutation=mutation), patch.object(self.client._opener, "open") as opened:
                with self.assertRaises(ValueError):
                    self.client.evaluate(events, self.trace["query"])
                opened.assert_not_called()

    def test_duplicate_and_gapped_history_fail_closed(self):
        events = deepcopy(self.trace["events"])
        extra = deepcopy(events[0])
        extra.update(order=3, epoch=2)
        for field in ("event_id", "order", "epoch"):
            changed = deepcopy(extra)
            if field == "epoch":
                changed.update(event_id="new", epoch=3)
            else:
                changed[field] = events[0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_input(events + [changed], self.trace["query"])


@unittest.skipUnless(os.environ.get("PCFL_OPA_TEST_URL"), "Set PCFL_OPA_TEST_URL for real Rego integration")
class OpaServiceTests(unittest.TestCase):
    @staticmethod
    def long_history(count):
        return [{"event_id": f"long-history-{index}", "order": index + 1,
            "org_id": f"org_{index % 8 + 1:02d}", "epoch": index // 8 + 1,
            "kind": "GRANT", "rules": [{"purpose": "readmission", "action": action, "effect": "allow"}
                for action in ("train", "submit_update", "aggregate")]}
            for index in range(count)]

    def test_large_complete_histories_preserve_oracle_decisions(self):
        from pcfl.oracle import evaluate_interval
        client = OpaClient(os.environ["PCFL_OPA_TEST_URL"], allow_loopback_http=True)
        for count in (2064, 4096):
            events = self.long_history(count)
            query = {"org_id": "org_01", "purpose": "readmission", "start_order": count - 16,
                "commit_order": count, "actions": ["train", "submit_update", "aggregate"]}
            for revoked in (False, True):
                if revoked:
                    events[-8].update(kind="REVOKE", rules=[])
                with self.subTest(count=count, revoked=revoked):
                    actual, expected = client(events, query), evaluate_interval(events, query)
                    self.assertEqual(actual["valid"], expected["valid"])
                    self.assertEqual(actual["invalid_order"], expected["invalid_order"])

    def test_native_rego_rejects_rank_epoch_and_global_identity_corruption(self):
        from pcfl.oracle import evaluate_interval
        client = OpaClient(os.environ["PCFL_OPA_TEST_URL"], allow_loopback_http=True)
        query = {"org_id": "org_01", "purpose": "readmission", "start_order": 32,
            "commit_order": 32, "actions": ["train", "submit_update", "aggregate"]}
        cases = []
        for mutation in ("epoch-gap", "swapped-epoch-rank", "duplicate-epoch", "non-one-first-epoch", "duplicate-global-id", "duplicate-global-order"):
            events = self.long_history(32)
            if mutation == "epoch-gap": events[24]["epoch"] = 6
            elif mutation == "swapped-epoch-rank": events[8]["epoch"], events[16]["epoch"] = events[16]["epoch"], events[8]["epoch"]
            elif mutation == "duplicate-epoch": events[16]["epoch"] = events[8]["epoch"]
            elif mutation == "non-one-first-epoch": events[1]["epoch"] = 2
            elif mutation == "duplicate-global-id": events[1]["event_id"] = events[0]["event_id"]
            else: events[1]["order"] = events[0]["order"]
            cases.append((mutation, events))
        for mutation, events in cases:
            # Bypass the Python input-shape guard so this exercises native Rego
            # itself, including malformed histories rejected before HTTP normally.
            request = Request(client.endpoint + "/v1/data/pcfl/decision?provenance=true",
                data=json.dumps({"input": {"events": events, "query": query}}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with self.subTest(mutation=mutation), client._opener.open(request, timeout=3) as response:
                actual = json.loads(response.read())["result"]
                self.assertFalse(evaluate_interval(events, query)["valid"])
                self.assertFalse(actual["valid"])
                self.assertEqual(actual["reason"], "malformed_history_or_query")

    def test_actual_service_matches_all_sixteen_independent_oracle_traces(self):
        from pcfl.oracle import evaluate_interval
        traces = json.loads((ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8"))
        client = OpaClient(os.environ["PCFL_OPA_TEST_URL"], allow_loopback_http=True)
        ids = set()
        for trace in traces:
            with self.subTest(trace=trace["id"]):
                result = client.evaluate(trace["events"], trace["query"])
                self.assertEqual(result["valid"], trace["expected_valid"])
                self.assertEqual(result["valid"], evaluate_interval(trace["events"], trace["query"])["valid"])
                ids.add(result["decision_id"])
        self.assertEqual(len(ids), 16)

    def test_seeded_valid_histories_match_independent_oracle(self):
        from pcfl.oracle import evaluate_interval
        rng = random.Random(268601)
        client = OpaClient(os.environ["PCFL_OPA_TEST_URL"], allow_loopback_http=True)
        actions = ["train", "submit_update", "aggregate"]
        organizations = [f"org_{index:02d}" for index in range(1, 9)]
        outcomes = set()
        for case in range(128):
            events, epochs = [], {org: 1 for org in organizations}
            order = 0
            for org in organizations:
                order += 1
                events.append({"event_id": f"{case}-{order}", "order": order, "org_id": org,
                    "epoch": 1, "kind": "GRANT", "rules": [
                        {"purpose": "research", "action": action, "effect": "allow"} for action in actions]})
            for _ in range(12):
                order += rng.randint(1, 3)
                org = rng.choice(organizations)
                epochs[org] += 1
                kind = rng.choice(["CHANGE", "CHANGE", "GRANT", "REVOKE", "EXPIRE"])
                rules = []
                if kind in {"GRANT", "CHANGE"}:
                    rules = [{"purpose": "research", "action": action, "effect": "allow"} for action in actions]
                    alteration = rng.randrange(4)
                    if alteration == 0:
                        rules.pop(rng.randrange(3))
                    if alteration == 1:
                        rules.append({"purpose": "research", "action": rng.choice(actions), "effect": "deny"})
                    rules.append({"purpose": "other-purpose", "action": rng.choice(actions), "effect": "deny"})
                events.append({"event_id": f"{case}-{order}", "order": order, "org_id": org,
                    "epoch": epochs[org], "kind": kind, "rules": rules})
            start = rng.choice(events[7:])["order"]
            query = {"org_id": rng.choice(organizations), "purpose": "research", "start_order": start,
                     "commit_order": order, "actions": actions}
            if case % 4 == 0:
                events.append({"order": order + 1, "unrecognized_future_payload": True})
            rng.shuffle(events)
            with self.subTest(case=case):
                expected = evaluate_interval(events, query)
                decision = client(events, query)
                self.assertEqual(decision["valid"], expected["valid"])
                self.assertEqual(decision["invalid_order"], expected["invalid_order"])
                outcomes.add(decision["valid"])
        self.assertEqual(outcomes, {True, False})
