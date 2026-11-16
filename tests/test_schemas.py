"""Dependency-free checks of this repository's deliberately bounded schema subset.

This helper is not a general JSON Schema implementation or a metaschema test
suite. It rejects unsupported assertion keywords, resolves the local URN set,
and checks positive/negative contract examples. Semantic bindings are checked by
the independent/runtime implementations separately from structural validity.
"""

from copy import deepcopy
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from pcfl import aws_transactions as tx
from pcfl.contracts import ACTIONS, ORGANIZATIONS, digest
from pcfl.opa import OpaClient, OpaUnavailable, validate_input
from pcfl.reference import evaluate_history
from pcfl.verifier import verify_chain


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {path.stem.removesuffix(".schema"): json.loads(path.read_text(encoding="utf-8"))
           for path in (ROOT / "schemas").glob("*.schema.json")}
REGISTRY = {schema["$id"]: schema for schema in SCHEMAS.values()}
RUNTIME = all(importlib.util.find_spec(name) is not None for name in ("numpy", "flwr", "torch", "sklearn"))


class ShapeError(ValueError):
    pass


def _equal(first, second):
    if isinstance(first, bool) or isinstance(second, bool):
        return type(first) is type(second) and first == second
    return first == second


def _resolve(reference):
    identifier, _, pointer = reference.partition("#")
    schema = REGISTRY[identifier]
    for part in pointer.lstrip("/").split("/") if pointer else []:
        schema = schema[part.replace("~1", "/").replace("~0", "~")]
    return schema


def _matches(schema, value):
    try:
        check(schema, value)
        return True
    except ShapeError:
        return False


def check(schema, value):
    """Validate only the assertion vocabulary used in this versioned schema set."""
    if schema is False:
        raise ShapeError("forbidden value")
    if schema is True:
        return
    if "$ref" in schema:
        check(_resolve(schema["$ref"]), value)
    if "const" in schema and not _equal(value, schema["const"]):
        raise ShapeError("const")
    if "enum" in schema and not any(_equal(value, item) for item in schema["enum"]):
        raise ShapeError("enum")
    for child in schema.get("allOf", []):
        check(child, value)
    if "anyOf" in schema and not any(_matches(child, value) for child in schema["anyOf"]):
        raise ShapeError("anyOf")
    if "oneOf" in schema and sum(_matches(child, value) for child in schema["oneOf"]) != 1:
        raise ShapeError("oneOf")
    if "not" in schema and _matches(schema["not"], value):
        raise ShapeError("not")
    if "if" in schema:
        selected = "then" if _matches(schema["if"], value) else "else"
        if selected in schema:
            check(schema[selected], value)
    number = type(value) in (int, float) and math.isfinite(value)
    kinds = {"object": isinstance(value, dict), "array": isinstance(value, list),
             "string": isinstance(value, str), "boolean": type(value) is bool,
             "null": value is None, "number": number,
             "integer": number and (type(value) is int or value.is_integer())}
    if "type" in schema and not kinds[schema["type"]]:
        raise ShapeError("type")
    if isinstance(value, dict):
        if any(key not in value for key in schema.get("required", [])):
            raise ShapeError("required")
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", math.inf):
            raise ShapeError("property count")
        for key, child in value.items():
            if "propertyNames" in schema:
                check(schema["propertyNames"], key)
            if key in schema.get("properties", {}):
                check(schema["properties"][key], child)
            elif "additionalProperties" in schema:
                check(schema["additionalProperties"], child)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", math.inf):
            raise ShapeError("item count")
        if schema.get("uniqueItems") and any(_equal(value[left], value[right])
                for left in range(len(value)) for right in range(left)):
            raise ShapeError("duplicate item")
        for child in value:
            if "items" in schema:
                check(schema["items"], child)
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise ShapeError("pattern")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", math.inf):
            raise ShapeError("string length")
    if number and (value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf)):
        raise ShapeError("number bound")
    if number and (value <= schema.get("exclusiveMinimum", -math.inf) or value >= schema.get("exclusiveMaximum", math.inf)):
        raise ShapeError("exclusive number bound")


def validate(name, value):
    check(SCHEMAS[name], value)


def candidate():
    reference = {"bucket": "pcfl-test-models", "key": "models/candidates/model.npz", "version_id": "version-1",
                 "sha256": "a" * 64, "size_bytes": 100}
    value = {"snapshot_order": 12, "parent_manifest_id": None, "round_generation": 1,
        "policy_epochs": {"org_01": 1}, "history_digests": {"org_01": "b" * 64},
        "model_schema_hash": "c" * 64, "rule_bundle_hash": "d" * 64, "model_digest": reference["sha256"],
        "s3": reference, "object_confirmation": {key: reference[key] for key in ("version_id", "sha256", "size_bytes")},
        "updates": [{"update_id": "update-1", "task_id": "task-1", "org_id": "org_01", "purpose": "readmission",
                     "start_order": 3, "sample_count": 2, "weights_digest": "e" * 64}]}
    value["candidate_id"] = tx.candidate_digest(value)
    return value


def publication(value=None):
    return tx.build_publication("pcfl-test-state", run_id="run-1", round_id="round-1", txn_id="publish-1",
        candidate=value or candidate(), expected_audit_count=0, expected_audit_head="0" * 64)


def emitted(request, record_type, field):
    return [json.loads(action["Put"]["Item"][field]["S"]) for action in request["TransactItems"]
            if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": record_type}]


class SchemaContractTests(unittest.TestCase):
    def test_all_twenty_one_versioned_schemas_resolve_without_network_or_unlocked_dependencies(self):
        self.assertEqual(len(SCHEMAS), 21)
        self.assertEqual(len(REGISTRY), 21)
        supported = {"$schema", "$id", "$ref", "$defs", "$comment", "title", "description", "type", "required",
            "properties", "additionalProperties", "propertyNames", "enum", "const", "allOf", "anyOf", "oneOf",
            "not", "if", "then", "else", "items", "uniqueItems", "minItems", "maxItems", "minimum", "maximum",
            "pattern", "minLength", "maxLength", "minProperties", "maxProperties", "exclusiveMinimum", "exclusiveMaximum"}
        def inspect(schema):
            if type(schema) is bool:
                return
            self.assertFalse(set(schema) - supported, "unsupported assertion must not silently pass")
            if "$ref" in schema:
                self.assertIsInstance(_resolve(schema["$ref"]), dict)
            for key in ("$defs", "properties"):
                for child in schema.get(key, {}).values():
                    inspect(child)
            for key in ("additionalProperties", "propertyNames", "items", "not", "if", "then", "else"):
                if key in schema:
                    inspect(schema[key])
            for key in ("allOf", "anyOf", "oneOf"):
                for child in schema.get(key, []):
                    inspect(child)
        for name, schema in SCHEMAS.items():
            with self.subTest(schema=name):
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["$id"], "urn:pcfl:0.1.0:" + name)
                inspect(schema)
        self.assertEqual(set(SCHEMAS["common"]["$defs"]["org"]["enum"]), set(ORGANIZATIONS))

    def test_golden_policy_records_and_queries_use_documented_grammar(self):
        traces = json.loads((ROOT / "policies/fixtures/interval_traces.json").read_text(encoding="utf-8"))
        self.assertEqual(len(traces), 16)
        for trace in traces:
            with self.subTest(trace=trace["id"]):
                for event in trace["events"]:
                    validate("policy-event", event)
                    validate("policy-version", event)
                validate("interval-query", trace["query"])
                self.assertEqual(evaluate_history(trace["events"], trace["query"])["valid"], trace["expected_valid"])

    def test_boolean_orders_wrong_orgs_actions_and_revocation_rules_are_malformed(self):
        event = {"event_id": "grant", "org_id": "org_01", "order": 1, "epoch": 1, "kind": "GRANT",
                 "rules": [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS]}
        for update in ({"order": True}, {"org_id": "org_09"}, {"epoch": 0}, {"kind": "REVOKE"}, {"event_id": " "}):
            with self.subTest(update=update), self.assertRaises(ShapeError):
                validate("policy-event", {**event, **update})
        for actions in (["train", "train", "aggregate"], ["train"], ["train", "submit_update", "evaluate"]):
            with self.subTest(actions=actions), self.assertRaises(ShapeError):
                validate("interval-query", {"org_id": "org_01", "purpose": "readmission", "start_order": 1,
                    "commit_order": 2, "actions": actions})

    def test_shape_valid_interval_gaps_and_native_float_orders_still_require_semantics(self):
        query = {"org_id": "org_01", "purpose": "readmission", "start_order": 5, "commit_order": 4, "actions": list(ACTIONS)}
        validate("interval-query", query)
        with self.assertRaises(ValueError):
            validate_input([], query)
        query.update(start_order=1, commit_order=3)
        event = {"event_id": "grant", "org_id": "org_01", "order": 1, "epoch": 2, "kind": "GRANT", "rules": []}
        validate("policy-event", event)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_input([event], query)
        event.update(order=1.0, epoch=1)
        validate("policy-event", event)  # JSON Schema's integer is mathematical, not lexical.
        with self.assertRaisesRegex(ValueError, "unknown_policy_order"):
            validate_input([event], query)

    def test_source_transaction_builders_emit_schema_compatible_manifest_and_audit(self):
        request = publication()
        manifest = emitted(request, "publication_manifest", "manifest_json")[0]
        audit = emitted(request, "audit_event", "event_json")
        validate("publication-manifest", manifest)
        for record in audit:
            validate("audit-event", record)
            validate("update-decision", record["payload"])
        self.assertTrue(verify_chain(audit, {"count": 1, "head": audit[-1]["event_hash"]}))
        changed = deepcopy(audit)
        changed[0]["payload"]["purpose"] = "other-purpose"
        validate("audit-event", changed[0])
        self.assertFalse(verify_chain(changed, {"count": 1, "head": audit[-1]["event_hash"]}))

    def test_shape_valid_candidate_rebinding_and_incomplete_guards_fail_builder_checks(self):
        for alter in (lambda value: value.update(model_digest="f" * 64),
                      lambda value: value["policy_epochs"].update(org_02=1),
                      lambda value: value["object_confirmation"].update(version_id="different-version")):
            value = candidate()
            alter(value)
            validate("publication-manifest", {"manifest_id": value["candidate_id"], "run_id": "run-1",
                "round_id": "round-1", "commit_order": 13, "commit_txn_id": "publish-1", "candidate": value})
            with self.assertRaises(ValueError):
                publication(value)

    def test_public_task_and_update_contracts_reject_bearer_tokens_and_private_payloads(self):
        task = {"task_id": "task-1", "org_id": "org_01", "purpose": "readmission", "round_id": "round-1",
            "start_order": 3, "policy_epoch": 1, "policy_hash": "a" * 64, "model_schema_hash": "b" * 64,
            "nonce_digest": "c" * 64}
        update = {**{key: task[key] for key in ("task_id", "org_id", "purpose", "round_id", "start_order", "model_schema_hash")},
            "update_id": "update-1", "sample_count": 2, "received_order": 4, "weights_digest": "d" * 64}
        validate("task-authorization", task)
        validate("model-update", update)
        for name, value, fields in (("task-authorization", task, ("nonce", "labels", "patient_nbr")),
                                    ("model-update", update, ("arrays", "rows", "training_records"))):
            for field in fields:
                with self.subTest(schema=name, field=field), self.assertRaises(ShapeError):
                    validate(name, {**value, field: "must-not-export"})
        changed = deepcopy(update)
        changed["sample_count"] = True
        with self.assertRaises(ShapeError):
            validate("model-update", changed)

    def test_current_evaluation_response_is_aggregate_validation_only(self):
        metrics = {"count": 2, "positive_count": 1, "prevalence": .5, "auroc": .5, "auprc": .5,
            "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7}
        result = {"schema_version": "0.1.0", "request_id": "evaluation-1", "run_id": "run-1", "round_id": "round-1",
            **{name: "a" * 64 for name in ("manifest_id", "model_schema_hash", "parameters_digest", "model_sha256",
                                           "metadata_digest", "validation_sha256", "validation_sample_digest")},
            "dataset_role": "validation", "final_test_evaluated": False, "manifest_verified": True, "metrics": metrics}
        validate("evaluation-response", result)
        for fields in ({"dataset_role": "test"}, {"final_test_evaluated": True}, {"labels": [0, 1]}, {"validation_path": "private.csv"}):
            with self.subTest(fields=fields), self.assertRaises(ShapeError):
                validate("evaluation-response", {**result, **fields})
        for field in ("rows", "labels", "predictions", "probabilities"):
            with self.subTest(field=field), self.assertRaises(ShapeError):
                validate("evaluation-response", {**result, "metrics": {**metrics, field: [0, 1]}})
        for value in (float("nan"), float("inf"), -0.1, 1.1, True):
            with self.subTest(auroc=value), self.assertRaises(ShapeError):
                validate("aggregate-metrics", {**metrics, "auroc": value})
        validate("aggregate-metrics", {**metrics, "auroc": None, "auprc": None})

    def test_native_decision_shape_does_not_substitute_for_expected_rule_binding(self):
        events = [{"event_id": "grant", "org_id": "org_01", "order": 1, "epoch": 1, "kind": "GRANT",
                   "rules": [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS]}]
        query = {"org_id": "org_01", "purpose": "readmission", "start_order": 2, "commit_order": 3,
                 "actions": list(ACTIONS)}
        client = OpaClient("https://opa.invalid")
        class Response(io.BytesIO):
            status = 200
        def wrong_revision(request, timeout):
            value = json.loads(request.data)["input"]
            decision = {"valid": True, "reason": "continuous_authorization", "invalid_order": None,
                "rule_hash": "f" * 64, "protocol_revision": "pcfl-interval-v1", "query": value["query"],
                "request_binding": value["request_binding"], "request_hash": value["request_hash"],
                "history_digest": value["history_digest"], "decision_id": "native-decision-1", "opa_version": "1.22.3"}
            validate("authorization-decision", decision)
            with self.assertRaises(ShapeError):
                validate("authorization-decision", {**decision, "reason": "authorization_interrupted"})
            envelope = {"decision_id": decision.pop("decision_id"), "provenance": {"version": decision.pop("opa_version")},
                        "result": decision}
            return Response(json.dumps(envelope).encode())
        with patch.object(client._opener, "open", side_effect=wrong_revision), self.assertRaises(OpaUnavailable):
            client(events, query)

    def test_verifier_summary_preserves_denominator_counts_without_confirmatory_claims(self):
        summary = {"successful": True, "baseline_id": "P1", "scenario_id": "stable",
            **{name: 0 for name in ("unique_presented_updates", "oracle_invalid_presented", "oracle_invalid_incorporations",
                "oracle_valid_rejections", "accepted_updates", "final_decisions", "published_models")},
            "audit_verified": True, "model_reconstruction_verified": True, "persistent_protocol_verified": False,
            "committed_evaluation_response_verified": False, "model_digests": [], "validation_metrics": None,
            "is_confirmatory": False}
        summary.update({name: 0 for name in ("assigned_tasks", "acknowledged_tasks", "final_update_decisions", "final_operational_errors",
            "indeterminate_tasks", "audited_final_decisions", "audit_complete_decisions")})
        validate("metric-record", summary)
        for changed in ({"is_confirmatory": True}, {"accepted_updates": True}, {"oracle_invalid_presented": -1}):
            with self.subTest(changed=changed), self.assertRaises(ShapeError):
                validate("metric-record", {**summary, **changed})

    @unittest.skipUnless(RUNTIME, "pinned runtime supplies Flower and learning dependencies")
    def test_actual_flower_export_projection_and_semantic_metric_binding(self):
        import numpy as np
        from pcfl.flower_app import RuntimeAuthority, arrays_digest
        from pcfl.runtime_verify import _verify_aggregate_metrics
        authority = RuntimeAuthority("P1", [np.zeros(2, dtype=np.float32)], "a" * 64)
        task = authority.issue("org_01", 1, "round-1")
        task = authority.acknowledge(task["task_id"], 1, task)
        arrays = [np.ones(2, dtype=np.float32)]
        metadata = {**{key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose",
            "start_order", "model_schema_hash", "nonce")}, "sample_count": 2, "weights_digest": arrays_digest(arrays)}
        authority.receive(task["task_id"], 1, metadata, arrays)
        manifest = authority.publish("round-1", stage=lambda _, sha: {"backend": "local_immutable_checkpoint", "path": "fixture.npz",
                                                                     "model_digest": sha, "file_sha256": "b" * 64})
        from pcfl.evaluation import request_from_manifest
        request = request_from_manifest(manifest, "run-1")
        validate("evaluation-request", request)
        with self.assertRaises(ShapeError):
            validate("evaluation-request", {**request, "validation_path": "private.csv"})
        evidence = authority.evidence()
        projected = {key: evidence[key] for key in ("policy_events", "tasks", "updates", "decisions",
                                                    "published_manifests", "audit", "anchor")}
        validate("lifecycle", projected)
        self.assertNotIn("nonce", projected["tasks"][0])
        self.assertEqual(projected["tasks"][0]["nonce_digest"], digest(task["nonce"]))
        with self.assertRaises(ShapeError):
            validate("lifecycle", {**projected, "durable_evidence": {"unreviewed_rows": []}})
        metrics = {"count": 2, "positive_count": 3, "prevalence": .5, "auroc": .5, "auprc": .5,
                   "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7}
        validate("aggregate-metrics", metrics)
        with self.assertRaises(ValueError):
            _verify_aggregate_metrics(metrics)

    @unittest.skipUnless(RUNTIME, "pinned runtime supplies learning dependencies")
    def test_public_model_metadata_binds_architecture_without_record_or_path_fields(self):
        from pcfl.data import FEATURES, NUMERIC_FEATURES, CATEGORICAL_FEATURES
        from pcfl.evaluation import build_model_metadata, create_model_from_metadata
        state = {"schema_version": "0.1.0", "fit_scope": "training_only", "fit_rows": 16,
            "feature_order": list(FEATURES), "target": "y",
            "numeric": {name: {"median": 0, "mean": 0, "scale": 1} for name in NUMERIC_FEATURES},
            "categorical": {name: {"missing_code": 0, "unknown_code": 1, "vocabulary": {"observed": 2}}
                            for name in CATEGORICAL_FEATURES}}
        metadata = build_model_metadata(state, hidden_dims=(4,))
        validate("model-metadata", metadata)
        changed = {**metadata, "model_schema_hash": "f" * 64}
        validate("model-metadata", changed)
        with self.assertRaises(ValueError):
            create_model_from_metadata(changed)
        for field in ("patient_records", "validation_path", "labels", "nonce"):
            with self.subTest(field=field), self.assertRaises(ShapeError):
                validate("model-metadata", {**metadata, "preprocessor": {**metadata["preprocessor"], field: []}})

    def test_local_reference_task_evidence_contains_only_nonce_digest(self):
        from pcfl.state_model import LocalProtocolModel
        model = LocalProtocolModel()
        model.mutate("org_01", "GRANT", [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS])
        task = model.authorize("org_01", "readmission", "round-1")
        exported = model.evidence()["tasks"][0]
        self.assertNotIn("nonce", exported)
        self.assertEqual(exported["nonce_digest"], digest(task.nonce))
        validate("task-authorization", exported)
