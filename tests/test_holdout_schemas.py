"""Role-specific schema boundaries using real synthetic service emissions.

The dependency-free bounded schema checker is a test helper, not runtime
authorization. Every shape-valid rebinding below is also sent to the actual
semantic validator so structural validity cannot be mistaken for permission.
"""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from pcfl.evaluation import validate_test_response
from pcfl.experiments import digest
from pcfl.holdout import validate_authorization
from pcfl.runtime_verify import verify_case
import test_final_holdout as finaltests
from test_schemas import ShapeError, SCHEMAS, validate


class FinalHoldoutSchemaTests(unittest.TestCase):
    def setUp(self):
        self.fixture = finaltests.FinalEvaluationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def emitted(self):
        return self.fixture.service().evaluate(self.fixture.request)

    def test_real_emitted_test_summary_and_authority_fit_distinct_role_contracts(self):
        fixture = self.fixture
        response = self.emitted()
        validate("evaluation-request", fixture.request)
        validate("evaluation-test-response", response)
        validate("final-holdout-authorization", fixture.auth)
        validate("final-holdout-expectation", fixture.context)
        self.assertEqual(len(response), 19)
        self.assertEqual(response["metrics"]["count"], 16)
        self.assertEqual(validate_test_response(response, fixture.request, fixture.context), response)
        validate_authorization(fixture.plan, fixture.auth, model_schema_hash=fixture.metadata["model_schema_hash"])
        with self.assertRaises(ShapeError):
            validate("evaluation-response", response)

    def test_shared_request_stays_exactly_seven_fields_and_carries_no_authority(self):
        schema = SCHEMAS["evaluation-request"]
        self.assertEqual(set(schema["required"]), {"request_id", "run_id", "round_id", "manifest_id",
            "model_schema_hash", "parameters_digest", "artifact"})
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["$id"], "urn:pcfl:0.1.0:evaluation-request")
        for field, value in (("dataset_role", "test"), ("test_path", "private.csv"),
                             ("authorized", True), ("accepted_plan", self.fixture.plan),
                             ("holdout_authorization", self.fixture.auth), ("labels", [])):
            with self.subTest(field=field), self.assertRaises(ShapeError):
                validate("evaluation-request", {**self.fixture.request, field: value})

    def test_validation_contract_is_unchanged_and_does_not_accept_test_self_claims(self):
        response = self.emitted()
        validation = {key: value for key, value in response.items() if key not in {
            "test_sha256", "test_sample_digest", "accepted_plan_digest", "holdout_authorization_digest",
            "holdout_authorization_id", "cell_id"}}
        validation.update(dataset_role="validation", final_test_evaluated=False,
            validation_sha256="f" * 64, validation_sample_digest="e" * 64)
        validate("evaluation-response", validation)
        self.assertEqual(len(validation), 15)
        with self.assertRaises(ShapeError):
            validate("evaluation-test-response", validation)
        for field, value in (("dataset_role", "test"), ("final_test_evaluated", True),
                             ("test_sha256", "f" * 64), ("accepted_plan_digest", "e" * 64)):
            with self.subTest(field=field), self.assertRaises(ShapeError):
                validate("evaluation-response", {**validation, field: value})

    def test_test_response_rejects_every_missing_field_and_private_or_wrong_role_payload(self):
        response = self.emitted()
        for field in response:
            with self.subTest(missing=field), self.assertRaises(ShapeError):
                validate("evaluation-test-response", {key: value for key, value in response.items() if key != field})
        for field, value in (("dataset_role", "validation"), ("final_test_evaluated", False),
                             ("manifest_verified", False), ("manifest_verified", 1),
                             ("validation_sha256", "f" * 64), ("rows", []), ("nonce", "bearer"),
                             ("model_sha256", "not-a-hash")):
            with self.subTest(field=field, value=value), self.assertRaises(ShapeError):
                validate("evaluation-test-response", {**response, field: value})
        for field in ("labels", "predictions", "probabilities", "arrays", "patient_records"):
            with self.subTest(field=field), self.assertRaises(ShapeError):
                validate("evaluation-test-response", {**response, "metrics": {**response["metrics"], field: []}})
        for field, value in (("count", True), ("auroc", float("nan")), ("loss", float("inf")),
                             ("auprc", 1.1), ("threshold", .7)):
            with self.subTest(metric=field), self.assertRaises(ShapeError):
                validate("evaluation-test-response", {**response, "metrics": {**response["metrics"], field: value}})

    def test_shape_valid_response_rebinding_still_requires_external_semantic_expectations(self):
        response = self.emitted()
        for field, value in (("manifest_id", "a" * 64), ("parameters_digest", "a" * 64),
                             ("model_sha256", "a" * 64), ("test_sha256", "a" * 64),
                             ("accepted_plan_digest", "a" * 64), ("holdout_authorization_digest", "a" * 64),
                             ("cell_id", "unregistered-cell"), ("run_id", "unlisted-run"), ("round_id", "round-4")):
            changed = {**response, field: value}
            with self.subTest(field=field):
                validate("evaluation-test-response", changed)
                with self.assertRaises(RuntimeError):
                    validate_test_response(changed, self.fixture.request, self.fixture.context)

    def test_native_integer_and_cross_metric_bindings_are_not_proved_by_shape(self):
        response = self.emitted()
        for fields in ({"count": 16.0}, {"positive_count": 17}, {"prevalence": .25}):
            changed = {**response, "metrics": {**response["metrics"], **fields}}
            with self.subTest(fields=fields):
                validate("evaluation-test-response", changed)
                with self.assertRaises((RuntimeError, ValueError)):
                    validate_test_response(changed, self.fixture.request, self.fixture.context)

    def test_authority_schema_rejects_booleans_wildcards_secrets_and_unbounded_scope(self):
        auth = self.fixture.auth
        for fields in ({"authorized": True}, {"scope": "all-runs"}, {"runs": {}},
                       {"runs": {"*": self.fixture.cell["cell_id"]}}, {"runs": {"run-1": True}},
                       {"issued_at_utc": "2026-11-13T00:00:00"}, {"private_key": "secret"},
                       {"plan_digest": False}, {"runs": {f"run-{i}": f"cell-{i}" for i in range(301)}}):
            with self.subTest(fields=list(fields)), self.assertRaises(ShapeError):
                validate("final-holdout-authorization", {**auth, **fields})
        for field in auth:
            with self.subTest(missing=field), self.assertRaises(ShapeError):
                validate("final-holdout-authorization", {key: value for key, value in auth.items() if key != field})

    def test_shape_valid_authority_requires_digest_plan_mapping_and_timestamp_semantics(self):
        fixture = self.fixture
        for field, value in (("authorization_digest", "0" * 64), ("plan_digest", "0" * 64),
                             ("test_sha256", "0" * 64), ("model_schema_hash", "0" * 64),
                             ("runs", {"run-1": "unregistered-cell"}),
                             ("runs", {"run-1": fixture.cell["cell_id"], "run-2": fixture.cell["cell_id"]}),
                             ("issued_at_utc", "2026-11-99T00:00:00Z")):
            auth = deepcopy(fixture.auth)
            auth[field] = value
            if field != "authorization_digest":
                auth["authorization_digest"] = digest({key: item for key, item in auth.items() if key != "authorization_digest"})
            with self.subTest(field=field):
                validate("final-holdout-authorization", auth)
                with self.assertRaises(ValueError):
                    validate_authorization(fixture.plan, auth, model_schema_hash=fixture.metadata["model_schema_hash"])

    def test_expected_response_scope_has_four_fields_and_grants_no_authority(self):
        context = self.fixture.context
        self.assertEqual(set(SCHEMAS["final-holdout-expectation"]["required"]), set(context))
        for fields in ({"authorized": True}, {"test_sha256": False}, {"cell_id": "*"}):
            with self.subTest(fields=fields), self.assertRaises(ShapeError):
                validate("final-holdout-expectation", {**context, **fields})
        wrong = {**context, "test_sha256": "0" * 64}
        validate("final-holdout-expectation", wrong)
        with self.assertRaises(RuntimeError):
            validate_test_response(self.emitted(), self.fixture.request, wrong)

    def test_independently_verified_summary_contract_preserves_baseline_counterexample(self):
        evidence, context = finaltests.final_evidence(self.fixture.root, baseline="B1", revoked=True)
        path = self.fixture.root / "runtime_result.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        summary = verify_case(path, expect_test_authorization=context)
        validate("metric-test-record", summary)
        self.assertGreater(summary["oracle_invalid_incorporations"], 0)
        self.assertFalse(summary["is_confirmatory"])
        with self.assertRaises(ShapeError):
            validate("metric-record", summary)
        for fields in ({"is_confirmatory": True}, {"evaluation_split": "validation"},
                       {"final_holdout_authorization_verified": False}, {"test_metrics": None},
                       {"validation_metrics": summary["test_metrics"]}, {"labels": []}):
            with self.subTest(fields=list(fields)), self.assertRaises(ShapeError):
                validate("metric-test-record", {**summary, **fields})


if __name__ == "__main__":
    unittest.main()
