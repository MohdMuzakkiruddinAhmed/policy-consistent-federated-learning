"""Future P9 boundaries. All approvals, CSV rows, models and AWS responses are synthetic."""

from copy import deepcopy
import csv
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import numpy as np

from pcfl import learning, service_runtime
from pcfl.evaluation import (DynamoManifestResolver, EvaluationClient, EvaluationService, build_model_metadata,
    create_model_from_metadata, make_evaluation_server, parameters_digest, request_from_manifest, validate_test_response)
from pcfl.experiments import GATES, build_plan, digest, file_digest, freeze_plan
from pcfl.holdout import strict_json, validate_authorization, validate_expectation
from pcfl.runtime_verify import verify_case
from pcfl.service_io import service_identities
from pcfl.data import FEATURES, NUMERIC_FEATURES, CATEGORICAL_FEATURES
from test_evaluation import preprocessor
from test_experiments import synthetic_gate_refs
import test_integrated_runtime as boundaries
from test_runtime_verify import persistent_fixture, persistent_baseline_fixture, json_hash

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=8)
def frozen_fixture(test_sha):
    """Exercise the real freeze function with temporary synthetic gate documents."""
    config = json.loads((ROOT / "configs/experiments.json").read_text())
    training = json.loads((ROOT / config["training_config"]).read_text())
    training.update(pilot_only=False, confirmatory_frozen=True)
    hashes = {f"{kind}/org_{i:02d}.csv": digest([kind, i])
              for kind in ("iid", "non_iid") for i in range(1, 9)}
    hashes.update({"preprocessor.json": digest("synthetic preprocessor"),
                   "validation.csv": digest("synthetic validation"), "test.csv": test_sha})
    data = {"private_artifacts_sha256": hashes, "checks": {key: True for key in
        ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")}}
    sources = {"src/synthetic.py": hashlib.sha256(b"# synthetic source fixture\n").hexdigest()}
    provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "git_commit": None,
                  "image_digests": {"runtime": "example.invalid/synthetic@sha256:" + "b" * 64}}
    plan = build_plan(config, training, data, provenance)
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        (directory / "src").mkdir()
        (directory / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
        acceptance = synthetic_gate_refs(plan, directory)
        return freeze_plan(plan, acceptance, directory)


def authority(test_sha, model_schema, *, run_id="run-1", baseline="P1", scenario="S0"):
    plan = deepcopy(frozen_fixture(test_sha))
    cell = next(cell for cell in plan["primary_cells"] if cell["baseline_id"] == baseline
        and cell["scenario_id"] == scenario and cell["distribution"] == "iid" and cell["seed"] == 296)
    auth = {"schema_version": "0.1.0", "kind": "pcfl-final-holdout-authorization",
        "authorization_id": "synthetic-operator-authorization", "status": "authorized",
        "scope": "final-committed-model-only", "issued_by": "synthetic-test-operator",
        "issued_at_utc": "2026-11-12T10:00:00Z", "plan_digest": plan["plan_digest"],
        "test_sha256": test_sha, "model_schema_hash": model_schema, "runs": {run_id: cell["cell_id"]}}
    auth["authorization_digest"] = digest(auth)
    return plan, auth, cell


def expectation(plan, auth, cell):
    return {"plan_digest": plan["plan_digest"], "authorization_digest": auth["authorization_digest"],
            "test_sha256": auth["test_sha256"], "cell_id": cell["cell_id"]}


def resign(value, field):
    value[field] = digest({key: item for key, item in value.items() if key != field})


class HoldoutAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.auth, self.cell = authority("f" * 64, "a" * 64)

    def test_actual_freeze_plus_separate_authority_is_required_and_immutable(self):
        scope = validate_authorization(self.plan, self.auth, model_schema_hash="a" * 64)
        self.assertEqual(scope.cell_for("run-1", "round-5"), self.cell["cell_id"])
        self.assertFalse(self.plan["final_test_access_permitted"])
        self.auth["runs"].clear()
        self.assertEqual(scope.cell_for("run-1", "round-5"), self.cell["cell_id"])
        for run, round_id in (("unlisted", "round-5"), ("run-1", "round-4")):
            with self.subTest(run=run, round=round_id), self.assertRaises(ValueError):
                scope.cell_for(run, round_id)

    def test_caller_boolean_candidate_plan_and_rebound_authority_are_denied(self):
        candidates = [(None, True), (self.plan, {**self.auth, "final_test_access_permitted": True})]
        plan = deepcopy(self.plan)
        plan.update(status="candidate_locked", confirmatory_execution_enabled=False)
        resign(plan, "plan_digest")
        auth = deepcopy(self.auth)
        auth["plan_digest"] = plan["plan_digest"]
        resign(auth, "authorization_digest")
        candidates.append((plan, auth))
        for field, value in (("test_sha256", "0" * 64), ("model_schema_hash", "0" * 64),
                             ("issued_at_utc", "2026-11-12T10:00:00")):
            changed = deepcopy(self.auth)
            changed[field] = value
            resign(changed, "authorization_digest")
            candidates.append((self.plan, changed))
        for plan, auth in candidates:
            with self.subTest(auth=auth), self.assertRaises(ValueError):
                validate_authorization(plan, auth, model_schema_hash="a" * 64)

    def test_registered_mapping_is_unique_and_unsafe_ablation_is_excluded(self):
        for mapping in ({"run-1": self.cell["cell_id"], "run-2": self.cell["cell_id"]},
                        {"run-1": "unregistered-cell"},
                        {"run-1": next(cell["cell_id"] for cell in self.plan["ablation_cells"] if cell["unsafe_comparator"])},
                        {"run-1": self.plan["ablation_cells"][0]["cell_id"]}):
            auth = deepcopy(self.auth)
            auth["runs"] = mapping
            resign(auth, "authorization_digest")
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                validate_authorization(self.plan, auth, model_schema_hash="a" * 64)

    def test_strict_json_and_expectation_reject_ambiguous_or_extra_authority(self):
        for encoded in ('{"runs":{},"runs":{}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(encoded)
        context = expectation(self.plan, self.auth, self.cell)
        self.assertEqual(validate_expectation(context), context)
        for changed in ({**context, "authorized": True}, {**context, "test_sha256": True}):
            with self.assertRaises(ValueError):
                validate_expectation(changed)


class FinalEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.test = self.root / "test.csv"
        with self.test.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow([*FEATURES, "y"])
            for i in range(16):
                writer.writerow([*[i % 3] * len(NUMERIC_FEATURES), *[2] * len(CATEGORICAL_FEATURES), i % 2])
        self.sha = file_digest(self.test)
        self.metadata = build_model_metadata(preprocessor())
        model = create_model_from_metadata(self.metadata)
        arrays = learning.get_parameters(model)
        stream = io.BytesIO()
        np.savez(stream, *arrays)
        self.content = stream.getvalue()
        self.artifact = {"backend": "s3", "bucket": "synthetic-models", "key": "models/candidates/final.npz",
            "version_id": "immutable-synthetic-version", "sha256": hashlib.sha256(self.content).hexdigest(),
            "size_bytes": len(self.content), "model_digest": parameters_digest(arrays),
            "parameters_digest": parameters_digest(arrays)}
        self.manifest = {"run_id": "run-1", "round_id": "round-5", "manifest_id": "c" * 64,
            "commit_order": 100, "parameters_digest": parameters_digest(arrays),
            "model_schema_hash": model.schema_hash, "artifact": self.artifact}
        self.plan, self.auth, self.cell = authority(self.sha, model.schema_hash)
        self.request = request_from_manifest(self.manifest, "run-1")
        self.context = expectation(self.plan, self.auth, self.cell)
        self.ddb, self.s3 = Mock(), Mock()
        self.pointer = {key: {kind: str(self.manifest[key])} for key, kind in
                        (("manifest_id", "S"), ("round_id", "S"), ("commit_order", "N"))}
        def get_item(**kwargs):
            self.assertTrue(kwargs["ConsistentRead"])
            if kwargs["Key"]["SK"]["S"] == "POINTER":
                return {"Item": deepcopy(self.pointer)}
            return {"Item": {"record_type": {"S": "publication_manifest"},
                             "manifest_json": {"S": json.dumps(self.manifest)}}}
        self.ddb.get_item.side_effect = get_item
        self.s3.get_object.side_effect = lambda **kwargs: {"Body": io.BytesIO(self.content),
            "VersionId": self.artifact["version_id"], "ContentLength": len(self.content)}

    def service(self, **overrides):
        options = dict(dataset_role="test", accepted_plan=self.plan, holdout_authorization=self.auth,
            max_examples=1000, s3_client=self.s3, allowed_bucket="synthetic-models",
            manifest_resolver=DynamoManifestResolver(self.ddb, "synthetic-state", require_current=True))
        options.update(overrides)
        return EvaluationService(self.metadata, self.test, self.sha, **options)

    def test_full_cohort_only_final_durable_model_and_idempotent_aggregate_response(self):
        service = self.service()
        response = service.evaluate(self.request)
        self.assertEqual(response["metrics"]["count"], 16)
        self.assertEqual(response["test_sha256"], self.sha)
        self.assertEqual(validate_test_response(response, self.request, self.context), response)
        self.assertTrue(response["final_test_evaluated"])
        self.assertNotIn("validation_sha256", response)
        for forbidden in ("rows", "labels", "predictions", "probabilities", "arrays"):
            self.assertNotIn(forbidden, response)
        second = {**self.request, "request_id": "synthetic-retry"}
        self.assertEqual(service.evaluate(second), {**response, "request_id": second["request_id"]})
        self.assertEqual(service.evaluation_count, 1)
        self.assertEqual(self.s3.get_object.call_count, 1)
        rebound = {**second, "manifest_id": "d" * 64}
        with self.assertRaisesRegex(ValueError, "already_bound"):
            service.evaluate(rebound)

    def test_invalid_authority_cannot_read_csv_or_model_bytes(self):
        for auth in (None, True, {**self.auth, "status": "denied"}):
            with self.subTest(auth=auth), patch("pcfl.evaluation.Path.read_bytes") as read:
                with self.assertRaises(ValueError):
                    self.service(holdout_authorization=auth)
                read.assert_not_called()
        self.s3.get_object.assert_not_called()

    def test_wrong_run_round_and_local_model_are_denied_before_s3_access(self):
        service = self.service()
        for change in ({"run_id": "other-run"}, {"round_id": "round-4"},
                       {"artifact": {"backend": "local_immutable_checkpoint", "path": "secret"}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                service.evaluate({**self.request, **change})
        self.s3.get_object.assert_not_called()

    def test_changed_current_pointer_or_version_denies_model_read(self):
        service = self.service()
        self.pointer["manifest_id"] = {"S": "d" * 64}
        with self.assertRaisesRegex(ValueError, "pointer_binding"):
            service.evaluate(self.request)
        self.s3.get_object.assert_not_called()
        self.pointer["manifest_id"] = {"S": self.manifest["manifest_id"]}
        request = deepcopy(self.request)
        request["artifact"]["version_id"] = "rebound-version"
        with self.assertRaisesRegex(ValueError, "artifact_binding"):
            service.evaluate(request)
        self.s3.get_object.assert_not_called()

    def test_pointer_change_during_manifest_read_fails_closed(self):
        service = self.service()
        stable = deepcopy(self.pointer)
        changed = {**stable, "commit_order": {"N": "101"}}
        self.ddb.get_item.side_effect = [
            {"Item": stable},
            {"Item": {"record_type": {"S": "publication_manifest"}, "manifest_json": {"S": json.dumps(self.manifest)}}},
            {"Item": changed}]
        with self.assertRaisesRegex(ValueError, "pointer_binding"):
            service.evaluate(self.request)
        self.s3.get_object.assert_not_called()

    def test_full_cohort_cap_does_not_silently_sample_and_public_metadata_cannot_read_paths(self):
        with self.assertRaisesRegex(ValueError, "full_authorized_test_cohort"):
            self.service(max_examples=8)
        metadata = deepcopy(self.metadata)
        metadata["preprocessor"] = "forbidden-preprocessor-file"
        with patch("pcfl.evaluation.learning.load_preprocessor") as read:
            with self.assertRaisesRegex(ValueError, "public_preprocessor_mapping"):
                create_model_from_metadata(metadata)
            read.assert_not_called()

    def test_response_binding_and_metric_privacy_are_strict(self):
        response = self.service().evaluate(self.request)
        changes = ({"cell_id": "wrong-cell"}, {"test_sha256": "0" * 64},
                   {"holdout_authorization_digest": "0" * 64}, {"final_test_evaluated": 1},
                   {"rows": []}, {"metrics": {**response["metrics"], "labels": []}},
                   {"metrics": {**response["metrics"], "count": True}},
                   {"metrics": {**response["metrics"], "auroc": float("nan")}})
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ValueError, RuntimeError)):
                validate_test_response({**response, **change}, self.request, self.context)

    def test_real_mtls_final_client_requires_coordinator_identity_and_explicit_bindings(self):
        service = self.service()
        identities = service_identities(self.root / "tls")
        server = make_evaluation_server(service, ("127.0.0.1", 0),
            certificate=identities["evaluation"]["cert"], private_key=identities["evaluation"]["key"],
            client_ca=identities["ca"], private_network=True, expected_client_cn="pcfl-coordinator")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        endpoint = f"https://127.0.0.1:{server.server_port}"
        def client(role="coordinator", context=None):
            return EvaluationClient(endpoint, ca_cert=identities["ca"], client_cert=identities[role]["cert"],
                client_key=identities[role]["key"], timeout=2, expected_holdout=context)
        try:
            with self.assertRaises(RuntimeError):
                client("policy-operator", self.context).evaluate(self.request)
            self.assertEqual(service.evaluation_count, 0)
            self.assertTrue(client(context=self.context).evaluate(self.request)["final_test_evaluated"])
            with self.assertRaises(RuntimeError):
                client().evaluate(self.request)
            with self.assertRaises(RuntimeError):
                client(context={**self.context, "test_sha256": "0" * 64}).evaluate(self.request)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(service.evaluation_count, 1)

    def loader_config(self):
        def ref(key, sha):
            return {"bucket": "synthetic-models", "key": key, "version_id": "synthetic-version",
                    "sha256": sha, "size_bytes": 100}
        return {"dataset_role": "test", "storage": {"expected_account_id": "123456789012"},
            "bucket": "synthetic-models", "table_name": "synthetic-state", "model_metadata": self.metadata,
            "runtime_directory": str(self.root / "runtime"),
            "accepted_plan_object": ref("evaluation/accepted/plan.json", digest(self.plan)),
            "authorization_object": ref("evaluation/accepted/authorization.json", digest(self.auth)),
            "test_object": ref("evaluation/frozen/test.csv", self.sha),
            "tls_files": {"server_cert": "synthetic-cert", "server_key": "synthetic-key", "ca_cert": "synthetic-ca"}}

    def test_loader_pins_read_only_authority_before_fetching_any_test_bytes(self):
        config = self.loader_config()
        fetched = []
        def fetch(_s3, reference, destination, **kwargs):
            fetched.append(reference["key"])
            self.assertEqual(kwargs["expected_owner"], "123456789012")
            destination = Path(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            value = self.plan if reference == config["accepted_plan_object"] else {**self.auth, "status": "denied"}
            destination.write_text(json.dumps(value))
            return destination
        with patch.object(service_runtime, "sdk_clients", return_value=(self.ddb, self.s3)), \
             patch.object(service_runtime, "fetch_pinned", side_effect=fetch):
            with self.assertRaises(ValueError):
                service_runtime.serve_evaluation(config)
        self.assertEqual(fetched, ["evaluation/accepted/plan.json", "evaluation/accepted/authorization.json"])

    def test_loader_rejects_inline_boolean_wrong_prefix_and_wrong_version_before_sdk(self):
        for change in ({"dataset_role": "validation", "confirmatory": True},
                       {"accepted_plan": self.plan}, {"authorization_object": {**self.loader_config()["authorization_object"], "key": "metadata/authorization.json"}},
                       {"test_object": {**self.loader_config()["test_object"], "version_id": "null"}}):
            with self.subTest(change=change), patch.object(service_runtime, "sdk_clients") as sdk:
                with self.assertRaises(ValueError):
                    service_runtime.serve_evaluation({**self.loader_config(), **change})
                sdk.assert_not_called()


def final_evidence(directory, *, baseline="P1", revoked=False):
    evidence = (persistent_fixture(directory) if baseline == "P1" else
                persistent_baseline_fixture(directory, baseline, revoked=revoked))
    # This independent synthetic transcript models its only publication at the
    # registered final round. Rebuild its audit commitments after changing IDs.
    evidence = json.loads(json.dumps(evidence).replace("round-1", "round-5"))
    previous = "0" * 64
    for record in evidence["audit"]:
        record["prev_hash"] = previous
        record["event_hash"] = previous = json_hash({key: value for key, value in record.items() if key != "event_hash"})
    evidence["anchor"]["head"] = previous
    rows = evidence["durable_evidence"]["run_records"]
    for row in rows:
        if row["SK"].startswith("AUDIT#"):
            record = evidence["audit"][int(row["SK"].split("#")[1]) - 1]
            row.update(event_hash=record["event_hash"], event_json=json.dumps(record))
        elif row["SK"] == "AUDIT_HEAD":
            row["head"] = previous
        elif row["SK"].startswith("TXN#") and row.get("operation_kind") == "publication":
            outcome = json.loads(row["result_json"])
            outcome["audit_head"] = previous
            row["result_json"] = json.dumps(outcome)
    plan, auth, cell = authority("f" * 64, evidence["model_schema_hash"],
        run_id=evidence["persistent_run_id"], baseline=baseline, scenario="S2" if revoked else "S0")
    evidence.update(test_holdout_evaluated=True, scenario_id="mid_round" if revoked else "stable", test_metrics=evidence.pop("validation_metrics"),
        test_source_sha256=evidence.pop("validation_source_sha256"), accepted_plan_digest=plan["plan_digest"],
        plan_digest=plan["plan_digest"], holdout_authorization_digest=auth["authorization_digest"],
        cell_id=cell["cell_id"], seed=cell["seed"], distribution=cell["distribution"], equivalence_hash=cell["equivalence_hash"])
    evidence["experiment_binding"] = {"plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"],
        "equivalence_hash": cell["equivalence_hash"], "family": cell["family"],
        "policy_schedule_hash": cell["shared_config"]["policy_schedule_hash"], "source_sha256": plan["provenance"]["source_sha256"]}
    response = evidence["evaluation_service_response"]
    response.pop("validation_sha256")
    sample = response.pop("validation_sample_digest")
    response.update(dataset_role="test", final_test_evaluated=True, test_sha256=auth["test_sha256"],
        test_sample_digest=sample, accepted_plan_digest=plan["plan_digest"],
        holdout_authorization_digest=auth["authorization_digest"], holdout_authorization_id=auth["authorization_id"], cell_id=cell["cell_id"])
    return evidence, {"accepted_plan": plan, "authorization": auth}


class IndependentFinalVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "runtime_result.json"

    def verify(self, evidence, context=None, **kwargs):
        self.path.write_text(json.dumps(evidence))
        return verify_case(self.path, expect_test_authorization=context, **kwargs)

    def test_external_authority_is_required_and_independently_validated(self):
        evidence, context = final_evidence(self.root)
        with self.assertRaisesRegex(ValueError, "validation_only"):
            self.verify(evidence)
        # Enforcement validation is deliberately unavailable to the verifier.
        with patch("pcfl.holdout.validate_authorization", side_effect=AssertionError("shared enforcement imported")):
            summary = self.verify(evidence, context)
        self.assertTrue(summary["final_holdout_authorization_verified"])
        self.assertFalse(summary["is_confirmatory"])
        self.assertEqual(summary["evaluation_split"], "test")
        self.assertEqual(summary["oracle_invalid_incorporations"], 0)

    def test_self_claims_and_coherently_resigned_wrong_authority_are_rejected(self):
        evidence, context = final_evidence(self.root)
        for field, value in (("test_sha256", "0" * 64), ("runs", {"unlisted": evidence["cell_id"]}),
                             ("model_schema_hash", "0" * 64)):
            changed = deepcopy(context)
            changed["authorization"][field] = value
            resign(changed["authorization"], "authorization_digest")
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(evidence, changed)
        for field, value in (("cell_id", "wrong-cell"), ("test_source_sha256", "0" * 64),
                             ("equivalence_hash", "0" * 64)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify({**evidence, field: value}, context)

    def test_final_response_tampering_and_safety_override_are_rejected(self):
        evidence, context = final_evidence(self.root)
        for field, value in (("test_sha256", "0" * 64), ("round_id", "round-4"), ("rows", []),
                             ("holdout_authorization_id", "wrong-operator")):
            changed = deepcopy(evidence)
            changed["evaluation_service_response"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(changed, context)
        with self.assertRaisesRegex(ValueError, "cannot_disable_P1_safety"):
            self.verify(evidence, context, expect_safe=False)

    def test_authorized_baseline_keeps_oracle_invalid_counterexample(self):
        evidence, context = final_evidence(self.root, baseline="B1", revoked=True)
        summary = self.verify(evidence, context)
        self.assertGreater(summary["oracle_invalid_incorporations"], 0)
        self.assertTrue(summary["final_holdout_authorization_verified"])


class FinalCoordinatorBoundaryTests(unittest.TestCase):
    def setUp(self):
        boundaries.IntegratedCoordinatorBoundaryTests.setUpClass()
        self.metadata = boundaries.IntegratedCoordinatorBoundaryTests.metadata
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.grid = boundaries.EightNodeGrid()

    def run_final(self, *, corrupt=False):
        from pcfl.flower_app import run_server
        config = boundaries.IntegratedCoordinatorBoundaryTests.configuration(self)
        config.update(distribution="iid", final_holdout={"plan_digest": "a" * 64,
            "authorization_digest": "b" * 64, "test_sha256": "c" * 64, "cell_id": "synthetic-cell"})
        config.update(plan_digest="a" * 64, cell_id="synthetic-cell", match_id="synthetic-match", equivalence_hash="e" * 64)
        config["experiment_binding"] = {"plan_digest": "a" * 64, "cell_id": "synthetic-cell", "equivalence_hash": "e" * 64,
            "family": "primary", "policy_schedule_hash": "f" * 64, "source_sha256": "f" * 64}
        # The authority double owns local checkpoints. Adapt only its request
        # transport reference; durable/current S3 bindings are tested above.
        def s3_request(manifest, run_id):
            request = request_from_manifest(manifest, run_id)
            request["artifact"]["sha256"] = request["artifact"]["file_sha256"]
            return request
        def response(request):
            return {**{key: request[key] for key in ("request_id", "run_id", "round_id", "manifest_id", "model_schema_hash", "parameters_digest")},
                "schema_version": "0.1.0", "model_sha256": request["artifact"]["sha256"],
                "metadata_digest": self.metadata["metadata_digest"], "dataset_role": "test",
                "final_test_evaluated": True, "manifest_verified": True,
                "metrics": {"count": 8, "positive_count": 4, "prevalence": .5, "auroc": .5, "auprc": .5,
                    "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7},
                "test_sha256": "0" * 64 if corrupt else "c" * 64, "test_sample_digest": "d" * 64,
                "accepted_plan_digest": "a" * 64, "holdout_authorization_digest": "b" * 64,
                "holdout_authorization_id": "synthetic-operator", "cell_id": "synthetic-cell"}
        with boundaries.IntegratedCoordinatorBoundaryTests.service_boundaries(self) as state, \
             patch("pcfl.evaluation.request_from_manifest", side_effect=s3_request):
            state.evaluator.evaluate.side_effect = response
            result = run_server(self.grid, config)
            state.partition.assert_not_called()
            state.local_evaluation.assert_not_called()
            self.assertEqual(state.evaluator_factory.call_args.kwargs["expected_holdout"], config["final_holdout"])
            return result

    def test_explicit_test_bindings_emit_only_final_test_metrics(self):
        result = self.run_final()
        self.assertTrue(result["test_holdout_evaluated"])
        self.assertIn("test_metrics", result)
        self.assertNotIn("validation_metrics", result)
        self.assertEqual(result["evaluation_service_response"]["manifest_id"], result["published_manifests"][-1]["manifest_id"])

    def test_bad_test_response_preserves_commit_and_records_failed_runtime(self):
        with self.assertRaisesRegex(RuntimeError, "response_binding"):
            self.run_final(corrupt=True)
        report = json.loads((self.output / "runtime_result.json").read_text())
        self.assertFalse(report["successful"])
        self.assertEqual(len(report["published_manifests"]), 1)
        self.assertNotIn("test_metrics", report)
        self.assertIsNot(report.get("test_holdout_evaluated"), True)


if __name__ == "__main__":
    unittest.main()
