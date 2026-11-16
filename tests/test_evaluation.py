from copy import deepcopy
import csv
import hashlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.request import Request, urlopen

import numpy as np

from pcfl import learning
from pcfl.data import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES
from pcfl.evaluation import (DynamoManifestResolver, EvaluationClient, EvaluationService,
    build_model_metadata, create_local_evaluation_tls, create_model_from_metadata,
    make_evaluation_server, parameters_digest, request_from_manifest)


def preprocessor():
    return {"schema_version": "0.1.0", "fit_scope": "training_only", "fit_rows": 16,
        "feature_order": list(FEATURES), "target": "y",
        "numeric": {name: {"median": 0, "mean": 0, "scale": 1} for name in NUMERIC_FEATURES},
        "categorical": {name: {"missing_code": 0, "unknown_code": 1, "vocabulary": {"observed": 2}}
                        for name in CATEGORICAL_FEATURES}}


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.models = self.root / "models"
        self.models.mkdir()
        self.validation = self.root / "validation.csv"
        with self.validation.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow([*FEATURES, "y"])
            for i in range(16):
                writer.writerow([*[i % 3] * len(NUMERIC_FEATURES), *[2] * len(CATEGORICAL_FEATURES), i % 2])
        self.validation_hash = hashlib.sha256(self.validation.read_bytes()).hexdigest()
        self.metadata = build_model_metadata(preprocessor(), seed=296)
        self.model = create_model_from_metadata(self.metadata)
        self.arrays = learning.get_parameters(self.model)
        self.path = self.models / "model.npz"
        with self.path.open("wb") as stream:
            np.savez(stream, *self.arrays)
        self.content = self.path.read_bytes()
        self.sha = hashlib.sha256(self.content).hexdigest()
        self.logical = parameters_digest(self.arrays)
        self.manifest = {"run_id": "run-1", "round_id": "round-1", "manifest_id": "a" * 64,
            "commit_order": 10, "model_schema_hash": self.model.schema_hash, "model_digest": self.logical,
            "artifact": {"backend": "local_immutable_checkpoint", "path": str(self.path),
                         "file_sha256": self.sha, "model_digest": self.logical}}
        self.request = request_from_manifest(self.manifest, "run-1")

    def service(self, **extra):
        return EvaluationService(self.metadata, self.validation, self.validation_hash,
                                 model_root=self.models, max_examples=8, **extra)

    def test_public_metadata_recreates_architecture_without_reading_evaluation_data(self):
        model = create_model_from_metadata(self.metadata)
        self.assertEqual(model.schema_hash, self.model.schema_hash)
        self.assertNotIn("validation", json.dumps(self.metadata))
        changed = deepcopy(self.metadata)
        changed["hidden_dims"] = [1]
        with self.assertRaises(ValueError):
            create_model_from_metadata(changed)
        state = preprocessor()
        state["patient_records"] = [{"patient": "must-never-publish"}]
        with self.assertRaisesRegex(ValueError, "nonpublic_preprocessor_fields"):
            build_model_metadata(state)

    def test_public_metadata_accepts_fitted_aggregate_missing_counts(self):
        state = preprocessor()
        for numeric in state["numeric"].values():
            numeric["missing_training_rows"] = 3
        metadata = build_model_metadata(state)
        self.assertEqual(create_model_from_metadata(metadata).schema_hash, metadata["model_schema_hash"])

    def test_evaluation_returns_only_aggregates_and_idempotent_bound_result(self):
        service = self.service()
        result = service.evaluate(self.request)
        self.assertEqual(result["metrics"]["count"], 8)
        self.assertEqual(result["dataset_role"], "validation")
        self.assertFalse(result["final_test_evaluated"])
        self.assertFalse(result["manifest_verified"])
        self.assertEqual(service.evaluate(self.request), result)
        self.assertEqual(service.evaluation_count, 1)
        for field in ("predictions", "probabilities", "labels", "rows", "validation_path", "arrays"):
            self.assertNotIn(field, result)
        rebound = deepcopy(self.request)
        rebound["run_id"] = "run-2"
        with self.assertRaisesRegex(ValueError, "request_id_rebound"):
            service.evaluate(rebound)

    def test_final_test_split_and_wrong_validation_hash_are_rejected(self):
        test = self.root / "test.csv"
        test.write_bytes(self.validation.read_bytes())
        with self.assertRaisesRegex(ValueError, "only_validation"):
            EvaluationService(self.metadata, test, self.validation_hash, model_root=self.models)
        with self.assertRaisesRegex(ValueError, "source_digest"):
            EvaluationService(self.metadata, self.validation, "0" * 64, model_root=self.models)

    def test_forged_model_bytes_digest_and_parameter_digest_fail_closed(self):
        service = self.service()
        forged = deepcopy(self.request)
        forged["artifact"]["file_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "byte_digest"):
            service.evaluate(forged)
        forged = deepcopy(self.request)
        forged["parameters_digest"] = forged["artifact"]["model_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "parameters_digest"):
            service.evaluate(forged)
        self.assertEqual(service.evaluation_count, 0)

    def test_local_path_escape_is_rejected_even_with_valid_bytes(self):
        outside = self.root / "outside.npz"
        outside.write_bytes(self.content)
        forged = deepcopy(self.request)
        forged["artifact"]["path"] = str(outside)
        with self.assertRaisesRegex(ValueError, "outside_owned_root"):
            self.service().evaluate(forged)

    def test_unexpected_record_payload_from_metric_provider_is_not_released(self):
        service = self.service()
        with patch("pcfl.evaluation.learning.evaluate", return_value={"count": 8, "labels": [0, 1]}):
            with self.assertRaisesRegex(ValueError, "aggregate_metric_schema"):
                service.evaluate(self.request)
        self.assertEqual(service.evaluation_count, 0)

    def test_coherently_hashed_wrong_shape_is_rejected_before_model_loading(self):
        bad = [self.arrays[0].reshape(-1), *self.arrays[1:]]
        with self.path.open("wb") as stream:
            np.savez(stream, *bad)
        forged = deepcopy(self.request)
        forged["artifact"]["file_sha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        forged["parameters_digest"] = forged["artifact"]["model_digest"] = parameters_digest(bad)
        with self.assertRaisesRegex(ValueError, "header_mismatch"):
            self.service().evaluate(forged)

    def s3_fixture(self):
        artifact = {"backend": "s3", "bucket": "pcfl-models", "key": "models/candidates/model.npz",
                    "version_id": "immutable-version-1", "sha256": self.sha, "size_bytes": len(self.content),
                    "model_digest": self.logical, "parameters_digest": self.logical}
        raw = {"run_id": "run-1", "round_id": "round-1", "manifest_id": "a" * 64,
               "commit_order": 10, "parameters_digest": self.logical,
               "candidate": {"model_schema_hash": self.model.schema_hash, "model_digest": self.sha,
                             "s3": {key: artifact[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}}}
        ddb = Mock()
        ddb.get_item.return_value = {"Item": {"record_type": {"S": "publication_manifest"},
                                              "manifest_json": {"S": json.dumps(raw)}}}
        s3 = Mock()
        s3.get_object.return_value = {"Body": io.BytesIO(self.content), "VersionId": artifact["version_id"],
                                      "ContentLength": len(self.content)}
        manifest = {**self.manifest, "artifact": artifact}
        request = request_from_manifest(manifest, "run-1")
        service = self.service(s3_client=s3, allowed_bucket="pcfl-models",
                               manifest_resolver=DynamoManifestResolver(ddb, "pcfl-state"))
        return service, request, ddb, s3

    def test_s3_bytes_and_logical_parameters_are_distinct_and_committed_metadata_is_resolved(self):
        service, request, ddb, s3 = self.s3_fixture()
        self.assertNotEqual(self.sha, self.logical)
        result = service.evaluate(request)
        self.assertTrue(result["manifest_verified"])
        self.assertTrue(ddb.get_item.call_args.kwargs["ConsistentRead"])
        self.assertEqual(ddb.get_item.call_args.kwargs["Key"]["SK"]["S"], "MANIFEST#" + "a" * 64)
        self.assertEqual(s3.get_object.call_args.kwargs["VersionId"], "immutable-version-1")

    def test_unpublished_or_rebound_s3_version_never_reaches_object_read(self):
        service, request, ddb, s3 = self.s3_fixture()
        ddb.get_item.return_value = {}
        with self.assertRaisesRegex(ValueError, "committed_manifest_missing"):
            service.evaluate(request)
        s3.get_object.assert_not_called()
        service, request, ddb, s3 = self.s3_fixture()
        request["artifact"]["version_id"] = "different-version"
        with self.assertRaisesRegex(ValueError, "committed_artifact_binding"):
            service.evaluate(request)
        s3.get_object.assert_not_called()

    def test_s3_evaluation_requires_independent_manifest_resolver(self):
        _, request, _, s3 = self.s3_fixture()
        service = self.service(s3_client=s3, allowed_bucket="pcfl-models")
        with self.assertRaisesRegex(ValueError, "manifest_resolver_required"):
            service.evaluate(request)
        s3.get_object.assert_not_called()

    def test_s3_response_version_and_payload_cannot_silently_change(self):
        service, request, _, s3 = self.s3_fixture()
        s3.get_object.return_value["VersionId"] = "wrong-version"
        with self.assertRaisesRegex(ValueError, "version_or_size"):
            service.evaluate(request)
        service, request, _, s3 = self.s3_fixture()
        s3.get_object.return_value["Body"] = io.BytesIO(b"x" * len(self.content))
        with self.assertRaisesRegex(ValueError, "byte_digest"):
            service.evaluate(request)

    def start_server(self):
        tls = create_local_evaluation_tls(self.root / "tls")
        service = self.service()
        server = make_evaluation_server(service, ("127.0.0.1", 0), certificate=tls["server_cert"],
                                       private_key=tls["server_key"], client_ca=tls["ca_cert"])
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(cleanup)
        endpoint = f"https://127.0.0.1:{server.server_port}"
        return service, endpoint, tls

    def test_real_mutual_tls_round_trip_and_missing_client_certificate_rejection(self):
        service, endpoint, tls = self.start_server()
        client = EvaluationClient(endpoint, ca_cert=tls["ca_cert"], client_cert=tls["client_cert"],
                                  client_key=tls["client_key"])
        result = client.evaluate(self.request)
        self.assertEqual(result["metrics"]["count"], 8)
        self.assertEqual(client.evaluate(self.request), result)
        context = ssl.create_default_context(cafile=str(tls["ca_cert"]))
        request = Request(endpoint + "/evaluate", data=json.dumps(self.request).encode(), method="POST")
        with self.assertRaises((URLError, ssl.SSLError, ConnectionResetError)):
            urlopen(request, context=context, timeout=3)
        self.assertEqual(service.evaluation_count, 1)

    def test_untrusted_client_ca_and_plaintext_endpoint_are_rejected(self):
        _, endpoint, tls = self.start_server()
        other = create_local_evaluation_tls(self.root / "untrusted-tls")
        client = EvaluationClient(endpoint, ca_cert=tls["ca_cert"], client_cert=other["client_cert"],
                                  client_key=other["client_key"])
        with self.assertRaises(RuntimeError):
            client.evaluate(self.request)
        with self.assertRaisesRegex(ValueError, "https_endpoint"):
            EvaluationClient(endpoint.replace("https:", "http:"), ca_cert=tls["ca_cert"],
                             client_cert=tls["client_cert"], client_key=tls["client_key"])


if __name__ == "__main__":
    unittest.main()
