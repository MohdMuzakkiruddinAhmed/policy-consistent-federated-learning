from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import numpy as np

from pcfl import learning
from pcfl.evaluation import build_model_metadata, create_model_from_metadata
from pcfl.service_runtime import fetch_pinned, materialize_tls, opa_command, probe_access, serve_evaluation, serve_governance
from pcfl.service_io import service_identities
from test_evaluation import preprocessor


class ServiceRuntimeTests(unittest.TestCase):
    def test_role_secret_materialization_is_private_non_overwriting_and_does_not_mutate_caller(self):
        secret = {"tls": {"ca_pem": "synthetic-ca", "server_cert_pem": "synthetic-cert", "server_key_pem": "synthetic-key"}}
        original = deepcopy(secret)
        with tempfile.TemporaryDirectory() as directory:
            config = materialize_tls(secret, directory)
            self.assertNotIn("tls", config)
            self.assertEqual(secret, original)
            self.assertEqual(Path(config["tls_files"]["server_key"]).read_text(), "synthetic-key")
            with self.assertRaises(FileExistsError):
                materialize_tls(secret, directory)
            with self.assertRaises(ValueError):
                materialize_tls({"tls": {"unknown_secret": "value"}}, directory)

    def test_object_fetch_requires_exact_version_checksum_owner_and_bounded_size(self):
        content = b"synthetic-only"
        reference = {"bucket": "synthetic", "key": "evaluation/frozen/validation.csv", "version_id": "v1",
                     "sha256": hashlib.sha256(content).hexdigest()}
        client = Mock()
        with tempfile.TemporaryDirectory() as directory:
            for reason in ("version", "hash", "size"):
                client.get_object.return_value = {"VersionId": "wrong" if reason == "version" else "v1",
                    "ContentLength": 100_000_001 if reason == "size" else len(content),
                    "Body": io.BytesIO(b"corrupted" if reason == "hash" else content)}
                path = Path(directory) / reason
                with self.assertRaises(ValueError):
                    fetch_pinned(client, reference, path, expected_owner="123456789012")
                self.assertFalse(path.exists())
            client.get_object.return_value = {"VersionId": "v1", "ContentLength": len(content), "Body": io.BytesIO(content)}
            path = Path(directory) / "valid"
            fetch_pinned(client, reference, path, expected_owner="123456789012")
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(client.get_object.call_args.kwargs["ExpectedBucketOwner"], "123456789012")

    def test_secret_types_and_path_injection_fail_before_any_materialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for secret in ({"tls": {"ca_pem": "ca", "client_key_pem": None}},
                           {"tls": {"ca_pem": "ca"}, "tls_files": {"client_key": "/other/key"}},
                           {"tls": {"ca_pem": " "}}):
                with self.subTest(secret=secret), self.assertRaises(ValueError):
                    materialize_tls(secret, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_body_length_mismatch_and_bad_reference_fail_without_creating_files(self):
        content = b"synthetic-only"
        reference = {"bucket": "test", "key": "evaluation/frozen/validation.csv", "version_id": "v1",
                     "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            body = io.BytesIO(content)
            client.get_object.return_value = {"VersionId": "v1", "ContentLength": len(content) + 1, "Body": body}
            with self.assertRaises(ValueError):
                fetch_pinned(client, reference, Path(directory) / "result", expected_owner="123456789012")
            self.assertTrue(body.closed)
            self.assertEqual(list(Path(directory).iterdir()), [])
            for invalid in ({**reference, "version_id": 1}, {**reference, "key": "evaluation/../test/validation.csv"},
                            {**reference, "size_bytes": True}):
                with self.subTest(invalid=invalid), patch.object(client, "get_object") as get:
                    with self.assertRaises(ValueError):
                        fetch_pinned(client, invalid, Path(directory) / "bad", expected_owner="123456789012")
                    get.assert_not_called()

    def test_bad_role_paths_and_public_metadata_fail_before_sdk_access(self):
        for config in ({"validation_object": {"key": "partitions/iid/org_01/train.csv"}},
                       {"validation_object": {"key": "evaluation/../frozen/validation.csv"}},
                       {"validation_object": {"key": "evaluation/frozen/validation.csv"}, "model_metadata": {}}):
            with self.subTest(config=config), patch("pcfl.service_runtime.sdk_clients") as sdk:
                with self.assertRaises(ValueError):
                    serve_evaluation(config)
                sdk.assert_not_called()
        with patch("pcfl.service_runtime.sdk_clients") as sdk, self.assertRaises(ValueError):
            serve_governance({"campaign_object": {"key": "metadata/policy.json"}})
        sdk.assert_not_called()

    def test_packaged_evaluation_boundary_authorizes_coordinator_role_over_real_mtls(self):
        from pcfl.evaluation import make_evaluation_server
        with tempfile.TemporaryDirectory() as directory:
            identities = service_identities(directory)
            service = Mock()
            service.evaluate.return_value = {"aggregate": "synthetic-only"}
            server = make_evaluation_server(service, ("127.0.0.1", 0), certificate=identities["evaluation"]["cert"],
                private_key=identities["evaluation"]["key"], client_ca=identities["ca"], private_network=True,
                expected_client_cn="pcfl-coordinator")
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
            thread.start()
            try:
                request = Request(f"https://127.0.0.1:{server.server_port}/evaluate", data=b"{}", method="POST")
                for role in ("policy-operator", "coordinator"):
                    context = ssl.create_default_context(cafile=identities["ca"])
                    context.load_cert_chain(identities[role]["cert"], identities[role]["key"])
                    if role == "policy-operator":
                        with self.assertRaises(HTTPError) as denied:
                            urlopen(request, context=context, timeout=2)
                        self.assertEqual(denied.exception.code, 403)
                        service.evaluate.assert_not_called()
                    else:
                        with urlopen(request, context=context, timeout=2) as response:
                            self.assertEqual(response.status, 200)
                        service.evaluate.assert_called_once_with({})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_coordinator_iam_probe_uses_metadata_and_does_not_fabricate_organization(self):
        from botocore.exceptions import ClientError
        content = b'{"public":"metadata"}'
        reference = {"key": "metadata/model.json", "version_id": "version-1", "sha256": hashlib.sha256(content).hexdigest()}
        storage = {"expected_account_id": "123456789012", "region": "us-east-1"}
        config = {"storage": storage, "bucket": "test", "role_kind": "coordinator", "allowed_object": reference,
            "denied_objects": [{"key": "evaluation/frozen/validation.csv", "version_id": "version-2"}],
            "table_name": "pcfl-state", "expected_task_role_arn": "arn:aws:iam::123456789012:role/coordinator"}
        denied = ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        ddb, s3, sts = Mock(), Mock(), Mock()
        s3.get_object.side_effect = [{"VersionId": "version-1", "ContentLength": len(content), "Body": io.BytesIO(content)}, denied]
        ddb.put_item.side_effect = denied
        sts.get_caller_identity.return_value = {"Arn": "arn:aws:sts::123456789012:assumed-role/coordinator/session"}
        with tempfile.TemporaryDirectory() as directory, patch("pcfl.service_runtime.sdk_clients", return_value=(ddb, s3)), patch("boto3.client", return_value=sts):
            result = probe_access({**config, "runtime_directory": directory})
        self.assertEqual(result["role_kind"], "coordinator")
        self.assertNotIn("org_id", result)
        self.assertEqual(result["own_metadata_sha256"], reference["sha256"])
        self.assertEqual(ddb.put_item.call_args.kwargs["Item"]["PK"], {"S": "POLICY#org_01"})
        with patch("pcfl.service_runtime.sdk_clients") as sdk, self.assertRaises(ValueError):
            probe_access({**config, "storage": {**storage, "local_emulation": True}})
        sdk.assert_not_called()

    def test_opa_command_requires_bundled_hash_tls_authentication_and_api_authorization(self):
        policy = Path(__file__).resolve().parents[1] / "policies/rego"
        config = {"tls_files": {"ca_cert": "ca", "server_cert": "cert", "server_key": "key"},
                  "policy_directory": str(policy), "rule_hash": hashlib.sha256((policy / "pcfl.rego").read_bytes()).hexdigest()}
        command = opa_command(config)
        self.assertIn("--authentication=tls", command)
        self.assertIn("--authorization=basic", command)
        self.assertIn("--addr=https://0.0.0.0:8443", command)
        self.assertTrue(command[-1].endswith("api_authz.rego"))
        with self.assertRaises(ValueError):
            opa_command({**config, "rule_hash": "0" * 64})

    def test_final_holdout_is_rejected_before_sdk_or_data_access(self):
        with patch("pcfl.service_runtime.sdk_clients") as sdk:
            for config in ({"dataset_role": "test"}, {"confirmatory": True}):
                with self.assertRaises(ValueError):
                    serve_evaluation(config)
            sdk.assert_not_called()

    def test_seed_repetitions_change_initial_parameters_but_preserve_frozen_model_schema(self):
        metadata = build_model_metadata(preprocessor())
        first = create_model_from_metadata(metadata, seed_override=296)
        second = create_model_from_metadata(metadata, seed_override=593)
        self.assertEqual(first.schema_hash, second.schema_hash)
        self.assertTrue(any(not np.array_equal(left, right) for left, right in
                            zip(learning.get_parameters(first), learning.get_parameters(second), strict=True)))
        with self.assertRaises(ValueError):
            create_model_from_metadata(metadata, seed_override=True)


if __name__ == "__main__":
    unittest.main()
