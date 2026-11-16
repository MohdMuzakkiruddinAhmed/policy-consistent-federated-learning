"""Endpoint and credential isolation checks; these tests never contact AWS."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from pcfl.service_io import sdk_clients, service_identities


HAS_BOTO = importlib.util.find_spec("boto3") is not None
HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
LOCAL = {"local_emulation": True, "region": "us-east-1",
         "dynamodb_endpoint": "http://127.0.0.1:49120", "s3_endpoint": "http://localhost:49121"}


@unittest.skipUnless(HAS_BOTO, "boto3 is installed in the pinned runtime")
class SdkIsolationTests(unittest.TestCase):
    def test_local_clients_use_only_explicit_dummy_credentials_and_endpoints(self):
        # Conflicting environment credentials/endpoints must not reach either client.
        environment = {"AWS_ACCESS_KEY_ID": "environment-real-key", "AWS_SECRET_ACCESS_KEY": "environment-real-secret",
                       "AWS_SESSION_TOKEN": "environment-real-token", "AWS_ENDPOINT_URL": "https://example.invalid"}
        with patch.dict(os.environ, environment):
            clients = sdk_clients(LOCAL)
        for client, endpoint in zip(clients, (LOCAL["dynamodb_endpoint"], LOCAL["s3_endpoint"])):
            credentials = client._request_signer._credentials
            self.assertEqual(credentials.access_key, "pcfllocal")
            self.assertEqual(credentials.secret_key, "pcfl-local-test-only")
            self.assertIsNone(credentials.token)
            self.assertEqual(client.meta.endpoint_url, endpoint)
            self.assertEqual(client.meta.config.connect_timeout, 3)
            self.assertEqual(client.meta.config.read_timeout, 5)
            self.assertEqual(client.meta.config.retries["total_max_attempts"], 1)
            client.close()

    def test_local_endpoint_validation_precedes_client_creation(self):
        bad = [None, "https://127.0.0.1:1", "http://example.com:1", "http://localhost.evil:1",
               "http://user:password@localhost:1", "http://localhost:1/prefix", "http://localhost:1?q=x",
               "http://localhost:1#fragment", "http://localhost", "http://localhost:99999"]
        for endpoint in bad:
            with self.subTest(endpoint=endpoint), patch("boto3.client") as create:
                config = {**LOCAL, "dynamodb_endpoint": endpoint}
                with self.assertRaises(ValueError):
                    sdk_clients(config)
                create.assert_not_called()

    def test_production_requires_expected_account_and_disallows_overrides(self):
        configs = [{}, {"expected_account_id": "123"},
                   {"expected_account_id": "980322232249", "dynamodb_endpoint": LOCAL["dynamodb_endpoint"]},
                   {"expected_account_id": "980322232249", "access_key": "provided"},
                   {"expected_account_id": "980322232249", "secret_key": "provided"}]
        for config in configs:
            with self.subTest(config=config), patch("boto3.client") as create:
                with self.assertRaises(ValueError):
                    sdk_clients(config)
                create.assert_not_called()

    def test_production_account_mismatch_stops_before_storage_clients(self):
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "111111111111"}
        with patch("boto3.client", return_value=sts) as create:
            with self.assertRaisesRegex(ValueError, "aws_account_mismatch"):
                sdk_clients({"expected_account_id": "980322232249"})
        self.assertEqual([call.args[0] for call in create.call_args_list], ["sts"])

    def test_production_checks_sts_before_using_standard_service_endpoints(self):
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "980322232249"}
        with patch("boto3.client", side_effect=[sts, MagicMock(), MagicMock()]) as create:
            sdk_clients({"expected_account_id": "980322232249", "region": "us-east-1"})
        self.assertEqual([call.args[0] for call in create.call_args_list], ["sts", "dynamodb", "s3"])
        for call in create.call_args_list:
            self.assertTrue(call.kwargs["config"].ignore_configured_endpoint_urls)
            self.assertNotIn("aws_access_key_id", call.kwargs)
            self.assertNotIn("aws_secret_access_key", call.kwargs)
            self.assertIsNone(call.kwargs.get("endpoint_url"))


@unittest.skipUnless(HAS_CRYPTO, "cryptography is installed in the pinned runtime")
class ServiceIdentityTests(unittest.TestCase):
    def test_ephemeral_ca_has_distinct_server_and_client_identity_purposes(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        with tempfile.TemporaryDirectory() as directory:
            identities = service_identities(directory)
            ca = x509.load_pem_x509_certificate(Path(identities["ca"]).read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertFalse((Path(directory) / "ca.key").exists())
            for role in ("governance", "evaluation", "coordinator", "policy-operator"):
                certificate = x509.load_pem_x509_certificate(Path(identities[role]["cert"]).read_bytes())
                self.assertEqual(certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "pcfl-" + role)
                eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                expected = ExtendedKeyUsageOID.SERVER_AUTH if role in {"governance", "evaluation"} else ExtendedKeyUsageOID.CLIENT_AUTH
                self.assertEqual(list(eku), [expected])
                self.assertFalse(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                self.assertTrue(Path(identities[role]["key"]).is_file())
                if expected == ExtendedKeyUsageOID.SERVER_AUTH:
                    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    self.assertIn("localhost", sans.get_values_for_type(x509.DNSName))
