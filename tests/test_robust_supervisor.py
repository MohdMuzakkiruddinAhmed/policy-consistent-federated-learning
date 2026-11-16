"""Additive supervisor preflight uses registered public metadata before SDK/Popen."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_robustness import ROOT, registry_fixture
sys.path.append(str(ROOT / "tests"))
from test_cloud_coordinator import CloudCoordinatorTests
from pcfl import robust_cloud_coordinator as cloud
from pcfl.opa import policy_hash
from pcfl.robust_host import public_documents
from pcfl.robustness import deployment_inputs


class AdditiveSupervisorTests(unittest.TestCase):
    def fixture(self):
        CloudCoordinatorTests.setUpClass()
        registry = registry_fixture()
        group = deployment_inputs(registry, {"authority_backend": "dynamodb-s3-opa", "baseline_id": "P1", "table_name": "pcfl-state",
            "bucket": "pcfl-models", "opa": {"endpoint": "https://opa.invalid:8443", "expected_rule_hash": policy_hash()},
            "evaluator": {"endpoint": "https://evaluation.invalid:8443"}})["groups"][0]
        document = public_documents(registry, group)["campaign"]
        return {**document, "storage": {"expected_account_id": "980322232249", "region": "us-east-1"}, "bucket": "pcfl-models",
            "node_public_keys": deepcopy(CloudCoordinatorTests.keys), "service_tls": {
                "ca_pem": "synthetic-ca", "client_cert_pem": "synthetic-cert", "client_key_pem": "synthetic-key"}}

    def test_whole_registered_group_passes_public_preflight_and_FAB_names_only_additive_app(self):
        cloud._preflight(self.fixture(), require_cases=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; destination = root / "bundle"
            source.mkdir(); destination.mkdir(); (source / "empty.py").write_text("# synthetic")
            cloud.transport_app(source, destination)
            pyproject = (destination / "pyproject.toml").read_text()
            self.assertIn("pcfl.robust_flower_app:server_app", pyproject)
            self.assertIn("pcfl.robust_flower_client:client_app", pyproject)

    def test_main_family_wrong_source_or_holdout_never_reaches_sdk_or_process(self):
        for fault in ("source", "family", "test", "duplicate"):
            config = self.fixture()
            if fault == "source": config["cases"][0]["runtime"]["robustness"]["adapter_source_sha256"] = "0" * 64
            elif fault == "family": config["cases"][0]["runtime"]["experiment_binding"]["family"] = "primary"
            elif fault == "test": config["cases"][0]["runtime"]["final_holdout"] = {}
            else: config["cases"].append(deepcopy(config["cases"][0]))
            with self.subTest(fault=fault), patch.object(cloud, "sdk_clients") as sdk, patch.object(cloud.subprocess, "Popen") as popen:
                with self.assertRaises(ValueError): cloud.supervise(config, ca="missing", certificate="missing", private_key="missing")
                sdk.assert_not_called(); popen.assert_not_called()


if __name__ == "__main__": unittest.main()
