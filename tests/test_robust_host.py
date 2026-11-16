"""Private actor input binding with synthetic immutable upload inventories."""
from copy import deepcopy
import hashlib
import unittest

from test_robustness import registry_fixture
from pcfl.contracts import ORGANIZATIONS
from pcfl.robustness import deployment_inputs
from pcfl.robust_host import bind_group, document_bytes, public_documents


class ActorBindingTests(unittest.TestCase):
    def fixture(self):
        registry = registry_fixture()
        group = deployment_inputs(registry, {"baseline_id": "P1", "authority_backend": "dynamodb-s3-opa", "opa": {}, "evaluator": {}})["groups"][-1]
        docs = public_documents(registry, group)
        bucket = "pcfl-980322232249-synthetic"
        uploads = []
        def ref(key, sha):
            item = {"bucket": bucket, "key": key, "version_id": "actual-synthetic-version-" + str(len(uploads)), "sha256": sha}
            uploads.append(item); return item
        for kind in ("campaign", "policy", "model"):
            ref(docs[kind + "_key"], hashlib.sha256(document_bytes(docs[kind])).hexdigest())
        shared = next(c for c in registry["cases"] if c["case_id"] == group["cases"][0]["cell_id"])["shared_config"]
        for org in ORGANIZATIONS:
            ref(f"partitions/{group['distribution']}/{org}/train.csv", group["partition_hashes"][org])
            ref(f"partitions/{group['distribution']}/{org}/preprocessor.json", shared["preprocessor_sha256"])
        ref("evaluation/frozen/validation.csv", shared["validation_sha256"])
        runtime = {"account_id": "980322232249", "images": {"client": "old", "coordinator": "old"},
            "services": {name: {"image": "old", "secrets": {"role": name}} for name in ("governance", "opa", "evaluation")},
            "clients": [{"org_id": org, "auth_secret_arn": "synthetic-auth-" + org, "registered_node_id": 10} for org in ORGANIZATIONS],
            "evaluation_objects": {"test": {"key": "evaluation/frozen/test.csv", "sha256": "a" * 64, "version_id": "locked"}}}
        roles = {"coordinator": {"bucket": bucket, "service_tls": {"client_key_pem": "synthetic-private-key"}},
            "governance": {"tls": {"server_key_pem": "synthetic-governance-key"}}, "evaluation": {"dataset_role": "validation"}, "opa": {}}
        reports = {name: {"path": name + "-future.json", "sha256": "c" * 64} for name in ("infrastructure", "container")}
        return registry, group, runtime, roles, uploads, reports

    def test_exact_owner_version_data_architecture_and_private_roles_bound_without_credential_mixing(self):
        registry, group, runtime, roles, uploads, reports = self.fixture()
        result = bind_group(registry, group, runtime, roles, uploads, validation_reports=reports)
        private, bound = result["private_role_configs"], result["runtime_input"]
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(private["evaluation"]["model_metadata"], group["evaluation_override"]["model_metadata"])
        self.assertEqual(private["evaluation"]["dataset_role"], "validation")
        self.assertNotIn("test_object", private["evaluation"])
        self.assertEqual(bound["evaluation_objects"]["test"], runtime["evaluation_objects"]["test"])
        self.assertEqual(private["coordinator"]["service_tls"], roles["coordinator"]["service_tls"])
        self.assertNotIn("service_tls", bound)
        self.assertEqual({c["partition"]["sha256"] for c in bound["clients"]}, set(group["partition_hashes"].values()))
        self.assertTrue(all(c["registered_node_id"] is None for c in bound["clients"]))
        self.assertEqual(len(set(c["auth_secret_arn"] for c in bound["clients"])), 8)
        self.assertEqual(len(set(bound["images"].values()) | {s["image"] for s in bound["services"].values()}), 1)

    def test_wrong_version_duplicate_inventory_changed_budget_and_holdout_rejected(self):
        for mode in ("version", "duplicate", "training", "holdout", "foreign-client", "rebound-schedule"):
            registry, group, runtime, roles, uploads, reports = self.fixture()
            if mode == "version": uploads[0]["version_id"] = "null"
            elif mode == "duplicate": uploads.append(deepcopy(uploads[0]))
            elif mode == "training": group["cases"][0]["runtime"]["rounds"] = 1
            elif mode == "holdout": roles["evaluation"]["authorization_object"] = {}
            elif mode == "foreign-client": runtime["clients"][-1]["org_id"] = "org_01"
            else: group["cases"][0]["runtime"]["experiment_binding"]["policy_schedule_hash"] = "0" * 64
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                bind_group(registry, group, runtime, roles, uploads, validation_reports=reports)


if __name__ == "__main__": unittest.main()
