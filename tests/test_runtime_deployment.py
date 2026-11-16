import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("runtime_generator", "infra/runtime/generate.py")
entrypoint = load("container_entrypoint", "containers/entrypoint.py")
builder = load("container_builder", "containers/build.py")


def fixture():
    # Synthetic metadata only; these are not real images, roles, keys or approval.
    account, region = "123456789012", "us-east-1"
    role = lambda name: f"arn:aws:iam::{account}:role/pcfl-{name}"
    secret = lambda name: f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-abcdef"
    foundation = {"bucket_name": f"pcfl-research-{account}-{region}",
                  "client_task_role_arns": {org: role(org) for org in generator.ORGANIZATIONS},
                  "service_task_role_arns": {"coordinator": role("coordinator")},
                  "task_execution_role_arn": role("execution")}
    config = {"account_id": account, "region": region,
              "budget": {"approved_total_usd": 10, "estimated_total_usd": 1, "authorization_scope": "eight-client-runtime-smoke"},
              "superlink_hostname": "superlink.pcfl.internal", "governance_endpoint": "https://governance.pcfl.internal",
              "network": {"subnet_ids": ["subnet-0123456789abcdef0"], "client_security_group_id": "sg-0123456789abcdef0",
                          "coordinator_security_group_id": "sg-0123456789abcdef1"},
              "images": {name: f"{account}.dkr.ecr.{region}.amazonaws.com/pcfl/{name}@sha256:" + "a" * 64 for name in ("client", "coordinator")},
              "distribution": "iid", "root_ca_secret_arn": secret("ca"),
              "coordinator_secrets": {"PCFL_SERVER_CERT_PEM": secret("server-cert"), "PCFL_SERVER_KEY_PEM": secret("server-key"),
                                      "PCFL_RUNTIME_CONFIG_JSON": secret("server-config")}, "clients": []}
    for number, org in enumerate(generator.ORGANIZATIONS, 1):
        obj = lambda filename: {"key": f"partitions/iid/{org}/{filename}", "version_id": f"immutable-v{number}", "sha256": "b" * 64}
        config["clients"].append({"org_id": org, "partition": obj("train.csv"), "preprocessor": obj("preprocessor.json"),
                                  "auth_secret_arn": secret(org), "registered_node_id": number,
                                  "public_key_sha256": f"{number:064x}"})
    return config, foundation


def complete_fixture():
    config, foundation = fixture()
    account, region = config["account_id"], config["region"]
    foundation["state_table_name"] = "pcfl-research-state"
    foundation["service_task_role_arns"].update({name: f"arn:aws:iam::{account}:role/pcfl-{name}" for name in ("governance", "opa", "evaluator", "operator")})
    names = [*generator.ORGANIZATIONS, "coordinator", *generator.SERVICE_ROLES, "operator"]
    config["network"] = {"subnet_ids": ["subnet-0123456789abcdef0"],
        "security_group_ids": {name: "sg-" + f"{number:017x}" for number, name in enumerate(names, 1)}}
    config["services"] = {name: {"image": config["images"]["coordinator"], "secrets": {
        "PCFL_" + name.upper() + "_CONFIG_JSON": f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-config-abcdef"}} for name in generator.SERVICE_ROLES}
    config["operator"] = {"image": config["images"]["coordinator"], "secrets": {
        "PCFL_OPERATOR_CONFIG_JSON": f"arn:aws:secretsmanager:{region}:{account}:secret:operator-config-abcdef"}}
    config["opa_endpoint"] = "https://opa.pcfl.internal:8443"
    config["evaluation_endpoint"] = "https://evaluation.pcfl.internal:8443"
    config["evaluation_objects"] = {split: {"key": f"evaluation/frozen/{split}.csv", "version_id": "frozen-v1", "sha256": "e" * 64} for split in ("validation", "test")}
    config["model_metadata_object"] = {"key": "metadata/schema.json", "version_id": "metadata-v1", "sha256": "f" * 64}
    return config, foundation


class RuntimeDeploymentTests(unittest.TestCase):
    def test_eight_separate_client_tasks_have_distinct_roles_and_own_versioned_data(self):
        config, foundation = fixture()
        plan = generator.build_plan(config, foundation)
        self.assertEqual(set(plan["task_definitions"]), set(generator.ORGANIZATIONS) | {"coordinator"})
        self.assertEqual(len({task["taskRoleArn"] for task in plan["task_definitions"].values()}), 9)
        for org in generator.ORGANIZATIONS:
            task = plan["task_definitions"][org]
            self.assertEqual(task["requiresCompatibilities"], ["FARGATE"])
            self.assertEqual(task["networkMode"], "awsvpc")
            self.assertEqual(len(task["containerDefinitions"]), 1)
            container = task["containerDefinitions"][0]
            self.assertTrue(container["readonlyRootFilesystem"])
            self.assertEqual(container["portMappings"], [])
            env = {item["name"]: item["value"] for item in container["environment"]}
            self.assertIn(f"/{org}/", env["PCFL_DATA_KEY"])
            self.assertIn(f"/{org}/", env["PCFL_PREPROCESSOR_KEY"])
            self.assertNotIn("holdout", json.dumps(container))
            self.assertTrue(env["PCFL_DATA_VERSION_ID"])
        self.assertTrue(all(item["count"] == 1 for item in plan["run_task_templates"]))
        self.assertTrue(all(item["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"] == "DISABLED"
                            for item in plan["run_task_templates"]))

    def test_keys_are_secret_references_and_internal_appio_is_not_exposed(self):
        config, foundation = fixture()
        plan = generator.build_plan(config, foundation)
        for name, task in plan["task_definitions"].items():
            container = task["containerDefinitions"][0]
            self.assertTrue(all(item["valueFrom"].startswith("arn:aws:secretsmanager:") for item in container["secrets"]))
            self.assertFalse(any("PRIVATE_KEY" in item["name"] or "SERVER_KEY" in item["name"] for item in container["environment"]))
            self.assertFalse({9091, 9094} & {item["containerPort"] for item in container["portMappings"]})
        resources = plan["execution_role_supplement"]["Statement"][0]["Resource"]
        self.assertEqual(len(resources), 12)
        self.assertNotIn("*", resources)

    def test_readiness_flags_cannot_supply_missing_service_inputs_or_cloud_evidence(self):
        config, foundation = fixture()
        initial = generator.build_plan(config, foundation)
        config["readiness"] = {key: True for key in initial["required_readiness_checks"]}
        plan = generator.build_plan(config, foundation)
        self.assertFalse(plan["deployable"])
        self.assertIn("supporting_service_inputs_required", plan["blockers"])
        self.assertIn("per_task_private_network_contract_required", plan["blockers"])
        self.assertFalse(plan["cloud_validation_complete"])
        self.assertEqual(set(plan["service_contracts"]), {"governance", "opa", "evaluation"})
        self.assertTrue(all(contract["rendered"] is False for contract in plan["service_contracts"].values()))
        self.assertEqual(plan["service_contracts"]["opa"]["required_data_access"], [])
        self.assertNotIn("artifact_missing_integrated_production_dynamodb_opa_training_adapter", plan["blockers"])

    def test_complete_service_contract_renders_separate_tasks_and_access_probes(self):
        config, foundation = complete_fixture()
        plan = generator.build_plan(config, foundation)
        self.assertEqual(len(plan["task_definitions"]), 13)
        for name in ("governance", "opa", "evaluation", "operator"):
            container = plan["task_definitions"][name]["containerDefinitions"][0]
            self.assertEqual(container["command"], [name])
            self.assertEqual([secret["name"] for secret in container["secrets"]], ["PCFL_" + name.upper() + "_CONFIG_JSON"])
            self.assertFalse(any("CONFIG_JSON" in item["name"] for item in container["environment"]))
            env = {item["name"]: item["value"] for item in container["environment"]}
            self.assertEqual(env["AWS_STS_REGIONAL_ENDPOINTS"], "regional")
        self.assertTrue(all(contract["rendered"] for contract in plan["service_contracts"].values()))
        self.assertEqual(len(plan["client_access_probe_templates"]), 8)
        for probe in plan["client_access_probe_templates"]:
            override = probe["overrides"]["containerOverrides"][0]
            settings = json.loads(override["environment"][0]["value"])
            self.assertEqual(override["command"], ["operator"])
            self.assertEqual(settings["expected_task_role_arn"], foundation["client_task_role_arns"][settings["org_id"]])
            self.assertEqual(len(settings["denied_objects"]), 9)
            self.assertTrue(all("/" + settings["org_id"] + "/" not in item["key"] for item in settings["denied_objects"]))

    def test_deployment_preflight_can_pass_without_claiming_observed_cloud_validation(self):
        config, foundation = complete_fixture()
        # Pin the renderer artifact inventory to this real test source. Missing
        # input and source checks still run; the test does not fabricate G1.
        with patch.object(generator, "DEPLOYMENT_ARTIFACTS", ("tests/test_runtime_deployment.py",)), \
             patch.object(generator, "_validation_reports", return_value={"infrastructure": True, "container": True}):
            required = generator.build_plan(config, foundation)["required_readiness_checks"]
            config["readiness"] = {name: True for name in required}
            plan = generator.build_plan(config, foundation)
        self.assertTrue(plan["deployment_preflight_ready"])
        self.assertTrue(plan["deployable"])
        self.assertFalse(plan["cloud_validation_complete"])
        with tempfile.TemporaryDirectory() as folder, patch.object(generator, "ROOT", Path(folder)):
            missing = generator.build_plan(config, foundation)
        self.assertFalse(missing["deployable"])
        self.assertTrue(any(blocker.startswith("artifact_missing:") for blocker in missing["blockers"]))

    def test_optional_anchor_probe_binds_existing_version_for_all_application_roles(self):
        config, foundation = complete_fixture()
        reference = {"bucket": foundation["bucket_name"], "key": "anchors/campaign-one/cell/witness.json", "version_id": "witness-v1", "sha256": "a" * 64}
        config["protected_anchor_object"] = reference
        plan = generator.build_plan(config, foundation)
        for probe in [*plan["client_access_probe_templates"], plan["coordinator_access_probe_template"]]:
            settings = json.loads(probe["overrides"]["containerOverrides"][0]["environment"][0]["value"])
            self.assertEqual(settings["protected_anchor_object"], reference)
            self.assertEqual(probe["expected"]["protected_anchor_write"], "AccessDenied")
        for change in ({"bucket": "unrelated"}, {"key": "evidence/witness.json"}, {"key": "anchors/campaign-one/../escape.json"}, {"version_id": "null"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "pinned_protected_anchor"):
                generator.build_plan({**config, "protected_anchor_object": {**reference, **change}}, foundation)
    def test_service_identity_and_secret_reuse_is_rejected(self):
        for field in ("same_role", "same_secret", "plaintext_opa", "shared_security_group"):
            config, foundation = complete_fixture()
            if field == "same_role": foundation["service_task_role_arns"]["opa"] = foundation["service_task_role_arns"]["governance"]
            if field == "same_secret": config["services"]["opa"]["secrets"]["PCFL_OPA_CONFIG_JSON"] = config["services"]["governance"]["secrets"]["PCFL_GOVERNANCE_CONFIG_JSON"]
            if field == "plaintext_opa": config["opa_endpoint"] = "http://opa.pcfl.internal:8443"
            if field == "shared_security_group": config["network"]["security_group_ids"]["opa"] = config["network"]["security_group_ids"]["governance"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                generator.build_plan(config, foundation)

    def test_supervisor_registration_does_not_require_invented_node_ids(self):
        config, foundation = complete_fixture()
        config["registration_mode"] = "coordinator-supervisor"
        for client in config["clients"]:
            client["registered_node_id"] = None
        plan = generator.build_plan(config, foundation)
        self.assertTrue(all(binding["node_id"] is None for binding in plan["registered_node_bindings"].values()))
        self.assertFalse(plan["cloud_validation_complete"])

    def test_validation_report_bytes_and_source_are_bound_and_stale_reports_fail(self):
        import hashlib
        source = "tests/test_runtime_deployment.py"
        current = hashlib.sha256((ROOT / source).read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "validation.json"
            path.write_text(json.dumps({"successful": True, "source_sha256": {source: current}}), encoding="utf-8")
            binding = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertTrue(generator._validation_reports({"infrastructure": binding}, {source: current})["infrastructure"])
            self.assertFalse(generator._validation_reports({"infrastructure": binding}, {source: "0" * 64})["infrastructure"])
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                generator._validation_reports({"infrastructure": binding}, {source: current})

    def test_mutable_images_wrong_account_and_plaintext_governance_are_rejected(self):
        for field in ("mutable_image", "wrong_image_account", "wrong_role_account", "plain_governance", "old_smoke_budget", "infinite_budget"):
            config, foundation = fixture()
            if field == "mutable_image": config["images"]["client"] = "runtime:latest"
            if field == "wrong_image_account": config["images"]["client"] = config["images"]["client"].replace("123456789012", "999999999999")
            if field == "wrong_role_account": foundation["client_task_role_arns"]["org_01"] = "arn:aws:iam::999999999999:role/client"
            if field == "plain_governance": config["governance_endpoint"] = "http://governance.internal"
            if field == "old_smoke_budget": config["budget"]["authorization_scope"] = "first-smoke-test-total"
            if field == "infinite_budget": config["budget"]["approved_total_usd"] = float("inf")
            with self.subTest(field=field), self.assertRaises(ValueError):
                generator.build_plan(config, foundation)

    def test_cross_organization_data_duplicate_roles_or_identity_keys_are_rejected(self):
        for field in ("cross_data", "shared_role", "shared_key", "shared_node", "shared_public", "unversioned"):
            config, foundation = fixture()
            if field == "cross_data": config["clients"][0]["partition"]["key"] = "partitions/iid/org_02/train.csv"
            if field == "shared_role": foundation["client_task_role_arns"]["org_02"] = foundation["client_task_role_arns"]["org_01"]
            if field == "shared_key": config["clients"][1]["auth_secret_arn"] = config["clients"][0]["auth_secret_arn"]
            if field == "shared_node": config["clients"][1]["registered_node_id"] = config["clients"][0]["registered_node_id"]
            if field == "shared_public": config["clients"][1]["public_key_sha256"] = config["clients"][0]["public_key_sha256"]
            if field == "unversioned": config["clients"][0]["partition"]["version_id"] = "null"
            with self.subTest(field=field), self.assertRaises(ValueError):
                generator.build_plan(config, foundation)

    def test_coordinator_command_requires_tls_auth_and_removes_raw_secret_environment(self):
        env = {"PCFL_ROOT_CA_PEM": "synthetic-test-ca", "PCFL_SERVER_CERT_PEM": "synthetic-test-cert",
               "PCFL_SERVER_KEY_PEM": "synthetic-test-key", "PCFL_RUNTIME_CONFIG_JSON": "{}"}
        with tempfile.TemporaryDirectory() as folder, patch.object(entrypoint, "RUNTIME", Path(folder)):
            command = entrypoint.build_command("coordinator", env)
            self.assertNotIn("--insecure", command)
            self.assertIn("--enable-supernode-auth", command)
            self.assertIn("127.0.0.1:9091", command)
            self.assertTrue(all(name not in env for name in ("PCFL_ROOT_CA_PEM", "PCFL_SERVER_KEY_PEM", "PCFL_RUNTIME_CONFIG_JSON")))
            self.assertTrue(Path(env["PCFL_RUNTIME_CONFIG"]).is_file())

    def test_versioned_s3_fetch_checks_owner_digest_and_never_writes_bad_bytes(self):
        client = Mock()
        content = b"synthetic features only"
        digest = __import__("hashlib").sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            client.get_object.return_value = {"VersionId": "v1", "ContentLength": len(content), "Body": io.BytesIO(content)}
            destination = Path(folder) / "good.csv"
            entrypoint.fetch_verified(client, bucket="test", key="partitions/iid/org_01/train.csv", version_id="v1",
                                      checksum=digest, owner="123456789012", destination=destination)
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(client.get_object.call_args.kwargs["ExpectedBucketOwner"], "123456789012")
            client.get_object.return_value = {"VersionId": "v1", "ContentLength": len(content), "Body": io.BytesIO(content)}
            bad = Path(folder) / "bad.csv"
            with self.assertRaises(ValueError):
                entrypoint.fetch_verified(client, bucket="test", key="key", version_id="v1", checksum="0" * 64,
                                          owner="123456789012", destination=bad)
            self.assertFalse(bad.exists())

    def test_client_bootstrap_uses_openssh_p384_and_rejects_pkcs8_before_s3(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP384R1())
        ssh = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
        pkcs8 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
        data, preprocessing = b"synthetic,y\n0,0\n", b"{}"
        import hashlib
        env = {"PCFL_ORG_ID": "org_01", "PCFL_ROOT_CA_PEM": "synthetic-test-ca", "PCFL_NODE_PRIVATE_KEY_PEM": ssh,
               "PCFL_AWS_ACCOUNT_ID": "123456789012", "AWS_REGION": "us-east-1", "PCFL_DATA_BUCKET": "synthetic-bucket",
               "PCFL_SUPERLINK_ADDRESS": "superlink.pcfl.internal:9092"}
        for kind, filename, content in (("DATA", "train.csv", data), ("PREPROCESSOR", "preprocessor.json", preprocessing)):
            env[f"PCFL_{kind}_KEY"] = f"partitions/iid/org_01/{filename}"
            env[f"PCFL_{kind}_VERSION_ID"] = "v1"
            env[f"PCFL_{kind}_SHA256"] = hashlib.sha256(content).hexdigest()
        fake_boto = Mock()
        fake_boto.client.return_value.get_object.side_effect = [
            {"VersionId": "v1", "ContentLength": len(content), "Body": io.BytesIO(content)} for content in (data, preprocessing)]
        with tempfile.TemporaryDirectory() as folder, patch.object(entrypoint, "RUNTIME", Path(folder)), \
                patch.dict("sys.modules", {"boto3": fake_boto}):
            command = entrypoint.build_command("client", env.copy())
            self.assertIn("flower-supernode", command)
            self.assertIn("--auth-supernode-private-key", command)
            self.assertIn("127.0.0.1:9094", command)
            self.assertEqual(fake_boto.client.return_value.get_object.call_count, 2)
        fake_boto.reset_mock()
        with tempfile.TemporaryDirectory() as folder, patch.object(entrypoint, "RUNTIME", Path(folder)), \
                patch.dict("sys.modules", {"boto3": fake_boto}), self.assertRaises(ValueError):
            entrypoint.build_command("client", {**env, "PCFL_NODE_PRIVATE_KEY_PEM": pkcs8})
        fake_boto.client.assert_not_called()

    def test_allowlisted_build_context_excludes_datasets_credentials_results_and_tools(self):
        with tarfile.open(fileobj=io.BytesIO(builder.context_bytes()), mode="r:gz") as archive:
            names = archive.getnames()
        self.assertIn("containers/requirements-linux.lock", names)
        self.assertTrue(any(name.startswith("src/pcfl/") for name in names))
        for name in names:
            self.assertFalse(name.startswith(("data/", "results/", ".aws/", ".tools/", ".venv")))
            self.assertNotIn("patient", name)


if __name__ == "__main__":
    unittest.main()
