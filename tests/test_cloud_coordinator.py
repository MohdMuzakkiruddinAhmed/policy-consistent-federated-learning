"""Private supervisor binding, deadline and evidence-retention boundaries."""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pcfl import cloud_coordinator as cloud
from pcfl.contracts import ORGANIZATIONS
from pcfl.evaluation import build_model_metadata
from test_evaluation import preprocessor


class RecordingS3:
    def __init__(self):
        self.puts, self.gets, self.objects = [], [], {}
        self.fail = lambda key: False
        self.corrupt = False

    def put_object(self, **request):
        self.puts.append(deepcopy(request))
        if self.fail(request["Key"]):
            raise OSError("synthetic_export_failure")
        version = f"version-{len(self.puts)}"
        self.objects[(request["Key"], version)] = request["Body"]
        return {"VersionId": version}

    def get_object(self, **request):
        self.gets.append(deepcopy(request))
        content = self.objects[(request["Key"], request["VersionId"])]
        return {"VersionId": request["VersionId"], "ContentLength": len(content),
                "Body": io.BytesIO(b"corrupt" if self.corrupt else content)}


class FakeClock:
    def __init__(self):
        self.value = 0.0
    def now(self):
        return self.value
    def sleep(self, seconds):
        self.value += seconds


class CloudCoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {org: ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() for org in ORGANIZATIONS}
        cls.metadata = build_model_metadata(preprocessor(), hidden_dims=(4,))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ca = self.root / "ca.pem"
        self.ca.write_text("synthetic-ca")

    def config(self, count=1):
        runtime = {"authority_backend": "dynamodb-s3-opa", "baseline_id": "P1", "scenario_id": "S0", "rounds": 1,
            "seed": 296, "model_metadata": deepcopy(self.metadata), "validation_source_sha256": "a" * 64,
            "table_name": "pcfl-state", "bucket": "pcfl-models", "opa": {"endpoint": "https://opa:8443", "expected_rule_hash": "b" * 64},
            "evaluator": {"endpoint": "https://evaluation:8443"}}
        return {"campaign_id": "campaign-01", "runtime_directory": str(self.root / "runtime"), "task_deadline_seconds": 60,
            "bucket": "pcfl-models", "storage": {"local_emulation": True, "expected_account_id": "123456789012"},
            "node_public_keys": deepcopy(self.keys), "service_tls": {"ca_pem": "synthetic-ca", "client_cert_pem": "synthetic-cert", "client_key_pem": "synthetic-key"},
            "cases": [{"cell_id": f"cell-{i}", "runtime": {**deepcopy(runtime), "persistent_run_id": f"run-{i}"}} for i in range(count)]}

    @contextmanager
    def boundaries(self, config, run=None, clock=None, s3=None):
        s3 = s3 or RecordingS3()
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        channel = Mock()
        def ordinary_run(*_, **kwargs):
            active = json.loads(Path(kwargs["env"]["PCFL_RUNTIME_CONFIG"]).read_text())
            cloud.json_file(Path(active["output_dir"]) / "runtime_result.json", {"successful": True})
            return SimpleNamespace(stdout="synthetic CLI\n", stderr="", returncode=0)
        def prepare_app(_, destination):
            destination.mkdir(parents=True)
        with ExitStack() as stack:
            state = SimpleNamespace(s3=s3, process=process, channel=channel)
            state.sdk = stack.enter_context(patch.object(cloud, "sdk_clients", return_value=(Mock(), s3)))
            state.popen = stack.enter_context(patch.object(cloud.subprocess, "Popen", return_value=process))
            state.run = stack.enter_context(patch.object(cloud.subprocess, "run", side_effect=run or ordinary_run))
            stack.enter_context(patch.object(cloud, "transport_app", side_effect=prepare_app))
            stack.enter_context(patch("grpc.secure_channel", return_value=channel))
            stack.enter_context(patch("grpc.ssl_channel_credentials", return_value=object()))
            stack.enter_context(patch("grpc.channel_ready_future", return_value=Mock()))
            stack.enter_context(patch("flwr.proto.control_pb2_grpc.ControlStub", return_value=Mock()))
            stack.enter_context(patch.object(cloud, "register_nodes", return_value={str(i): org for i, org in enumerate(ORGANIZATIONS, 1)}))
            stack.enter_context(patch.object(cloud, "wait_online"))
            if clock:
                stack.enter_context(patch.object(cloud.time, "monotonic", side_effect=clock.now))
                stack.enter_context(patch.object(cloud.time, "sleep", side_effect=clock.sleep))
            yield state

    def supervise(self, config):
        return cloud.supervise(config, ca=self.ca, certificate=self.ca, private_key=self.ca)

    def test_registration_binds_wire_public_keys_and_rejects_bad_fleet_before_registration(self):
        from flwr.supercore.primitives.asymmetric import public_key_to_bytes
        stub = Mock()
        stub.RegisterNode.side_effect = [SimpleNamespace(node_id=number) for number in range(1, 9)]
        registry = cloud.register_nodes(stub, self.keys)
        self.assertEqual(registry, {str(i): org for i, org in enumerate(ORGANIZATIONS, 1)})
        for org, call in zip(ORGANIZATIONS, stub.RegisterNode.call_args_list, strict=True):
            key = serialization.load_ssh_public_key(self.keys[org].encode())
            self.assertEqual(call.args[0].public_key, public_key_to_bytes(key))
        wrong_curve = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        for replacement in (self.keys["org_01"], wrong_curve, "not a key"):
            invalid = {**self.keys, "org_08": replacement}
            with self.subTest(replacement=replacement[:16]), self.assertRaises(ValueError):
                other = Mock()
                cloud.register_nodes(other, invalid)
            other.RegisterNode.assert_not_called()
        duplicate = Mock()
        duplicate.RegisterNode.return_value = SimpleNamespace(node_id=1)
        with self.assertRaisesRegex(ValueError, "registration_not_unique"):
            cloud.register_nodes(duplicate, self.keys)

    def test_wait_online_requires_exact_authenticated_set_and_respects_remaining_rpc_budget(self):
        clock, stub, process = FakeClock(), Mock(), Mock()
        process.poll.return_value = None
        registry = {str(i): org for i, org in enumerate(ORGANIZATIONS, 1)}
        from flwr.proto.control_pb2 import ListNodesResponse
        response = ListNodesResponse(now="1970-01-01T00:00:01+00:00")
        for node_id in range(1, 10):
            response.nodes_info.add(node_id=node_id, online_until=2.0)
        stub.ListNodes.return_value = response
        with patch.object(cloud.time, "monotonic", side_effect=clock.now), patch.object(cloud.time, "sleep", side_effect=clock.sleep):
            with self.assertRaises(TimeoutError):
                cloud.wait_online(stub, registry, process, timeout=.2)
        self.assertLessEqual(stub.ListNodes.call_args.kwargs["timeout"], .2)
        response.nodes_info.pop()
        cloud.wait_online(stub, registry, process, timeout=1)
        response.now = "1970-01-01T00:00:01"
        with self.assertRaisesRegex(ValueError, "requires_timezone"):
            cloud.wait_online(stub, registry, process, timeout=1)
        process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "superlink_exited"):
            cloud.wait_online(stub, registry, process, timeout=1)

    def test_duplicate_bad_metadata_and_private_paths_fail_before_sdk_or_process(self):
        configs = []
        config = self.config(2)
        config["cases"][1]["cell_id"] = config["cases"][0]["cell_id"]
        configs.append(config)
        config = self.config(2)
        config["cases"][1]["runtime"]["persistent_run_id"] = "run-0"
        configs.append(config)
        for field, value in (("data_dir", "private"), ("preprocessor_path", "private.json"), ("validation_path", "private.csv"),
                             ("benchmark_policy_writer", {}), ("model_metadata", {}), ("scenario_id", "unknown")):
            config = self.config()
            config["cases"][0]["runtime"][field] = value
            configs.append(config)
        config = self.config()
        config["cases"][0]["cell_id"] = "../escape"
        configs.append(config)
        for config in configs:
            with self.subTest(config=config["cases"][0]["cell_id"]), self.boundaries(config) as state:
                with self.assertRaises(ValueError):
                    self.supervise(config)
                state.sdk.assert_not_called()
                state.popen.assert_not_called()

    def test_exports_read_back_exact_versions_with_owner_and_detect_corruption(self):
        case = self.root / "case"
        cloud.json_file(case / "runtime_result.json", {"successful": True})
        (case / "private.pem").write_text("must-not-export")
        s3 = RecordingS3()
        records = cloud.export_case(s3, case, bucket="pcfl-models", prefix="evidence/campaigns/one/case", owner="123456789012")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sha256"], hashlib.sha256((case / "runtime_result.json").read_bytes()).hexdigest())
        self.assertEqual(s3.gets[0]["VersionId"], records[0]["version_id"])
        self.assertTrue(all(call["ExpectedBucketOwner"] == "123456789012" for call in s3.puts + s3.gets))
        s3.corrupt = True
        with self.assertRaisesRegex(RuntimeError, "body_mismatch"):
            cloud.export_case(s3, case, bucket="pcfl-models", prefix="evidence/campaigns/two/case", owner="123456789012")

    def test_second_case_timeout_preserves_earlier_export_and_committed_model_record(self):
        config = self.config(2)
        clock = FakeClock()
        calls = []
        def execute(*args, **kwargs):
            calls.append(kwargs["timeout"])
            runtime = json.loads(Path(kwargs["env"]["PCFL_RUNTIME_CONFIG"]).read_text())
            destination = Path(runtime["output_dir"]) / "runtime_result.json"
            if len(calls) == 1:
                clock.sleep(10)
                cloud.json_file(destination, {"successful": True})
                return SimpleNamespace(stdout="first", stderr="", returncode=0)
            cloud.json_file(destination, {"successful": True, "published_manifests": [{"manifest_id": "a" * 64}]})
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output=b"partial", stderr=b"deadline")
        with self.boundaries(config, run=execute, clock=clock) as state:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.supervise(config)
        report = json.loads((self.root / "runtime/campaign_result.json").read_text())
        self.assertEqual(len(report["cases"]), 2)
        self.assertTrue(report["cases"][0]["successful"])
        self.assertTrue(report["cases"][0]["artifacts"])
        self.assertFalse(report["cases"][1]["successful"])
        self.assertLess(calls[1], calls[0])
        second = json.loads((self.root / "runtime/cases/cell-1/runtime_result.json").read_text())
        self.assertTrue(second["case_timed_out"])
        from datetime import datetime
        first = json.loads((self.root / "runtime/cases/cell-0/runtime_result.json").read_text())
        for raw in (first, second):
            started = datetime.fromisoformat(raw["case_started_at_utc"])
            finished = datetime.fromisoformat(raw["case_finished_at_utc"])
            self.assertIsNotNone(started.tzinfo)
            self.assertLessEqual(started, finished)
            self.assertGreaterEqual(raw["elapsed_seconds"], 0)
        self.assertEqual(second["published_manifests"], [{"manifest_id": "a" * 64}])
        self.assertEqual((self.root / "runtime/cases/cell-1/flower-cli.log").read_text(), "partialdeadline")
        state.process.terminate.assert_called_once()
        state.channel.close.assert_called_once()

    def test_export_failure_does_not_mask_original_timeout_and_is_recorded_locally(self):
        config = self.config()
        s3 = RecordingS3()
        s3.fail = lambda key: True
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output=b"partial")
        with self.boundaries(config, run=timeout, s3=s3):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.supervise(config)
        report = json.loads((self.root / "runtime/campaign_result.json").read_text())
        self.assertFalse(report["successful"])
        self.assertEqual(report["error"], "TimeoutExpired")
        self.assertEqual(report["cases"][0]["status"], "evidence_export_failed")
        self.assertEqual(report["campaign_export_error"], "OSError")

    def test_before_case_host_restart_requires_ack_then_authenticated_fleet_readiness(self):
        config = self.config()
        config["cases"][0]["runtime"]["host_restart"] = {"request_id": "restart-1", "org_id": "org_01",
            "run_id": "run-0", "phase": "before-case", "round_id": "initial"}
        with self.boundaries(config), patch("pcfl.runtime_faults.host_restart_barrier", return_value={"completed": True}) as restart, \
             patch.object(cloud, "wait_online") as online:
            report = self.supervise(config)
        restart.assert_called_once()
        self.assertEqual(online.call_count, 2)
        self.assertTrue(report["cases"][0]["host_restart"]["authenticated_registry_unchanged"])

    def test_ambiguous_faults_and_registered_scope_rebinding_fail_before_sdk(self):
        cases = []
        for fields in ({"scenario_id": "S7", "rounds": 2}, {"scenario_id": "S8", "rounds": 2},
                       {"authority_backend": "dynamodb-s3-ablation", "ablation_id": "Abl-2", "full_protocol": True},
                       {"plan_digest": "a" * 64}):
            config = self.config()
            config["cases"][0]["runtime"].update(fields)
            cases.append(config)
        for config in cases:
            with self.subTest(runtime=config["cases"][0]["runtime"]), self.boundaries(config) as state:
                with self.assertRaises(ValueError): self.supervise(config)
                state.sdk.assert_not_called()
                state.popen.assert_not_called()
