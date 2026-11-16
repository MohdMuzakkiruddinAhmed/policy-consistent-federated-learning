"""Coordinator/service boundaries with a small synchronous eight-node Grid double.

Persistent storage and remote service constructors are substituted here. The
real coordinator handshake, receipt, publication, artifact, and failure-reporting
paths run without coordinator access to any training or validation records.
"""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, RecordDict

from pcfl import learning
from pcfl.contracts import ORGANIZATIONS
from pcfl.data import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES
from pcfl.evaluation import build_model_metadata
from pcfl.flower_app import RuntimeAuthority, arrays_digest, run_server


class EightNodeGrid:
    """Acknowledge tasks and return bound tiny updates; it never loads a dataset."""
    def __init__(self):
        self.pending = {}
        self.messages_sent = 0

    def get_node_ids(self):
        return list(range(1, 9))

    def create_message(self, content, message_type, dst_node_id, group_id, **_):
        return SimpleNamespace(content=content,
            metadata=SimpleNamespace(dst_node_id=dst_node_id, message_type=message_type, group_id=group_id))

    def send_and_receive(self, messages, **_):
        self.messages_sent += len(messages)
        return [SimpleNamespace(content=message.content, has_error=lambda: False,
            metadata=SimpleNamespace(src_node_id=message.metadata.dst_node_id)) for message in messages]

    def push_messages(self, messages):
        for message in messages:
            self.messages_sent += 1
            message_id = f"training-message-{self.messages_sent}"
            task = json.loads(message.content["config"]["task_json"])
            arrays = [value + np.float32(task["node_id"] / 10)
                      for value in message.content["arrays"].to_numpy_ndarrays()]
            metadata = {key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose",
                                                   "start_order", "model_schema_hash", "nonce")}
            metadata.update(weights_digest=arrays_digest(arrays), sample_count=2)
            content = RecordDict({"arrays": ArrayRecord(numpy_ndarrays=arrays), "config": ConfigRecord({
                "metadata_json": json.dumps(metadata), "training_json": json.dumps({"examples": 2})})})
            self.pending[message_id] = SimpleNamespace(content=content, has_error=lambda: False,
                metadata=SimpleNamespace(src_node_id=task["node_id"], reply_to_message_id=message_id))
            yield message_id

    def pull_messages(self, message_ids):
        return [self.pending.pop(message_id) for message_id in message_ids if message_id in self.pending]


class IntegratedCoordinatorBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        public_state = {"schema_version": "0.1.0", "fit_scope": "training_only", "fit_rows": 16,
            "feature_order": list(FEATURES), "target": "y",
            "numeric": {name: {"median": 0, "mean": 0, "scale": 1} for name in NUMERIC_FEATURES},
            "categorical": {name: {"missing_code": 0, "unknown_code": 1, "vocabulary": {"observed": 2}}
                            for name in CATEGORICAL_FEATURES}}
        cls.metadata = build_model_metadata(public_state, seed=296, hidden_dims=(4,))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.grid = EightNodeGrid()

    def configuration(self):
        return {"node_registry": {str(index): org for index, org in enumerate(ORGANIZATIONS, 1)},
            "baseline_id": "P1", "scenario_id": "stable", "rounds": 1, "seed": 296,
            "max_examples_per_client": 4, "message_timeout_seconds": 1,
            "authority_backend": "dynamodb-s3-opa", "model_metadata": deepcopy(self.metadata),
            "storage": {"local_emulation": True}, "table_name": "test-state", "bucket": "test-models",
            "persistent_run_id": "boundary-run", "output_dir": str(self.output),
            "opa": {"endpoint": "http://127.0.0.1:8181", "allow_loopback_http": True},
            "evaluator": {"endpoint": "https://evaluation.invalid"}}

    @contextmanager
    def service_boundaries(self, *, evaluator_error=None):
        state = SimpleNamespace(authorities=[])
        state.evaluator = Mock()
        state.evaluator.evaluate.return_value = {"metrics": {"count": 8, "auroc": 0.5},
            "dataset_role": "validation", "final_test_evaluated": False, "manifest_verified": True}
        if evaluator_error:
            state.evaluator.evaluate.side_effect = evaluator_error
        state.opa = SimpleNamespace(rule_hash="a" * 64, evaluate=Mock())
        def authority_factory(_ddb, _s3, **options):
            authority = RuntimeAuthority("P1", options["template"], options["model_schema_hash"],
                                         max_examples=options["max_examples"])
            state.authorities.append(authority)
            return authority
        original_preprocessor = learning.load_preprocessor
        def public_mapping_only(value):
            if not isinstance(value, dict):
                raise AssertionError("coordinator attempted to read a training preprocessor file")
            return original_preprocessor(value)
        with ExitStack() as stack:
            state.storage = stack.enter_context(patch("pcfl.service_io.sdk_clients", return_value=(object(), object())))
            state.opa_factory = stack.enter_context(patch("pcfl.opa.OpaClient", return_value=state.opa))
            state.policy_factory = stack.enter_context(patch("pcfl.governance_service.PolicyClient"))
            state.evaluator_factory = stack.enter_context(patch("pcfl.evaluation.EvaluationClient", return_value=state.evaluator))
            state.authority_factory = stack.enter_context(patch("pcfl.persistent.PersistentAuthority", side_effect=authority_factory))
            state.partition = stack.enter_context(patch.object(learning, "load_partition",
                side_effect=AssertionError("coordinator attempted to load private records")))
            state.local_evaluation = stack.enter_context(patch.object(learning, "evaluate",
                side_effect=AssertionError("coordinator attempted local validation")))
            state.preprocessor = stack.enter_context(patch.object(learning, "load_preprocessor", side_effect=public_mapping_only))
            yield state

    def assert_no_service_construction(self, state):
        for constructor in (state.storage, state.opa_factory, state.policy_factory,
                            state.evaluator_factory, state.authority_factory):
            constructor.assert_not_called()
        self.assertEqual(self.grid.messages_sent, 0)

    def test_persistent_coordinator_uses_public_metadata_and_remote_aggregate_evaluation(self):
        config = self.configuration()
        with self.service_boundaries() as state:
            result = run_server(self.grid, config)
            state.partition.assert_not_called()
            state.local_evaluation.assert_not_called()
            self.assertGreater(state.preprocessor.call_count, 0)
            state.policy_factory.assert_not_called()
            options = state.authority_factory.call_args.kwargs
            query = {"org_id": "org_01", "start_order": 1, "commit_order": 2}
            response = options["policy_evaluator"]([], query)
            state.opa.evaluate.assert_called_once_with([], query)
            self.assertIs(response, state.opa.evaluate.return_value)
            self.assertEqual(result["policy_rpc_metrics"][-1]["org_id"], "org_01")
            self.assertEqual(options["rule_hash"], state.opa.rule_hash)
            request = state.evaluator.evaluate.call_args.args[0]
        self.assertTrue(result["successful"])
        self.assertEqual(result["validation_metrics"], {"count": 8, "auroc": 0.5})
        self.assertEqual(result["authority_backend"], "dynamodb-s3-opa")
        self.assertFalse(result["test_holdout_evaluated"])
        manifest = result["published_manifests"][0]
        self.assertEqual(request["manifest_id"], manifest["manifest_id"])
        self.assertEqual(request["parameters_digest"], manifest["model_digest"])
        self.assertEqual(request["artifact"], manifest["artifact"])
        self.assertEqual(len(manifest["included_update_ids"]), 8)
        self.assertTrue((self.output / "published_model.json").is_file())

    def test_persistent_mode_rejects_all_comparator_baselines_before_services_or_messages(self):
        for baseline in ("B1", "B2", "B3", "unknown"):
            config = {**self.configuration(), "baseline_id": baseline}
            with self.subTest(baseline=baseline), self.service_boundaries() as state:
                with self.assertRaisesRegex(ValueError, "public_metadata_and_P1"):
                    run_server(self.grid, config)
                self.assert_no_service_construction(state)

    def test_persistent_mode_rejects_private_dataset_and_preprocessor_paths_before_services(self):
        for forbidden in ("data_dir", "preprocessor_path", "validation_path"):
            config = {**self.configuration(), forbidden: "private-records-must-not-be-read"}
            with self.subTest(field=forbidden), self.service_boundaries() as state:
                with self.assertRaisesRegex(ValueError, "public_metadata_and_P1"):
                    run_server(self.grid, config)
                self.assert_no_service_construction(state)

    def test_benchmark_policy_writer_requires_local_emulation_before_any_account_access(self):
        for storage in ({"local_emulation": False}, {"expected_account_id": "980322232249"}):
            config = {**self.configuration(), "storage": storage, "benchmark_policy_writer": {"endpoint": "https://policy.invalid"}}
            with self.subTest(storage=storage), self.service_boundaries() as state:
                with self.assertRaisesRegex(ValueError, "requires_explicit_local_emulation"):
                    run_server(self.grid, config)
                self.assert_no_service_construction(state)

    def test_benchmark_writer_is_injected_only_for_explicit_local_storage(self):
        config = {**self.configuration(), "benchmark_policy_writer": {"endpoint": "https://policy.invalid"}}
        with self.service_boundaries() as state:
            result = run_server(self.grid, config)
            state.policy_factory.assert_called_once_with(endpoint="https://policy.invalid")
            self.assertIs(state.authority_factory.call_args.kwargs["policy_mutator"], state.policy_factory.return_value.mutate)
        self.assertTrue(result["benchmark_policy_injection"])
        self.assertFalse(result["aws_used"])

    def test_evaluator_outage_records_failure_and_preserves_committed_publication(self):
        with self.service_boundaries(evaluator_error=URLError("evaluator_unavailable")) as state:
            with self.assertRaises(URLError):
                run_server(self.grid, self.configuration())
            state.partition.assert_not_called()
            state.local_evaluation.assert_not_called()
            authority = state.authorities[0]
        report = json.loads((self.output / "runtime_result.json").read_text(encoding="utf-8"))
        committed = json.loads((self.output / "published_model.json").read_text(encoding="utf-8"))
        self.assertFalse(report["successful"])
        self.assertEqual(report["error"], "URLError")
        self.assertIn("evaluator_unavailable", report["reason"])
        self.assertEqual(report["published_manifests"], [committed])
        self.assertEqual(report["current_model_digest"], committed["model_digest"])
        self.assertEqual(arrays_digest(authority.parameters()), committed["model_digest"])
        self.assertTrue(Path(committed["artifact"]["path"]).is_file())
        self.assertNotIn("validation_metrics", report)
        self.assertTrue(all(decision["outcome"] == "accepted" for decision in report["decisions"].values()))
        observations = report["runtime_observations"]
        self.assertEqual(observations["stages"][-1]["name"], "run")
        self.assertEqual(observations["stages"][-1]["status"], "error")
        self.assertEqual(next(item for item in observations["stages"] if item["name"] == "evaluation")["status"], "error")
        self.assertEqual(observations["operations"][-1]["manifest_id"], committed["manifest_id"])

    def test_observed_denial_binds_actual_selection_order_without_inventing_a_task(self):
        config = {**self.configuration(), "scenario_id": "S1", "rounds": 2}
        with self.service_boundaries():
            result = run_server(self.grid, config)
        operations = result["runtime_observations"]["operations"]
        denial, = [item for item in operations if item["operation"] == "issue" and item["outcome"] == "denied"]
        selected, = [item for item in result["selection"] if not item["selected"]]
        self.assertEqual((denial["org_id"], denial["round_id"], denial["observation_order"]),
                         (selected["org_id"], selected["round_id"], selected["order"]))
        self.assertIsNone(denial["task_id"])
        self.assertIsNone(denial["update_id"])
        self.assertEqual(len(result["tasks"]), 15)
        self.assertEqual([item["sequence"] for item in operations], list(range(1, len(operations) + 1)))

    def test_publication_observation_keeps_pending_before_and_actual_exclusion_after_race(self):
        with self.service_boundaries():
            result = run_server(self.grid, {**self.configuration(), "scenario_id": "S6"})
        observations = result["runtime_observations"]
        publication, = [item for item in observations["operations"] if item["operation"] == "publish"]
        receipts = [item for item in observations["operations"] if item["operation"] == "receive"]
        self.assertEqual(len(receipts), 8)
        self.assertTrue(all(item["outcome"] == "pending" for item in receipts))
        self.assertEqual(set(publication["pending_update_ids"]), {item["update_id"] for item in receipts})
        rejected, = [item for item in result["decisions"].values() if item["outcome"] == "rejected"]
        self.assertEqual(publication["excluded_update_ids"], [rejected["update_id"]])
        manifest, = result["published_manifests"]
        self.assertEqual(publication["included_update_ids"], manifest["included_update_ids"])
        self.assertEqual(publication["observation_order"], manifest["commit_order"])
        self.assertEqual(publication["manifest_id"], manifest["manifest_id"])
        # Legacy local mutation has no independent signal bracket; never invent one.
        self.assertEqual(observations["policy_windows"], [])
        self.assertEqual(observations["stages"][-1]["status"], "complete")
        self.assertTrue(all(0 <= item["start_ms"] <= item["end_ms"] <= observations["stages"][-1]["end_ms"]
                            for item in observations["operations"]))
