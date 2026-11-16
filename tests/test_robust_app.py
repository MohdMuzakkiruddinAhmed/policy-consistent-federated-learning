"""Synthetic handler and transport boundary tests; no clinical rows or AWS."""
from contextlib import ExitStack
from copy import deepcopy
import csv
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict

from test_robustness import STAGE, ROOT, preprocessor, registry_fixture
sys.path.append(str(ROOT / "tests"))
from test_integrated_runtime import EightNodeGrid
from pcfl import learning, robust_flower_app as app
from pcfl.contracts import ORGANIZATIONS
from pcfl.data import FEATURES, NUMERIC_FEATURES, CATEGORICAL_FEATURES
from pcfl.evaluation import build_model_metadata
from pcfl.robustness import DEFAULTS, architecture, deployment_inputs, selected_orgs, targets


class ActualSyntheticClientTests(unittest.TestCase):
    def test_new_exploratory_client_component_keeps_ACK_free_of_training_imports(self):
        code = '''import json,sys
from pcfl.robust_flower_client import acknowledge_task
from flwr.app import ConfigRecord,Context,Message,RecordDict
task={'org_id':'org_01','node_id':1,'purpose':'readmission','start_order':None,'nonce':'synthetic','model_schema_hash':'a'*64}
context=Context(run_id=1,node_id=1,node_config={'org-id':'org_01'},state=RecordDict(),run_config={})
reply=acknowledge_task(Message(RecordDict({'config':ConfigRecord({'task_json':json.dumps(task)})}),dst_node_id=1,message_type='query.ack'),context)
assert json.loads(reply.content['config']['task_json'])==task
assert not any(name in sys.modules for name in ('torch','sklearn','pcfl.learning','pcfl.evaluation','pcfl.robustness','pcfl.robust_flower_app'))
'''
        result = subprocess.run([sys.executable, '-c', code], env=dict(os.environ, PYTHONPATH=str(STAGE/'src')),
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_fourfold_model_trains_and_reports_delay_and_skew_without_changing_authentication(self):
        spec = architecture(build_model_metadata(preprocessor()), 4)
        model = learning.create_model(spec["model_metadata"]["preprocessor"], hidden_dims=spec["hidden_dims"])
        authority = app.RuntimeAuthority("P1", learning.get_parameters(model), model.schema_hash)
        task = authority.issue("org_01", 1, "round-1")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); own = root / "synthetic-own.csv"
            with own.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream); writer.writerow([*FEATURES, "y"])
                for i in range(16):
                    writer.writerow([*[i % 3] * len(NUMERIC_FEATURES), *[2] * len(CATEGORICAL_FEATURES), i % 2])
            state = root / "synthetic-preprocessor.json"; state.write_text(json.dumps(preprocessor()))
            context = Context(run_id=1, node_id=1, node_config={"org-id": "org_01", "data-file": str(own),
                "preprocessor-path": str(state)}, state=RecordDict(), run_config={})
            request = Message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task)})}),
                dst_node_id=1, message_type="query.ack")
            app.acknowledge_task(request, context)
            task = authority.acknowledge(task["task_id"], 1, task)
            options = {"task_json": json.dumps(task), "seed": 396, "max_examples": 16,
                "training_json": json.dumps(learning.DEFAULT_TRAINING), "hidden_dims_json": json.dumps(spec["hidden_dims"]),
                "artificial_latency_ms": 250, "client_clock_skew_ms": -60000}
            request = Message(RecordDict({"config": ConfigRecord(options), "arrays": ArrayRecord(numpy_ndarrays=learning.get_parameters(model))}),
                dst_node_id=1, message_type="train")
            with patch.object(app.time, "sleep") as sleep, patch.object(app.time, "time", return_value=1000):
                response = app.train_task(request, context)
            sleep.assert_called_once_with(.25)
            metadata = json.loads(response.content["config"]["metadata_json"])
            diagnostics = json.loads(response.content["config"]["training_json"])
            self.assertEqual(metadata["nonce"], task["nonce"])
            self.assertEqual(metadata["start_order"], task["start_order"])
            self.assertEqual(metadata["model_schema_hash"], model.schema_hash)
            self.assertEqual(diagnostics["client_reported_epoch_seconds"], 940)
            self.assertEqual(diagnostics["client_reported_clock_offset_ms"], -60000)
            arrays = response.content["arrays"].to_numpy_ndarrays()
            self.assertEqual(sum(value.nbytes for value in arrays), spec["float32_parameter_bytes"])
            self.assertEqual(authority.receive(task["task_id"], 1, metadata, arrays), "pending")
            options["artificial_latency_ms"] = True
            bad = Message(RecordDict({"config": ConfigRecord(options)}), dst_node_id=1, message_type="train")
            with patch.object(learning, "load_partition", side_effect=AssertionError("must reject before reading rows")) as load:
                with self.assertRaisesRegex(ValueError, "client_injections"):
                    app.train_task(bad, context)
                load.assert_not_called()


class ExploratoryCoordinatorTests(unittest.TestCase):
    def configuration(self, output, fraction=.5):
        source = {"authority_backend": "dynamodb-s3-opa", "baseline_id": "P1", "table_name": "synthetic-state", "bucket": "synthetic-bucket",
            "opa": {"endpoint": "http://127.0.0.1:8181", "allow_loopback_http": True}, "evaluator": {"endpoint": "https://invalid.example"}}
        inputs = deployment_inputs(registry_fixture(), source)
        chosen = next(case["runtime"] for group in inputs["groups"] for case in group["cases"]
                      if case["runtime"]["distribution"] == "iid" and case["runtime"]["robustness"]["factors"] == {**DEFAULTS, "participation_fraction": fraction})
        return {**chosen, "node_registry": {str(number): org for number, org in enumerate(ORGANIZATIONS, 1)},
            "storage": {"local_emulation": True}, "output_dir": str(output), "message_timeout_seconds": 1}

    def test_real_coordinator_path_issues_only_prespecified_subset_while_all_eight_registered(self):
        # The Grid and service constructors are doubles; handler/selection/artifact/report paths run.
        for fraction, count in ((.5, 4), (.75, 6), (1., 8)):
            with self.subTest(fraction=fraction), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                config = self.configuration(directory, fraction)
                holder = {}
                def authority_factory(_ddb, _s3, **options):
                    authority = app.RuntimeAuthority("P1", options["template"], options["model_schema_hash"], max_examples=71160)
                    holder["authority"] = authority
                    return authority
                class Signal:
                    def __init__(self, *args, **kwargs): pass
                    def reach(self, phase, round_id="initial"):
                        number = int(round_id.split("-")[-1]) if round_id != "initial" else 0
                        if phase == "before_round" and number > 1:
                            for org in targets(296, number - 1, config["robustness"]["factors"]): holder["authority"].mutate(org, "GRANT")
                        if phase == "after_dispatch":
                            for org in targets(296, number, config["robustness"]["factors"]): holder["authority"].mutate(org, "REVOKE")
                stack.enter_context(patch("pcfl.service_io.sdk_clients", return_value=(object(), object())))
                stack.enter_context(patch("pcfl.opa.OpaClient", return_value=SimpleNamespace(rule_hash="a" * 64, evaluate=Mock())))
                stack.enter_context(patch("pcfl.evaluation.EvaluationClient", return_value=SimpleNamespace(evaluate=Mock(return_value={"metrics": {"auroc": .5}}))))
                stack.enter_context(patch("pcfl.persistent.PersistentAuthority", side_effect=authority_factory))
                stack.enter_context(patch("pcfl.robust_policy.RobustScenarioSignal", Signal))
                stack.enter_context(patch.object(learning, "load_partition", side_effect=AssertionError("coordinator cannot read rows")))
                grid = EightNodeGrid()
                result = app.run_server(grid, config)
                self.assertTrue(result["successful"])
                self.assertEqual(len(result["node_registry"]), 8)
                self.assertEqual([r["selected_clients"] for r in result["rounds"]], [count] * 5)
                self.assertEqual([r["accepted_updates"] for r in result["rounds"]], [count-1] * 5)
                self.assertFalse(result["test_holdout_evaluated"])
                self.assertFalse(result["registered_primary_case"])
                observations = result["runtime_observations"]
                self.assertEqual(observations["stages"][-1]["name"], "run")
                self.assertEqual(observations["stages"][-1]["status"], "complete")
                self.assertEqual(len([item for item in observations["operations"] if item["operation"] == "issue"]), count * 5)
                self.assertEqual(len([item for item in observations["operations"] if item["operation"] == "publish"]), 5)
                for number in range(1, 6):
                    self.assertEqual(sorted(t["org_id"] for t in result["tasks"] if t["round_id"] == f"round-{number}"), selected_orgs(296, number, fraction))

    def test_holdout_main_family_and_wrong_adapter_hash_rejected_before_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            for mutation in ({"final_holdout": {}}, {"baseline_id": "B3"}, {"scenario_control": False}, {"robustness": None}):
                config = {**self.configuration(directory), **mutation}
                with self.subTest(mutation=mutation), patch("pcfl.service_io.sdk_clients") as sdk:
                    with self.assertRaises(ValueError): app.run_server(EightNodeGrid(), config)
                    sdk.assert_not_called()

    def test_additive_entrypoint_changes_only_module_routing_and_denies_holdout(self):
        spec = importlib.util.spec_from_file_location("exploratory_entrypoint", STAGE / "containers/robustness/entrypoint.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        frozen = SimpleNamespace(build_command=Mock(return_value=["python", "-m", "pcfl.cloud_coordinator", "--config", "/runtime/a.json"]))
        env = {"PCFL_RUNTIME_CONFIG_JSON": json.dumps({"cases": [{"runtime": {"robustness": {}}}]})}
        self.assertEqual(module.build_command("coordinator", env, frozen)[2], "pcfl.robust_cloud_coordinator")
        frozen.build_command.reset_mock()
        env["PCFL_RUNTIME_CONFIG_JSON"] = json.dumps({"cases": [{"runtime": {"robustness": {}, "final_holdout": {}}}]})
        with self.assertRaises(ValueError): module.build_command("coordinator", env, frozen)
        frozen.build_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
