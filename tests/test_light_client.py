"""Independent ACK bindings and real synthetic-training parity with frozen client."""
from copy import deepcopy
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "tests"))
from test_evaluation import preprocessor
from pcfl import flower_client as client, flower_app, learning
from pcfl.data import FEATURES, NUMERIC_FEATURES, CATEGORICAL_FEATURES

spec = importlib.util.spec_from_file_location("pcfl._frozen_legacy_client", ROOT / "tests/fixtures/client_v3_reference.py")
legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)


def context(data="synthetic.csv", prep="synthetic-preprocessor.json"):
    return Context(run_id=1, node_id=1, node_config={"org-id": "org_01", "data-file": str(data),
        "preprocessor-path": str(prep)}, state=RecordDict(), run_config={})


def message(task, **options):
    return Message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task), **options})}), dst_node_id=1, message_type="query.ack")


class LightweightClientTests(unittest.TestCase):
    def setUp(self):
        self.model = learning.create_model(preprocessor(), seed=296)
        self.authority = flower_app.RuntimeAuthority("P1", learning.get_parameters(self.model), self.model.schema_hash)
        self.task = self.authority.issue("org_01", 1, "round-1")

    def test_compatibility_aliases_preserve_existing_entrypoint_names(self):
        reference = ROOT / "tests/fixtures/client_v3_reference.py"
        provenance = json.loads(reference.with_suffix(".json").read_bytes())
        self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(), provenance["fixture_sha256"])
        self.assertFalse(provenance["production_import_allowed"])
        self.assertIs(flower_app.client_app, client.client_app)
        self.assertIs(flower_app.acknowledge_task, client.acknowledge_task)
        self.assertIs(flower_app.train_task, client.train_task)

    def test_ack_echoes_exact_nonce_schema_and_identity_and_rejects_invalid_sender_scope(self):
        for module in (legacy, client):
            state = context()
            reply = module.acknowledge_task(message(self.task), state)
            self.assertEqual(json.loads(reply.content["config"]["task_json"]), self.task)
            self.assertEqual(json.loads(state.state["task-ack"]["task_json"]), self.task)
            for update in ({"org_id": "org_02"}, {"node_id": 2}, {"purpose": "different"}, {"start_order": 7}):
                with self.subTest(module=module.__name__, update=update), self.assertRaises(ValueError):
                    module.acknowledge_task(message({**self.task, **update}), context())

    def test_train_rebinding_replay_and_bad_start_are_rejected_before_dataset_access(self):
        for module in (legacy, client):
            for update in ({"nonce": "different"}, {"model_schema_hash": "f" * 64}, {"round_id": "round-2"},
                           {"task_id": "rebound"}, {"start_order": self.task["issue_order"]}, {"start_order": True}):
                state = context(); module.acknowledge_task(message(self.task), state)
                task = {**self.task, "start_order": self.task["issue_order"]+1, **update}
                with self.subTest(module=module.__name__, update=update), patch.object(learning, "load_partition") as read:
                    with self.assertRaises(ValueError): module.train_task(message(task), state)
                    read.assert_not_called()
            state = context(); module.acknowledge_task(message({**self.task, "nonce": "new-issued-task"}), state)
            with self.assertRaises(ValueError): module.train_task(message({**self.task, "start_order": self.task["issue_order"]+1}), state)
            with self.assertRaises(KeyError): module.train_task(message({**self.task, "start_order": 100}), context())

    def test_real_numpy_model_and_all_nontiming_training_metadata_match_frozen_client_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); own=root/"synthetic.csv"; prep=root/"preprocessor.json"
            prep.write_text(json.dumps(preprocessor()))
            with own.open("w", newline="") as stream:
                writer=csv.writer(stream);writer.writerow([*FEATURES,"y"])
                for i in range(32): writer.writerow([*[i%3]*len(NUMERIC_FEATURES),*[2]*len(CATEGORICAL_FEATURES),i%2])
            outputs=[]
            task={**self.task,"start_order":self.task["issue_order"]+1}
            for module in (legacy,client,client):
                state=context(own,prep); module.acknowledge_task(message(self.task),state)
                config={"task_json":json.dumps(task),"seed":396,"max_examples":32,"training_json":json.dumps(learning.DEFAULT_TRAINING)}
                request=Message(RecordDict({"config":ConfigRecord(config),"arrays":ArrayRecord(numpy_ndarrays=learning.get_parameters(self.model))}),dst_node_id=1,message_type="train")
                response=module.train_task(request,state)
                training=json.loads(response.content["config"]["training_json"]); training.pop("duration_seconds")
                outputs.append((response.content["arrays"].to_numpy_ndarrays(),json.loads(response.content["config"]["metadata_json"]),training))
            for actual in outputs[1:]:
                for left,right in zip(outputs[0][0],actual[0],strict=True):np.testing.assert_array_equal(left,right)
                self.assertEqual(outputs[0][1:],actual[1:])
            self.assertEqual(outputs[0][1]["nonce"],self.task["nonce"])
            self.assertEqual(outputs[0][2]["sample_count"],32)

    def test_ack_in_fresh_interpreter_does_not_import_learning_torch_or_sklearn(self):
        script='''import sys,json
from pcfl.flower_client import acknowledge_task,train_task
from flwr.app import Context,Message,ConfigRecord,RecordDict
task=TASK
context=Context(run_id=1,node_id=1,node_config={'org-id':'org_01'},state=RecordDict(),run_config={})
request=Message(RecordDict({'config':ConfigRecord({'task_json':json.dumps(task)})}),dst_node_id=1,message_type='query.ack')
reply=acknowledge_task(request,context)
assert json.loads(reply.content['config']['task_json'])==task
rebound={**task,'start_order':task['issue_order']+1,'nonce':'changed'}
bad=Message(RecordDict({'config':ConfigRecord({'task_json':json.dumps(rebound)})}),dst_node_id=1,message_type='train')
try:train_task(bad,context)
except ValueError:pass
else:raise AssertionError('rebound accepted')
assert not any(name in sys.modules for name in ('torch','sklearn','pcfl.learning','pcfl.evaluation','pcfl.flower_app'))
print(json.dumps({'ACK_verified':True,'rebound_rejected':True,'heavy_modules_loaded':False}))
'''.replace('TASK',repr(self.task))
        result=subprocess.run([sys.executable,'-c',script],env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['ACK_verified'])


if __name__=='__main__':unittest.main()
