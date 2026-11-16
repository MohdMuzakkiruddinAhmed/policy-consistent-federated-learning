"""Lightweight Flower client dispatch; import learning only after training binding checks."""
import hashlib
import json
import math
import time
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from .contracts import ORGANIZATIONS, digest


def arrays_digest(arrays):
    """Bind exact dtype, shape and C-order parameter bytes without pickle."""
    return digest([{"dtype": array.dtype.str, "shape": list(array.shape),
                    "sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest()}
                   for array in arrays])



client_app = ClientApp()


def _task_from_message(message, context):
    task = json.loads(message.content["config"]["task_json"])
    org = context.node_config.get("org-id")
    if (not isinstance(task, dict) or org not in ORGANIZATIONS or task.get("org_id") != org
            or task.get("node_id") != context.node_id or task.get("purpose") != "readmission"):
        raise ValueError("client_task_identity_mismatch")
    return task


@client_app.query("ack")
def acknowledge_task(message: Message, context: Context) -> Message:
    task = _task_from_message(message, context)
    if task["start_order"] is not None:
        raise ValueError("task_already_started")
    context.state["task-ack"] = ConfigRecord({"task_json": json.dumps(task, sort_keys=True)})
    return Message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task, sort_keys=True)})}), reply_to=message)


@client_app.train()
def train_task(message: Message, context: Context) -> Message:
    task = _task_from_message(message, context)
    acknowledged = json.loads(context.state["task-ack"]["task_json"])
    expected = {**acknowledged, "start_order": task["start_order"]}
    if expected != task or type(task["start_order"]) is not int or task["start_order"] <= task["issue_order"]:
        raise ValueError("task_was_not_acknowledged")
    from . import learning
    options = message.content["config"]
    preprocessor = context.node_config.get("preprocessor-path", context.node_config.get("preprocessor-file"))
    dataset = learning.load_partition(context.node_config["data-file"], preprocessor,
        max_examples=int(options["max_examples"]), seed=int(options["seed"]))
    model = learning.create_model(dataset.preprocessor, seed=int(options["seed"]))
    if model.schema_hash != task["model_schema_hash"]:
        raise ValueError("client_model_schema_mismatch")
    learning.set_parameters(model, message.content["arrays"].to_numpy_ndarrays())
    training = json.loads(options["training_json"])
    metadata = learning.train_local(model, dataset, training, seed=int(options["seed"]))
    arrays = learning.get_parameters(model)
    reply_metadata = {key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose",
                                                "start_order", "model_schema_hash", "nonce")}
    reply_metadata.update({"weights_digest": arrays_digest(arrays), "sample_count": len(dataset)})
    delay = options.get("reply_delay_seconds", 0.0)
    if type(delay) not in (int, float) or not math.isfinite(delay) or not 0 <= delay <= 5:
        raise ValueError("invalid_scripted_reply_delay")
    if delay:
        time.sleep(delay)
    return Message(RecordDict({"arrays": ArrayRecord(numpy_ndarrays=arrays),
        "config": ConfigRecord({"metadata_json": json.dumps(reply_metadata, sort_keys=True),
                                "training_json": json.dumps(metadata, sort_keys=True)})}), reply_to=message)

