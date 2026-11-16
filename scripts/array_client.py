"""Synthetic client worker used across two separate local process lifetimes."""

import hashlib
import json
import os
import sys

document = json.load(sys.stdin)
task = document["task"]
if document["operation"] == "ack":
    result = {"task": task, "pid": os.getpid()}
elif document["operation"] == "train":
    import numpy as np
    number = document["number"]
    arrays = [np.array([number, number], dtype=np.float32)]
    descriptors = [{"dtype": value.dtype.str, "shape": list(value.shape), "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest()} for value in arrays]
    digest = hashlib.sha256(json.dumps(descriptors, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    metadata = {key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose", "start_order", "model_schema_hash", "nonce")}
    metadata.update(sample_count=number, weights_digest=digest, client_wall_clock_ms=-60000 if number == 1 else 60000)
    result = {"metadata": metadata, "arrays": [value.tolist() for value in arrays], "pid": os.getpid()}
else:
    raise ValueError("unknown_synthetic_client_operation")
json.dump(result, sys.stdout)
