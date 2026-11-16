"""CPU tabular learning for the frozen UCI preparation contract.

CSV category codes are nominal: this module one-hot encodes them using only the
already fitted training preprocessor. It never fits a transform or logs records.
"""

from copy import deepcopy
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import random
import time

import numpy as np
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from .data import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES, canonical_json

DEFAULT_TRAINING = {"local_epochs": 1, "batch_size": 64, "learning_rate": 0.001,
                    "optimizer": "adam", "cpu_threads": 1}


def _hash(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _seed(seed):
    if type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("invalid_learning_seed")
    return seed


def load_preprocessor(preprocessor):
    """Validate a frozen mapping/path; deliberately provide no fit operation."""
    if isinstance(preprocessor, (str, Path)):
        state = json.loads(Path(preprocessor).read_text(encoding="utf-8"))
    else:
        state = deepcopy(preprocessor)
    if (not isinstance(state, dict) or state.get("fit_scope") != "training_only"
            or state.get("feature_order") != list(FEATURES) or state.get("target") != "y"
            or type(state.get("fit_rows")) is not int or state["fit_rows"] < 1
            or set(state.get("numeric", {})) != set(NUMERIC_FEATURES)
            or set(state.get("categorical", {})) != set(CATEGORICAL_FEATURES)):
        raise ValueError("invalid_frozen_preprocessor")
    for name in NUMERIC_FEATURES:
        numeric = state["numeric"][name]
        if (not isinstance(numeric, dict)
                or any(type(numeric.get(key)) not in (int, float) or not math.isfinite(numeric[key])
                       for key in ("median", "mean", "scale")) or numeric["scale"] <= 0):
            raise ValueError("invalid_frozen_numeric_state")
    for name in CATEGORICAL_FEATURES:
        category = state["categorical"][name]
        if (not isinstance(category, dict) or category.get("missing_code") != 0
                or type(category.get("missing_code")) is not int
                or category.get("unknown_code") != 1 or type(category.get("unknown_code")) is not int
                or not isinstance(category.get("vocabulary"), dict)):
            raise ValueError("invalid_frozen_category_state")
        vocab = category["vocabulary"]
        if (any(not isinstance(value, str) or not value.strip() for value in vocab)
                or any(type(code) is not int for code in vocab.values())
                or sorted(vocab.values()) != list(range(2, len(vocab) + 2))):
            raise ValueError("noncontiguous_frozen_category_codes")
    return state


def feature_layout(preprocessor):
    state = load_preprocessor(preprocessor)
    widths = [len(state["categorical"][name]["vocabulary"]) + 2 for name in CATEGORICAL_FEATURES]
    descriptor = {"encoding": "eight-standardized-numeric-plus-one-hot-v1",
                  "feature_order": list(FEATURES), "categorical_widths": widths,
                  "preprocessor_digest": _hash(state)}
    return {**descriptor, "input_dimension": len(NUMERIC_FEATURES) + sum(widths),
            "feature_schema_hash": _hash(descriptor)}


class EncodedPartition(TensorDataset):
    """Encoded tensors plus aggregate provenance, without source identifiers."""

    def __init__(self, x, y, preprocessor, source_sha256, source_rows, sampled_positions_digest):
        super().__init__(x, y)
        self._preprocessor = deepcopy(preprocessor)
        self.feature_schema_hash = feature_layout(preprocessor)["feature_schema_hash"]
        self.source_sha256 = source_sha256
        self.source_rows = source_rows
        self.sampled_positions_digest = sampled_positions_digest

    @property
    def preprocessor(self):
        return deepcopy(self._preprocessor)


def encode_features(values, preprocessor):
    """Encode prepared numeric/code columns without learning from these values."""
    layout = feature_layout(preprocessor)
    raw = np.asarray(values, dtype=np.float64)
    if raw.ndim != 2 or raw.shape[1] != len(FEATURES) or not np.isfinite(raw).all():
        raise ValueError("invalid_prepared_feature_matrix")
    encoded = np.zeros((len(raw), layout["input_dimension"]), dtype=np.float32)
    numeric = raw[:, :len(NUMERIC_FEATURES)]
    if np.any(np.abs(numeric) > np.finfo(np.float32).max):
        raise ValueError("numeric_feature_exceeds_float32")
    encoded[:, :len(NUMERIC_FEATURES)] = numeric.astype(np.float32)
    offset = len(NUMERIC_FEATURES)
    for index, width in enumerate(layout["categorical_widths"], len(NUMERIC_FEATURES)):
        codes = raw[:, index]
        if np.any(codes != np.floor(codes)) or np.any(codes < 0) or np.any(codes >= width):
            raise ValueError("invalid_nominal_category_code")
        encoded[np.arange(len(raw)), offset + codes.astype(np.int64)] = 1.0
        offset += width
    return encoded


def load_partition(csv_path, preprocessor_path, max_examples=None, seed=296):
    """Read one prepared partition; optionally take a seeded label-blind sample."""
    _seed(seed)
    if max_examples is not None and (type(max_examples) is not int or max_examples < 1):
        raise ValueError("invalid_max_examples")
    state = load_preprocessor(preprocessor_path)
    content = Path(csv_path).read_bytes()
    reader = csv.reader(io.StringIO(content.decode("utf-8-sig")))
    if next(reader, None) != list(FEATURES) + ["y"]:
        raise ValueError("prepared_csv_header_mismatch")
    features, labels = [], []
    for row in reader:
        if len(row) != len(FEATURES) + 1 or row[-1] not in ("0", "1"):
            raise ValueError("invalid_prepared_csv_row")
        try:
            features.append([float(value) for value in row[:-1]])
        except ValueError:
            raise ValueError("invalid_prepared_csv_number") from None
        labels.append(int(row[-1]))
    if not labels:
        raise ValueError("empty_prepared_partition")
    # Validate the complete source before sampling so a small pilot cannot hide
    # malformed rows. Sampling consults positions only, never target values.
    encoded = encode_features(features, state)
    count = len(labels)
    positions = np.arange(count)
    if max_examples is not None and max_examples < count:
        positions = np.sort(np.random.default_rng(seed).choice(count, max_examples, replace=False))
    x = torch.from_numpy(encoded[positions].copy())
    y = torch.from_numpy(np.asarray(labels, dtype=np.float32)[positions].copy())
    return EncodedPartition(x, y, state, hashlib.sha256(content).hexdigest(), count,
                            _hash(positions.tolist()))


class TabularMLP(nn.Module):
    def __init__(self, input_dimension, hidden_dims, feature_schema_hash):
        super().__init__()
        dimensions = [input_dimension, *hidden_dims, 1]
        layers = []
        for index in range(len(dimensions) - 1):
            layers.append(nn.Linear(dimensions[index], dimensions[index + 1]))
            if index < len(dimensions) - 2:
                layers.append(nn.ReLU())
        self.network = nn.Sequential(*layers)
        self.input_dimension = input_dimension
        self.feature_schema_hash = feature_schema_hash
        self.schema_hash = _hash({"architecture": "tabular-mlp-v1", "dimensions": dimensions,
                                  "feature_schema_hash": feature_schema_hash,
                                  "parameters": [{"name": name, "shape": list(value.shape),
                                                  "dtype": str(value.dtype)}
                                                 for name, value in self.state_dict().items()]})

    def forward(self, x):
        if x.ndim != 2 or x.shape[1] != self.input_dimension:
            raise ValueError("model_input_dimension_mismatch")
        return self.network(x).squeeze(-1)


def create_model(preprocessor, seed=296, hidden_dims=(64, 32)):
    _seed(seed)
    if (not isinstance(hidden_dims, (tuple, list)) or not 1 <= len(hidden_dims) <= 4
            or any(type(width) is not int or not 1 <= width <= 1024 for width in hidden_dims)):
        raise ValueError("invalid_mlp_hidden_dimensions")
    layout = feature_layout(preprocessor)
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(seed)
        return TabularMLP(layout["input_dimension"], hidden_dims, layout["feature_schema_hash"]).cpu()


def get_parameters(model):
    result = [value.detach().cpu().numpy().copy() for value in model.state_dict().values()]
    if any(value.dtype != np.float32 or not np.isfinite(value).all() for value in result):
        raise ValueError("invalid_model_parameter_state")
    return result


def set_parameters(model, parameters):
    """Reject an invalid bundle before copying any of its arrays into the model."""
    state = model.state_dict()
    if not isinstance(parameters, (tuple, list)) or len(parameters) != len(state):
        raise ValueError("parameter_count_mismatch")
    replacement = {}
    for (name, expected), supplied in zip(state.items(), parameters, strict=True):
        if (not isinstance(supplied, np.ndarray) or supplied.dtype != np.float32
                or tuple(supplied.shape) != tuple(expected.shape) or not np.isfinite(supplied).all()):
            raise ValueError("parameter_shape_dtype_or_finiteness_mismatch")
        replacement[name] = torch.from_numpy(np.array(supplied, copy=True, order="C"))
    model.load_state_dict(replacement, strict=True)


def _validate_dataset(model, dataset):
    if not isinstance(dataset, TensorDataset) or len(dataset.tensors) != 2 or len(dataset) < 1:
        raise ValueError("invalid_learning_dataset")
    x, y = dataset.tensors
    if (x.dtype != torch.float32 or y.dtype != torch.float32 or x.device.type != "cpu" or y.device.type != "cpu"
            or x.ndim != 2 or y.ndim != 1 or len(x) != len(y) or x.shape[1] != model.input_dimension
            or not torch.isfinite(x).all() or not torch.isfinite(y).all() or not torch.all((y == 0) | (y == 1))):
        raise ValueError("dataset_shape_dtype_or_values_mismatch")
    if hasattr(dataset, "feature_schema_hash") and dataset.feature_schema_hash != model.feature_schema_hash:
        raise ValueError("dataset_preprocessor_schema_mismatch")
    if any(parameter.device.type != "cpu" for parameter in model.parameters()):
        raise ValueError("cpu_model_required")


def _training_configuration(config):
    if not isinstance(config, dict):
        raise ValueError("invalid_training_configuration")
    values = {name: config.get(name, default) for name, default in DEFAULT_TRAINING.items()}
    if (type(values["local_epochs"]) is not int or not 1 <= values["local_epochs"] <= 100
            or type(values["batch_size"]) is not int or not 1 <= values["batch_size"] <= 100000
            or type(values["cpu_threads"]) is not int or not 1 <= values["cpu_threads"] <= 32
            or type(values["learning_rate"]) not in (int, float) or not math.isfinite(values["learning_rate"])
            or not 0 < values["learning_rate"] <= 1 or values["optimizer"] not in ("adam", "sgd")):
        raise ValueError("invalid_training_configuration")
    return values


def train_local(model, dataset, config, seed=296):
    _seed(seed)
    _validate_dataset(model, dataset)
    settings = _training_configuration(config)
    get_parameters(model)
    torch.set_num_threads(settings["cpu_threads"])
    torch.use_deterministic_algorithms(True)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    started = time.perf_counter()
    before = evaluate(model, dataset)["loss"]
    optimizer_class = torch.optim.Adam if settings["optimizer"] == "adam" else torch.optim.SGD
    optimizer = optimizer_class(model.parameters(), lr=settings["learning_rate"])
    generator = torch.Generator(device="cpu").manual_seed(seed)
    loader = DataLoader(dataset, batch_size=settings["batch_size"], shuffle=True,
                        generator=generator, num_workers=0, drop_last=False)
    loss_function = nn.BCEWithLogitsLoss()
    model.train()
    batches, total_loss, exposures = 0, 0.0, 0
    for _ in range(settings["local_epochs"]):
        for x, y in loader:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_function(model(x), y)
            if not torch.isfinite(loss):
                raise ValueError("nonfinite_training_loss")
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(y)
            exposures += len(y)
            batches += 1
    get_parameters(model)
    after = evaluate(model, dataset)["loss"]
    return {"sample_count": len(dataset), "epochs": settings["local_epochs"], "batches": batches,
            "example_exposures": exposures, "loss": total_loss / exposures, "loss_before": before,
            "loss_after": after, "seed": seed, "optimizer": settings["optimizer"],
            "duration_seconds": time.perf_counter() - started}


def classification_metrics(y_true, probabilities, threshold=0.5):
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("invalid_classification_threshold")
    y = np.asarray(y_true)
    scores = np.asarray(probabilities, dtype=np.float64)
    if (y.ndim != 1 or scores.ndim != 1 or len(y) != len(scores) or not len(y)
            or not np.isin(y, (0, 1)).all() or not np.isfinite(scores).all()
            or np.any(scores < 0) or np.any(scores > 1)):
        raise ValueError("invalid_metric_inputs")
    predicted = scores >= threshold
    positives = int(np.count_nonzero(y))
    return {"count": len(y), "positive_count": positives, "prevalence": positives / len(y),
            "auroc": float(roc_auc_score(y, scores)) if 0 < positives < len(y) else None,
            "auprc": float(average_precision_score(y, scores)) if positives else None,
            "f1": float(f1_score(y, predicted, zero_division=0)),
            "precision": float(precision_score(y, predicted, zero_division=0)),
            "recall": float(recall_score(y, predicted, zero_division=0)), "threshold": float(threshold)}


def evaluate(model, dataset, threshold=0.5):
    _validate_dataset(model, dataset)
    was_training = model.training
    model.eval()
    probabilities, labels, losses = [], [], []
    try:
        with torch.inference_mode():
            for x, y in DataLoader(dataset, batch_size=1024, shuffle=False, num_workers=0):
                logits = model(x)
                if not torch.isfinite(logits).all():
                    raise ValueError("nonfinite_evaluation_logits")
                losses.append(float(nn.functional.binary_cross_entropy_with_logits(logits, y, reduction="sum")))
                probabilities.extend(torch.sigmoid(logits).tolist())
                labels.extend(y.tolist())
        return {**classification_metrics(labels, probabilities, threshold), "loss": math.fsum(losses) / len(dataset)}
    finally:
        model.train(was_training)
