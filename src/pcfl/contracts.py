"""Small immutable contracts for the local protocol state model."""

from dataclasses import asdict, dataclass
import hashlib
import json
import math

ACTIONS = ("train", "submit_update", "aggregate")
ORGANIZATIONS = tuple(f"org_{i:02d}" for i in range(1, 9))
SCHEMA_VERSION = "0.1.0"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


@dataclass(frozen=True)
class TaskAuthorization:
    task_id: str
    org_id: str
    purpose: str
    round_id: str
    start_order: int
    policy_epoch: int
    policy_hash: str
    model_schema_hash: str
    nonce: str


@dataclass(frozen=True)
class ModelUpdate:
    update_id: str
    task: TaskAuthorization
    sample_count: int
    weights: tuple[float, ...]
    weights_digest: str

    @classmethod
    def create(cls, update_id: str, task: TaskAuthorization, sample_count: int,
               weights: tuple[float, ...]) -> "ModelUpdate":
        immutable_weights = tuple(float(v) for v in weights)
        return cls(update_id, task, sample_count, immutable_weights, digest(immutable_weights))

    def validate(self, dimension: int) -> None:
        if not isinstance(self.update_id, str) or not self.update_id.strip():
            raise ValueError("missing_update_id")
        if not positive_integer(self.sample_count):
            raise ValueError("invalid_sample_count")
        if not isinstance(self.weights, tuple) or len(self.weights) != dimension:
            raise ValueError("invalid_model_shape")
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in self.weights):
            raise ValueError("non_finite_weights")
        if self.weights_digest != digest(self.weights):
            raise ValueError("weights_digest_mismatch")

    def fingerprint(self) -> str:
        return digest(asdict(self))
