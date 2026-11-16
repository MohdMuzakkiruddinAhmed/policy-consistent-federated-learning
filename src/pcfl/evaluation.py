"""Isolated evaluator: immutable published models in, aggregates out.

Validation is the default; test data additionally requires separately trusted,
scoped frozen-plan authorization. The coordinator receives model metadata and
aggregate results, never evaluation records, labels or prediction vectors.
"""

from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import ssl
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile

import numpy as np

from . import learning

MAX_MODEL_BYTES = 32 * 1024 * 1024
MAX_REQUEST_BYTES = 512 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def parameters_digest(arrays):
    return _hash([{"dtype": value.dtype.str, "shape": list(value.shape),
                   "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest()} for value in arrays])


def _aggregate_metrics_only(metrics):
    names = {"count", "positive_count", "prevalence", "auroc", "auprc", "precision", "recall", "f1", "threshold", "loss"}
    if not isinstance(metrics, dict) or set(metrics) != names:
        raise ValueError("evaluation_aggregate_metric_schema_required")
    for key, value in metrics.items():
        if value is None and key in {"auroc", "auprc"}:
            continue
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("evaluation_scalar_metrics_required")


def _public_preprocessor(preprocessor):
    state = learning.load_preprocessor(preprocessor)
    if set(state) != {"schema_version", "fit_scope", "fit_rows", "numeric", "categorical", "feature_order", "target"}:
        raise ValueError("nonpublic_preprocessor_fields")
    for numeric in state["numeric"].values():
        if (not {"median", "mean", "scale"} <= set(numeric)
                or set(numeric) - {"median", "mean", "scale", "missing_training_rows"}):
            raise ValueError("nonpublic_preprocessor_fields")
        if "missing_training_rows" in numeric and (type(numeric["missing_training_rows"]) is not int
                or not 0 <= numeric["missing_training_rows"] <= state["fit_rows"]):
            raise ValueError("invalid_preprocessor_aggregate")
    if any(set(category) != {"missing_code", "unknown_code", "vocabulary"}
           for category in state["categorical"].values()):
        raise ValueError("nonpublic_preprocessor_fields")
    return state


def build_model_metadata(preprocessor, *, seed=296, hidden_dims=(64, 32)):
    state = _public_preprocessor(preprocessor)
    model = learning.create_model(state, seed=seed, hidden_dims=hidden_dims)
    result = {"schema_version": "0.1.0", "architecture": "tabular-mlp-v1", "seed": seed,
              "hidden_dims": list(hidden_dims), "preprocessor": state,
              "feature_schema_hash": model.feature_schema_hash, "model_schema_hash": model.schema_hash}
    return {**result, "metadata_digest": _hash(result)}


def create_model_from_metadata(metadata, *, seed_override=None):
    required = {"schema_version", "architecture", "seed", "hidden_dims", "preprocessor",
                "feature_schema_hash", "model_schema_hash", "metadata_digest"}
    if not isinstance(metadata, dict) or set(metadata) != required:
        raise ValueError("incomplete_model_metadata")
    if not isinstance(metadata["preprocessor"], dict):
        raise ValueError("public_preprocessor_mapping_required")
    if (metadata["schema_version"] != "0.1.0" or metadata["architecture"] != "tabular-mlp-v1"
            or metadata["metadata_digest"] != _hash({k: v for k, v in metadata.items() if k != "metadata_digest"})):
        raise ValueError("model_metadata_digest_or_architecture_mismatch")
    if seed_override is not None and (type(seed_override) is not int or not 0 <= seed_override < 2**32):
        raise ValueError("invalid_initialization_seed")
    model = learning.create_model(_public_preprocessor(metadata["preprocessor"]),
                                  seed=metadata["seed"] if seed_override is None else seed_override,
                                  hidden_dims=metadata["hidden_dims"])
    if model.schema_hash != metadata["model_schema_hash"] or model.feature_schema_hash != metadata["feature_schema_hash"]:
        raise ValueError("model_metadata_schema_mismatch")
    return model


def request_from_manifest(manifest, run_id, *, request_id=None):
    artifact = deepcopy(manifest["artifact"])
    logical = manifest.get("parameters_digest") or artifact.get("parameters_digest") or manifest["model_digest"]
    result = {"run_id": run_id, "round_id": manifest["round_id"], "manifest_id": manifest["manifest_id"],
              "model_schema_hash": manifest["model_schema_hash"], "parameters_digest": logical, "artifact": artifact}
    result["request_id"] = request_id or "evaluation-" + _hash(result)[:32]
    return result


class DynamoManifestResolver:
    """Resolve committed immutable metadata with the evaluator's read-only role."""

    def __init__(self, dynamodb_client, table_name, *, require_current=False):
        self.client, self.table = dynamodb_client, table_name
        if type(require_current) is not bool:
            raise ValueError("invalid_manifest_resolver_mode")
        self.require_current = require_current

    def __call__(self, run_id, manifest_id):
        def pointer():
            return self.client.get_item(TableName=self.table, ConsistentRead=True,
                Key={"PK": {"S": f"RUN#{run_id}"}, "SK": {"S": "POINTER"}}).get("Item", {})
        before = pointer() if self.require_current else None
        response = self.client.get_item(TableName=self.table, ConsistentRead=True,
            Key={"PK": {"S": f"RUN#{run_id}"}, "SK": {"S": f"MANIFEST#{manifest_id}"}})
        item = response.get("Item", {})
        if item.get("record_type") != {"S": "publication_manifest"}:
            raise ValueError("committed_manifest_missing")
        try:
            manifest = json.loads(item["manifest_json"]["S"])
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError("committed_manifest_unreadable") from None
        if (manifest.get("run_id") != run_id or manifest.get("manifest_id") != manifest_id
                or type(manifest.get("commit_order")) is not int or manifest["commit_order"] < 1):
            raise ValueError("committed_manifest_identity_mismatch")
        if self.require_current:
            after = pointer()
            if (not before or before != after or before.get("manifest_id") != {"S": manifest_id}
                    or before.get("round_id") != {"S": manifest["round_id"]}
                    or before.get("commit_order") != {"N": str(manifest["commit_order"])}):
                raise ValueError("final_committed_pointer_binding_mismatch")
        return manifest


class EvaluationService:
    def __init__(self, metadata, validation_path, validation_sha256, *, model_root=None,
                 max_examples=512, seed=296, s3_client=None, allowed_bucket=None,
                 allowed_prefix="models/candidates/", manifest_resolver=None, dataset_role="validation",
                 accepted_plan=None, holdout_authorization=None):
        self.metadata = deepcopy(metadata)
        self.holdout_scope = None
        if dataset_role not in {"validation", "test"}:
            raise ValueError("unknown_evaluation_dataset_role")
        if dataset_role == "test":
            from .holdout import validate_authorization
            schema = self.metadata.get("model_schema_hash") if isinstance(self.metadata, dict) else None
            self.holdout_scope = validate_authorization(accepted_plan, holdout_authorization, model_schema_hash=schema)
            if (not isinstance(manifest_resolver, DynamoManifestResolver) or not manifest_resolver.require_current
                    or s3_client is None or not allowed_bucket):
                raise ValueError("final_holdout_requires_current_durable_s3_manifest_resolver")
            if validation_sha256 != self.holdout_scope.test_sha256:
                raise ValueError("authorized_test_source_digest_mismatch")
        elif accepted_plan is not None or holdout_authorization is not None:
            raise ValueError("holdout_authorization_requires_explicit_test_role")
        self.dataset_role = dataset_role
        create_model_from_metadata(self.metadata)
        validation = Path(validation_path)
        if validation.name != dataset_role + ".csv":
            raise ValueError("only_" + dataset_role + "_split_allowed")
        if not isinstance(validation_sha256, str) or not _HASH.fullmatch(validation_sha256):
            raise ValueError("invalid_validation_digest")
        if hashlib.sha256(validation.read_bytes()).hexdigest() != validation_sha256:
            raise ValueError("validation_source_digest_mismatch")
        if type(max_examples) is not int or not 1 <= max_examples <= 1_000_000:
            raise ValueError("invalid_evaluation_example_budget")
        self.dataset = learning.load_partition(validation, self.metadata["preprocessor"],
            max_examples=None if self.holdout_scope else max_examples, seed=seed)
        if self.dataset.source_sha256 != validation_sha256:
            raise ValueError("validation_source_changed_during_load")
        if self.holdout_scope and (len(self.dataset) != self.dataset.source_rows or len(self.dataset) > max_examples):
            raise ValueError("full_authorized_test_cohort_required")
        self.validation_sha = validation_sha256
        self.model_root = Path(model_root).resolve() if model_root is not None else None
        self.s3, self.bucket, self.prefix = s3_client, allowed_bucket, allowed_prefix
        if not isinstance(allowed_prefix, str) or not allowed_prefix or ".." in allowed_prefix:
            raise ValueError("invalid_evaluation_model_prefix")
        self.resolve_manifest = manifest_resolver
        self.cache, self.lock, self.evaluation_count = OrderedDict(), threading.RLock(), 0
        self.final_results = {}

    def _validate_request(self, request):
        fields = {"request_id", "run_id", "round_id", "manifest_id", "model_schema_hash", "parameters_digest", "artifact"}
        if not isinstance(request, dict) or set(request) != fields:
            raise ValueError("incomplete_evaluation_request")
        for field in ("request_id", "run_id", "round_id"):
            if not isinstance(request[field], str) or not _ID.fullmatch(request[field]):
                raise ValueError("invalid_evaluation_identity")
        for field in ("manifest_id", "model_schema_hash", "parameters_digest"):
            if not isinstance(request[field], str) or not _HASH.fullmatch(request[field]):
                raise ValueError("invalid_evaluation_digest")
        if request["model_schema_hash"] != self.metadata["model_schema_hash"]:
            raise ValueError("evaluation_model_schema_mismatch")
        if self.holdout_scope:
            self.holdout_scope.cell_for(request["run_id"], request["round_id"])
        artifact = request["artifact"]
        if not isinstance(artifact, dict):
            raise ValueError("invalid_evaluation_artifact")
        if self.holdout_scope and artifact.get("backend") != "s3":
            raise ValueError("final_holdout_requires_committed_immutable_s3_model")
        for alias in ("model_digest", "parameters_digest"):
            if alias in artifact and artifact[alias] != request["parameters_digest"]:
                raise ValueError("artifact_parameters_digest_mismatch")

    def _confirm_manifest(self, request):
        if self.resolve_manifest is None:
            if request["artifact"].get("backend") != "local_immutable_checkpoint":
                raise ValueError("independent_committed_manifest_resolver_required")
            return False
        manifest = self.resolve_manifest(request["run_id"], request["manifest_id"])
        candidate = manifest.get("candidate", manifest.get("candidate_metadata", {}))
        schema = manifest.get("model_schema_hash", candidate.get("model_schema_hash"))
        logical = manifest.get("parameters_digest", manifest.get("model_digest"))
        if (manifest.get("manifest_id") != request["manifest_id"] or manifest.get("run_id") != request["run_id"]
                or manifest.get("round_id") != request["round_id"] or schema != request["model_schema_hash"]
                or logical != request["parameters_digest"] or type(manifest.get("commit_order")) is not int
                or manifest["commit_order"] < 1):
            raise ValueError("evaluation_committed_manifest_binding_mismatch")
        stored = candidate.get("s3", manifest.get("artifact", {}))
        for field in ("bucket", "key", "version_id", "sha256", "size_bytes"):
            if stored.get(field) != request["artifact"].get(field):
                raise ValueError("evaluation_committed_artifact_binding_mismatch")
        return True

    def _model_bytes(self, artifact):
        if artifact.get("backend") == "local_immutable_checkpoint":
            if self.model_root is None:
                raise ValueError("local_evaluation_artifacts_disabled")
            path = Path(artifact.get("path", "")).resolve()
            if not path.is_relative_to(self.model_root) or path.suffix != ".npz":
                raise ValueError("evaluation_artifact_outside_owned_root")
            if path.stat().st_size > MAX_MODEL_BYTES:
                raise ValueError("evaluation_model_size_limit")
            with path.open("rb") as stream:
                content = stream.read(MAX_MODEL_BYTES + 1)
            expected = artifact.get("file_sha256")
        elif artifact.get("backend") == "s3":
            if self.s3 is None or not self.bucket or artifact.get("bucket") != self.bucket:
                raise ValueError("evaluation_bucket_not_allowed")
            key, version = artifact.get("key"), artifact.get("version_id")
            if (not isinstance(key, str) or not key.startswith(self.prefix) or ".." in key.split("/")
                    or not isinstance(version, str) or not version or version == "null"):
                raise ValueError("evaluation_immutable_s3_reference_required")
            size = artifact.get("size_bytes")
            if type(size) is not int or not 0 < size <= MAX_MODEL_BYTES:
                raise ValueError("evaluation_model_size_limit")
            response = self.s3.get_object(Bucket=self.bucket, Key=key, VersionId=version)
            body = response["Body"]
            try:
                content = body.read(MAX_MODEL_BYTES + 1)
            finally:
                body.close()
            if response.get("VersionId") != version or response.get("ContentLength") != size or len(content) != size:
                raise ValueError("evaluation_s3_version_or_size_mismatch")
            expected = artifact.get("sha256")
        else:
            raise ValueError("unsupported_evaluation_artifact")
        if (len(content) > MAX_MODEL_BYTES or not isinstance(expected, str) or not _HASH.fullmatch(expected)
                or hashlib.sha256(content).hexdigest() != expected):
            raise ValueError("evaluation_model_byte_digest_mismatch")
        return content

    def evaluate(self, request):
        self._validate_request(request)
        fingerprint = _hash({"request": request, "metadata": self.metadata["metadata_digest"],
                             "validation_sha256": self.validation_sha, "sample": self.dataset.sampled_positions_digest})
        with self.lock:
            if request["request_id"] in self.cache:
                old_fingerprint, response = self.cache[request["request_id"]]
                if old_fingerprint != fingerprint:
                    raise ValueError("evaluation_request_id_rebound")
                return deepcopy(response)
            final_fingerprint = _hash({key: value for key, value in request.items() if key != "request_id"})
            if self.holdout_scope and request["run_id"] in self.final_results:
                previous, response = self.final_results[request["run_id"]]
                if previous != final_fingerprint:
                    raise ValueError("authorized_run_already_bound_to_final_model")
                return {**deepcopy(response), "request_id": request["request_id"]}
            committed = self._confirm_manifest(request)
            content = self._model_bytes(request["artifact"])
            model = create_model_from_metadata(self.metadata)
            expected_arrays = learning.get_parameters(model)
            with zipfile.ZipFile(io.BytesIO(content)) as bundle:
                if sum(item.file_size for item in bundle.infolist()) > MAX_MODEL_BYTES:
                    raise ValueError("evaluation_uncompressed_model_size_limit")
                if set(bundle.namelist()) != {f"arr_{index}.npy" for index in range(len(expected_arrays))}:
                    raise ValueError("evaluation_parameter_archive_keys")
                # Inspect small NPY headers before NumPy allocates from a hostile
                # declared shape. The expected architecture bounds every array.
                for index, expected in enumerate(expected_arrays):
                    with bundle.open(f"arr_{index}.npy") as member:
                        version = np.lib.format.read_magic(member)
                        if version not in {(1, 0), (2, 0)}:
                            raise ValueError("evaluation_parameter_format_version")
                        reader = np.lib.format.read_array_header_1_0 if version == (1, 0) else np.lib.format.read_array_header_2_0
                        shape, _, dtype = reader(member, max_header_size=4096)
                        if shape != expected.shape or dtype != np.dtype("float32"):
                            raise ValueError("evaluation_parameter_header_mismatch")
            with np.load(io.BytesIO(content), allow_pickle=False) as archive:
                if set(archive.files) != {f"arr_{index}" for index in range(len(archive.files))}:
                    raise ValueError("evaluation_parameter_archive_keys")
                arrays = [archive[f"arr_{index}"].copy() for index in range(len(archive.files))]
            if parameters_digest(arrays) != request["parameters_digest"]:
                raise ValueError("evaluation_parameters_digest_mismatch")
            learning.set_parameters(model, arrays)
            metrics = learning.evaluate(model, self.dataset, threshold=0.5)
            _aggregate_metrics_only(metrics)
            response = {"schema_version": "0.1.0", "request_id": request["request_id"],
                "run_id": request["run_id"], "round_id": request["round_id"], "manifest_id": request["manifest_id"],
                "model_schema_hash": request["model_schema_hash"], "parameters_digest": request["parameters_digest"],
                "model_sha256": hashlib.sha256(content).hexdigest(), "metadata_digest": self.metadata["metadata_digest"],
                "validation_sha256": self.validation_sha, "validation_sample_digest": self.dataset.sampled_positions_digest,
                "dataset_role": "validation", "final_test_evaluated": False, "manifest_verified": committed,
                "metrics": metrics}
            if self.holdout_scope:
                scope = self.holdout_scope
                response.pop("validation_sha256")
                response.pop("validation_sample_digest")
                response.update(dataset_role="test", final_test_evaluated=True,
                    test_sha256=scope.test_sha256, test_sample_digest=self.dataset.sampled_positions_digest,
                    accepted_plan_digest=scope.plan_digest, holdout_authorization_digest=scope.authorization_digest,
                    holdout_authorization_id=scope.authorization_id, cell_id=scope.cell_for(request["run_id"], request["round_id"]))
                if committed is not True:
                    raise ValueError("final_holdout_requires_verified_publication")
                self.final_results[request["run_id"]] = (final_fingerprint, deepcopy(response))
            self.evaluation_count += 1
            self.cache[request["request_id"]] = (fingerprint, deepcopy(response))
            if len(self.cache) > 256:
                self.cache.popitem(last=False)
            return response


def make_evaluation_server(service, address, *, certificate, private_key, client_ca, private_network=False,
                           expected_client_cn=None):
    if not private_network and address[0] != "localhost" and not ipaddress.ip_address(address[0]).is_loopback:
        raise ValueError("evaluation_listener_must_be_loopback")
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            if expected_client_cn is not None:
                subject = self.connection.getpeercert().get("subject", ())
                names = [value for group in subject for name, value in group if name == "commonName"]
                if names != [expected_client_cn]:
                    self.send_error(403)
                    return
            if self.path != "/evaluate":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST_BYTES or self.headers.get("Transfer-Encoding"):
                    raise ValueError("evaluation_request_size_limit")
                result = service.evaluate(json.loads(self.rfile.read(length)))
                code = 200
            except (ValueError, TypeError, KeyError, zipfile.BadZipFile):
                result, code = {"error": "evaluation_request_rejected"}, 400
            except Exception:
                result, code = {"error": "evaluation_unavailable"}, 503
            content = _canonical(result)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(content)
            self.close_connection = True

    class SecureServer(ThreadingHTTPServer):
        def get_request(self):
            connection, peer = super().get_request()
            connection.settimeout(5)
            return connection, peer

        def handle_error(self, request, client_address):
            # TLS/HTTP failures must not dump request or model/data context.
            pass

    server = SecureServer(address, Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    context.load_verify_locations(cafile=str(client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def validate_test_response(response, request, expectation):
    """Bind a test response to explicit deployment expectations, never grant access."""
    from .holdout import validate_expectation
    expected = validate_expectation(expectation)
    fields = {"schema_version", "request_id", "run_id", "round_id", "manifest_id", "model_schema_hash", "parameters_digest",
        "model_sha256", "metadata_digest", "dataset_role", "final_test_evaluated", "manifest_verified", "metrics",
        "test_sha256", "test_sample_digest", "accepted_plan_digest", "holdout_authorization_digest", "holdout_authorization_id", "cell_id"}
    if (not isinstance(response, dict) or set(response) != fields or response.get("schema_version") != "0.1.0"
            or response.get("dataset_role") != "test" or response.get("final_test_evaluated") is not True
            or response.get("manifest_verified") is not True
            or any(response.get(name) != request[name] for name in ("request_id", "run_id", "round_id", "manifest_id", "model_schema_hash", "parameters_digest"))
            or response.get("accepted_plan_digest") != expected["plan_digest"]
            or response.get("holdout_authorization_digest") != expected["authorization_digest"]
            or response.get("test_sha256") != expected["test_sha256"] or response.get("cell_id") != expected["cell_id"]
            or response.get("model_sha256") != request.get("artifact", {}).get("sha256")
            or any(not isinstance(response.get(name), str) or not _HASH.fullmatch(response[name]) for name in
                   ("model_sha256", "metadata_digest", "test_sha256", "test_sample_digest", "accepted_plan_digest", "holdout_authorization_digest"))
            or not isinstance(response.get("holdout_authorization_id"), str) or not _ID.fullmatch(response["holdout_authorization_id"])):
        raise RuntimeError("final_holdout_response_binding_mismatch")
    _aggregate_metrics_only(response["metrics"])
    metrics = response["metrics"]
    if (type(metrics["count"]) is not int or metrics["count"] < 1 or type(metrics["positive_count"]) is not int
            or not 0 <= metrics["positive_count"] <= metrics["count"] or metrics["threshold"] != 0.5
            or metrics["prevalence"] != metrics["positive_count"] / metrics["count"]
            or any(value is not None and (value < 0 or (key != "loss" and value > 1))
                   for key, value in metrics.items() if key not in {"count", "positive_count"})):
        raise RuntimeError("final_holdout_aggregate_metrics_invalid")
    return response


class EvaluationClient:
    def __init__(self, endpoint, *, ca_cert, client_cert, client_key, timeout=30, expected_holdout=None):
        if expected_holdout is not None:
            from .holdout import validate_expectation
            expected_holdout = validate_expectation(expected_holdout)
        self.expected_holdout = deepcopy(expected_holdout)
        parsed = urlparse(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("evaluation_https_endpoint_required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 300:
            raise ValueError("evaluation_client_timeout_out_of_bounds")
        self.endpoint, self.timeout = endpoint.rstrip("/") + "/evaluate", timeout
        self.context = ssl.create_default_context(cafile=str(ca_cert))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(client_cert), str(client_key))

    def evaluate(self, request):
        call = Request(self.endpoint, data=_canonical(request), method="POST", headers={"Content-Type": "application/json"})
        try:
            with urlopen(call, context=self.context, timeout=self.timeout) as response:
                content = response.read(MAX_REQUEST_BYTES + 1)
                if len(content) > MAX_REQUEST_BYTES:
                    raise ValueError("evaluation_response_size_limit")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise ValueError("evaluation_response_object_required")
                if self.expected_holdout is not None:
                    return validate_test_response(result, request, self.expected_holdout)
                if set(result) != {"schema_version", "request_id", "run_id", "round_id", "manifest_id",
                        "model_schema_hash", "parameters_digest", "model_sha256", "metadata_digest", "validation_sha256",
                        "validation_sample_digest", "dataset_role", "final_test_evaluated", "manifest_verified", "metrics"}:
                    raise ValueError("evaluation_response_schema_required")
                _aggregate_metrics_only(result["metrics"])
        except (HTTPError, URLError, OSError, HTTPException, ValueError):
            raise RuntimeError("isolated_evaluation_failed_closed") from None
        for field in ("request_id", "run_id", "round_id", "manifest_id", "model_schema_hash", "parameters_digest"):
            if result.get(field) != request[field]:
                raise RuntimeError("isolated_evaluation_response_binding_mismatch")
        if result.get("dataset_role") != "validation" or result.get("final_test_evaluated") is not False:
            raise RuntimeError("isolated_evaluation_split_mismatch")
        return result


def create_local_evaluation_tls(directory):
    """Generate separate local evaluator/server and coordinator/client identities."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PCFL local evaluator CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA384()))
    result = {"ca_cert": directory / "ca.pem"}
    result["ca_cert"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for role, usage in (("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = ec.generate_private_key(ec.SECP384R1())
        certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([usage]), False))
        if role == "server":
            certificate = certificate.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        certificate = certificate.sign(ca_key, hashes.SHA384())
        for suffix, content in (("cert", certificate.public_bytes(serialization.Encoding.PEM)),
                ("key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))):
            path = directory / f"{role}.{suffix}.pem"
            with path.open("xb") as stream:
                stream.write(content)
            os.chmod(path, 0o600)
            result[f"{role}_{suffix}"] = path
    return result
