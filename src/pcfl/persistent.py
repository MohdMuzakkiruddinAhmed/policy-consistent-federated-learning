"""Persistent P1 lifecycle adapter using conditional DynamoDB and versioned S3.

Clients are injected: this module never discovers credentials, creates resources,
or silently selects an endpoint. A separately authenticated policy authority owns
policy mutations. The evaluator must be the pinned OPA decision client.
"""

from copy import deepcopy
import hashlib
import io
import json
import re
import secrets
import threading
import zipfile
from urllib.parse import urlparse

import numpy as np

from . import aws_transactions as tx
from .contracts import ACTIONS, ORGANIZATIONS, canonical, digest
from .reference import validate_event


class PersistentUnavailable(RuntimeError):
    pass


class PersistentConflict(RuntimeError):
    pass


def arrays_digest(arrays):
    return digest([{"dtype": value.dtype.str, "shape": list(value.shape),
                    "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest()} for value in arrays])


def validate_arrays(arrays, template):
    if not isinstance(arrays, (list, tuple)) or len(arrays) != len(template) or not arrays:
        raise ValueError("invalid_parameter_count")
    for value, expected in zip(arrays, template, strict=True):
        if (not isinstance(value, np.ndarray) or value.dtype != np.float32
                or value.shape != expected.shape or not np.isfinite(value).all()):
            raise ValueError("invalid_parameter_shape_dtype_or_finiteness")


def _decode(item):
    result = {}
    for key, value in item.items():
        if set(value) == {"S"}:
            result[key] = value["S"]
        elif set(value) == {"N"}:
            result[key] = int(value["N"])
        elif set(value) == {"BOOL"}:
            result[key] = value["BOOL"]
        elif set(value) == {"NULL"} and value["NULL"] is True:
            result[key] = None
        else:
            raise PersistentUnavailable("unsupported_persistent_attribute")
    return result


def _fields(mapping):
    return {key: tx._attribute(value) for key, value in mapping.items()}


def _repack(request, additions=()):
    """Bind every augmented action to the durable outcome and idempotency token."""
    request = deepcopy(request)
    request["TransactItems"].extend(deepcopy(list(additions)))
    outcomes = [action["Put"]["Item"] for action in request["TransactItems"]
                if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": "transaction_outcome"}]
    if len(outcomes) != 1:
        raise ValueError("unique_durable_outcome_required")
    outcomes[0]["request_digest"] = {"S": ""}
    fingerprint = digest(request["TransactItems"])
    outcomes[0]["request_digest"] = {"S": fingerprint}
    request["ClientRequestToken"] = digest(request["TransactItems"])[:36]
    tx.validate_transaction_request(request)
    return request


class PersistentAuthority:
    """P1-only authority; baselines retain their explicitly weaker local adapter."""

    def __init__(self, dynamodb, s3, *, table_name, bucket, run_id, template,
                 model_schema_hash, policy_evaluator, rule_hash, max_examples=256,
                 max_attempts=8, expected_bucket_owner=None, initialize=False,
                 policy_mutator=None, allow_policy_writes=False, local_emulation=False,
                 s3_encryption="AES256"):
        tx._table(table_name)
        tx._identifier(run_id, "run_id")
        tx._hash(model_schema_hash, "model_schema_hash")
        tx._hash(rule_hash, "rule_hash")
        if type(max_examples) is not int or max_examples < 1 or type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("invalid_persistent_limits")
        validate_arrays(template, template)
        if not callable(policy_evaluator):
            raise ValueError("pinned_policy_evaluator_required")
        if expected_bucket_owner is not None and not re.fullmatch(r"[0-9]{12}", expected_bucket_owner):
            raise ValueError("invalid_expected_bucket_owner")
        if s3_encryption is None:
            endpoint = getattr(getattr(s3, "meta", None), "endpoint_url", "")
            if not local_emulation or urlparse(endpoint).hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("unencrypted_object_test_requires_explicit_loopback_emulation")
        elif s3_encryption != "AES256":
            raise ValueError("unsupported_object_encryption")
        self.ddb, self.s3, self.table, self.bucket, self.run_id = dynamodb, s3, table_name, bucket, run_id
        self.pk = f"RUN#{run_id}"
        self.template = [value.copy() for value in template]
        self.schema_hash, self.rule_hash = model_schema_hash, rule_hash
        self.evaluate, self.policy_mutator = policy_evaluator, policy_mutator
        self.max_examples, self.max_attempts = max_examples, max_attempts
        self.owner, self.encryption = expected_bucket_owner, s3_encryption
        self.allow_policy_writes = allow_policy_writes
        self.lock = threading.RLock()
        self._issued, self._local_artifacts, self.selection = {}, {}, []
        self.conflicts = 0
        if initialize:
            if not self.item("AUTHORITY", "SEQUENCE"):
                if not allow_policy_writes:
                    raise PersistentUnavailable("operator_must_initialize_authority")
                identifier = self._txn_id("initialize-authority")
                self._transact(tx.build_initialize_authority(self.table, txn_id=identifier), identifier, authority=True)
            if allow_policy_writes:
                for org in ORGANIZATIONS:
                    if not self.item(f"POLICY#{org}", "CURRENT"):
                        self.mutate(org, "GRANT")
        if self.s3.get_bucket_versioning(Bucket=self.bucket, **self._owner()).get("Status") != "Enabled":
            raise PersistentUnavailable("versioned_model_bucket_required")

    def _owner(self):
        return {"ExpectedBucketOwner": self.owner} if self.owner else {}

    def _txn_id(self, prefix):
        return f"{prefix}-{secrets.token_hex(12)}"

    def item(self, pk, sk):
        return _decode(self.ddb.get_item(TableName=self.table, Key=tx._key(pk, sk), ConsistentRead=True).get("Item", {}))

    def query(self, pk):
        request = {"TableName": self.table, "ConsistentRead": True,
                   "KeyConditionExpression": "#pk = :pk", "ExpressionAttributeNames": {"#pk": "PK"},
                   "ExpressionAttributeValues": {":pk": {"S": pk}}}
        records = []
        while True:
            response = self.ddb.query(**request)
            records.extend(_decode(item) for item in response.get("Items", []))
            if not response.get("LastEvaluatedKey"):
                return records
            request["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    def _transact(self, request, txn_id, *, authority=False):
        """Resolve ambiguous responses by a strong read of the atomic outcome."""
        expected = tx.expected_outcome_digest(request)
        try:
            self.ddb.transact_write_items(**request)
        except Exception as error:
            try:
                outcome = _decode(self.ddb.get_item(**tx.recovery_get_request(
                    self.table, txn_id, run_id=None if authority else self.run_id)).get("Item", {}))
            except Exception as recovery:
                raise PersistentUnavailable("transaction_outcome_indeterminate") from recovery
            if outcome:
                if outcome.get("request_digest") != expected:
                    raise PersistentUnavailable("durable_transaction_id_rebound") from error
                return json.loads(outcome["result_json"])
            code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
            if code in {"TransactionCanceledException", "ConditionalCheckFailedException", "TransactionConflictException"}:
                self.conflicts += 1
                raise PersistentConflict("authoritative_transaction_conflict") from error
            raise PersistentUnavailable("transaction_not_confirmed") from error
        outcome = self.item("AUTHORITY" if authority else self.pk, f"TXN#{txn_id}")
        if outcome.get("request_digest") != expected:
            raise PersistentUnavailable("successful_transaction_missing_durable_outcome")
        return json.loads(outcome["result_json"])

    def _manual(self, actions, txn_id, kind, order, result, *, authority=False):
        outcome = tx._outcome_action(self.table, "AUTHORITY" if authority else self.pk,
                                    txn_id, kind, order, "0" * 64, result)
        return _repack({"TransactItems": [*actions, outcome], "ReturnConsumedCapacity": "TOTAL"})

    def snapshot(self):
        """A monotonic sequence fence makes the fully paginated snapshot coherent."""
        for _ in range(self.max_attempts):
            sequence = self.item("AUTHORITY", "SEQUENCE")
            if type(sequence.get("order")) is not int:
                raise PersistentUnavailable("missing_authority_sequence")
            histories, current, events, policy_records, seen_ids, seen_orders = {}, {}, [], [], set(), set()
            for org in ORGANIZATIONS:
                records = self.query(f"POLICY#{org}")
                policy_records.extend(records)
                states = [record for record in records if record["SK"] == "CURRENT"]
                history_records = [record for record in records if record["SK"].startswith("EVENT#")]
                history = sorted((json.loads(record["event_json"]) for record in history_records), key=lambda event: event["order"])
                if len(states) != 1 or not history:
                    raise PersistentUnavailable("missing_complete_policy_history")
                state = states[0]
                for record in history_records:
                    event = json.loads(record["event_json"])
                    if (record.get("policy_hash") != digest(event)
                            or record["SK"] != f"EVENT#{event['order']:020d}"):
                        raise PersistentUnavailable("policy_history_record_digest_mismatch")
                for epoch, event in enumerate(history, 1):
                    validate_event(event)
                    if (event["org_id"] != org or event["epoch"] != epoch
                            or event["event_id"] in seen_ids or event["order"] in seen_orders):
                        raise PersistentUnavailable("policy_history_chain_invalid")
                    seen_ids.add(event["event_id"])
                    seen_orders.add(event["order"])
                if state["epoch"] != history[-1]["epoch"] or state["policy_hash"] != digest(history[-1]):
                    raise PersistentUnavailable("policy_history_tail_mismatch")
                histories[org], current[org] = history, state
                events.extend(history)
            records = self.query(self.pk)
            after = self.item("AUTHORITY", "SEQUENCE")
            if sequence["order"] != after.get("order"):
                continue
            if any(event["order"] > sequence["order"] for event in events):
                raise PersistentUnavailable("policy_event_beyond_authority_sequence")
            items = {record["SK"]: record for record in records}
            if any(f"ROUND#{record['round_id']}" not in items for sk, record in items.items() if sk.startswith("UPDATE#")):
                raise PersistentUnavailable("update_missing_round_membership")
            for sk, record in items.items():
                if sk.startswith("ROUND#"):
                    round_id = sk[len("ROUND#"):]
                    pending = [item for key, item in items.items() if key.startswith("UPDATE#")
                               and item["round_id"] == round_id and item["status"] == "pending"]
                    if record["pending_count"] != len(pending):
                        raise PersistentUnavailable("pending_membership_snapshot_incomplete")
            return {"order": sequence["order"], "histories": histories, "current": current,
                    "events": sorted(events, key=lambda event: event["order"]), "items": items,
                    "policy_records": policy_records, "sequence": sequence}
        raise PersistentUnavailable("coherent_snapshot_retry_exhausted")

    def _policy(self, snapshot, org, start, end):
        query = {"org_id": org, "purpose": "readmission", "start_order": start,
                 "commit_order": end, "actions": list(ACTIONS)}
        result = self.evaluate(deepcopy(snapshot["events"]), query)
        if (not isinstance(result, dict) or type(result.get("valid")) is not bool
                or result.get("rule_hash") != self.rule_hash
                or not isinstance(result.get("decision_id"), str) or not result["decision_id"]):
            raise PersistentUnavailable("unverifiable_policy_decision")
        if "query" in result and result["query"] != query:
            raise PersistentUnavailable("policy_decision_query_mismatch")
        return deepcopy(result)

    def _authorization(self, snapshot, org, start, end, *, stage, task_id=None):
        return self._policy(snapshot, org, start, end)

    def _acknowledgment_policy(self, snapshot, stored):
        state = snapshot["current"][stored["org_id"]]
        if state["epoch"] != stored["policy_epoch"] or state["policy_hash"] != stored["policy_hash"]:
            raise ValueError("authorization_changed_before_acknowledgment")

    def _candidate_context(self, context):
        return context

    def _publication_request(self, **kwargs):
        return tx.build_publication(self.table, **kwargs)

    def _ensure_round(self, round_id):
        tx._identifier(round_id, "round_id")
        for _ in range(self.max_attempts):
            snapshot = self.snapshot()
            record = snapshot["items"].get(f"ROUND#{round_id}")
            if record:
                return snapshot
            identifier = self._txn_id("initialize-round")
            if "POINTER" not in snapshot["items"]:
                request = tx.build_initialize_run(self.table, run_id=self.run_id, round_id=round_id,
                    expected_order=snapshot["order"], txn_id=identifier)
            else:
                request = self._manual([tx._sequence_action(self.table, snapshot["order"], identifier),
                    tx._put(self.table, self.pk, f"ROUND#{round_id}", {"status": "OPEN", "generation": 0, "pending_count": 0})],
                    identifier, "initialize_round", snapshot["order"] + 1, {"round_id": round_id})
            try:
                self._transact(request, identifier)
                return self.snapshot()
            except PersistentConflict:
                continue
        raise PersistentUnavailable("round_initialization_retry_exhausted")

    def mutate(self, org, kind):
        if self.policy_mutator is not None:
            return self.policy_mutator(org, kind)
        if not self.allow_policy_writes:
            raise PersistentUnavailable("policy_mutation_requires_separate_authority")
        if org not in ORGANIZATIONS or kind not in {"GRANT", "REVOKE", "EXPIRE"}:
            raise ValueError("invalid_policy_transition")
        for _ in range(self.max_attempts):
            sequence = self.item("AUTHORITY", "SEQUENCE")["order"]
            state = self.item(f"POLICY#{org}", "CURRENT")
            identifier = self._txn_id("policy")
            event = {"event_id": identifier, "org_id": org, "order": sequence + 1,
                     "epoch": state.get("epoch", 0) + 1, "kind": kind,
                     "rules": [{"purpose": "readmission", "action": action, "effect": "allow"}
                               for action in ACTIONS] if kind == "GRANT" else []}
            try:
                self._transact(tx.build_policy_mutation(self.table, expected_order=sequence,
                    expected_epoch=state.get("epoch", 0), event=event, txn_id=identifier), identifier, authority=True)
                return event
            except PersistentConflict:
                continue
        raise PersistentUnavailable("policy_mutation_retry_exhausted")

    def issue(self, org, node_id, round_id):
        if org not in ORGANIZATIONS or type(node_id) is not int or not 0 < node_id < 2**64:
            raise ValueError("invalid_registered_identity")
        with self.lock:
            for _ in range(self.max_attempts):
                snapshot = self._ensure_round(round_id)
                if snapshot["items"][f"ROUND#{round_id}"]["status"] != "OPEN":
                    raise ValueError("round_already_closed")
                decision = self._authorization(snapshot, org, snapshot["order"], snapshot["order"], stage="issue", task_id=f"{round_id}-{org}")
                self.selection.append({"org_id": org, "round_id": round_id, "selected": decision["valid"], "order": snapshot["order"]})
                if not decision["valid"]:
                    return None
                task_id = f"{round_id}-{org}"
                if f"ISSUE#{task_id}" in snapshot["items"]:
                    raise ValueError("duplicate_task_assignment_requires_existing_acknowledgment")
                state = snapshot["current"][org]
                task = {"task_id": task_id, "update_id": f"update-{task_id}", "org_id": org,
                        "node_id": node_id, "round_id": round_id, "purpose": "readmission",
                        "issue_order": snapshot["order"] + 1, "start_order": None,
                        "policy_epoch": state["epoch"], "policy_hash": state["policy_hash"],
                        "model_schema_hash": self.schema_hash, "nonce": secrets.token_hex(16)}
                redacted = {key: value for key, value in task.items() if key != "nonce"}
                identifier = self._txn_id("issue")
                request = self._manual([tx._sequence_action(self.table, snapshot["order"], identifier),
                    tx._policy_guard(self.table, org, state["epoch"], state["policy_hash"]),
                    {"ConditionCheck": {"TableName": self.table, "Key": tx._key(self.pk, f"ROUND#{round_id}"),
                        "ConditionExpression": "#status = :open", "ExpressionAttributeNames": {"#status": "status"},
                        "ExpressionAttributeValues": {":open": {"S": "OPEN"}}}},
                    tx._put(self.table, self.pk, f"ISSUE#{task_id}", {"status": "ISSUED", "task_json": tx._json(redacted),
                        "nonce_digest": digest(task["nonce"]), "opa_decision_json": tx._json(decision)}),
                    tx._put(self.table, self.pk, f"ISSUE_ORG#{round_id}#{org}", {"task_id": task_id})],
                    identifier, "issue", task["issue_order"], {"task_id": task_id})
                try:
                    self._transact(request, identifier)
                    self._issued[task_id] = task
                    return deepcopy(task)
                except PersistentConflict:
                    continue
        raise PersistentUnavailable("task_issue_retry_exhausted")

    def acknowledge(self, task_id, source_node, echoed_task):
        with self.lock:
            for _ in range(self.max_attempts):
                snapshot = self.snapshot()
                issued = snapshot["items"].get(f"ISSUE#{task_id}")
                if not issued or not isinstance(echoed_task, dict):
                    raise ValueError("unknown_task_acknowledgment")
                stored = json.loads(issued["task_json"])
                redacted = {key: value for key, value in echoed_task.items() if key != "nonce"}
                if (redacted != stored or type(source_node) is not int or source_node != stored["node_id"]
                        or digest(echoed_task.get("nonce")) != issued["nonce_digest"]):
                    raise ValueError("authorization_acknowledgment_mismatch")
                existing = snapshot["items"].get(f"TASK#{task_id}")
                if existing:
                    return {**deepcopy(echoed_task), "start_order": existing["start_order"]}
                if snapshot["items"][f"ROUND#{stored['round_id']}"]["status"] != "OPEN":
                    raise ValueError("round_already_closed")
                self._acknowledgment_policy(snapshot, stored)
                start = snapshot["order"] + 1
                decision = self._authorization(snapshot, stored["org_id"], start, start, stage="acknowledge", task_id=task_id)
                if not decision["valid"]:
                    raise ValueError("dispatch_denied")
                task = {key: stored[key] for key in ("task_id", "org_id", "purpose", "policy_epoch", "policy_hash", "model_schema_hash")}
                task.update(start_order=start, nonce_digest=issued["nonce_digest"])
                identifier = self._txn_id("ack")
                request = tx.build_task_authorization(self.table, run_id=self.run_id, round_id=stored["round_id"],
                    expected_order=snapshot["order"], task=task, txn_id=identifier)
                for action in request["TransactItems"]:
                    if "Put" in action and action["Put"]["Item"]["SK"] == {"S": f"TASK#{task_id}"}:
                        action["Put"]["Item"].update(_fields({"node_id": source_node, "update_id": stored["update_id"],
                            "issue_order": stored["issue_order"], "opa_decision_json": tx._json(decision)}))
                request = _repack(request, [tx._update(self.table, self.pk, f"ISSUE#{task_id}",
                    "SET #status = :ack", "#status = :issued", {"#status": "status"}, {":ack": "ACKNOWLEDGED", ":issued": "ISSUED"})])
                try:
                    self._transact(request, identifier)
                    return {**deepcopy(echoed_task), "start_order": start}
                except PersistentConflict:
                    continue
        raise PersistentUnavailable("task_ack_retry_exhausted")

    def _stage(self, arrays, *, key):
        validate_arrays(arrays, self.template)
        stream = io.BytesIO()
        np.savez(stream, *arrays)
        body = stream.getvalue()
        logical, byte_digest = arrays_digest(arrays), hashlib.sha256(body).hexdigest()
        options = {"Bucket": self.bucket, "Key": key, "Body": body, "Metadata": {"sha256": byte_digest,
                   "parameters-digest": logical}, **self._owner()}
        if self.encryption:
            options["ServerSideEncryption"] = self.encryption
        response = self.s3.put_object(**options)
        version = response.get("VersionId")
        if not isinstance(version, str) or not version or version == "null":
            raise PersistentUnavailable("immutable_object_version_required")
        artifact = {"backend": "s3", "bucket": self.bucket, "key": key, "version_id": version,
                    "sha256": byte_digest, "size_bytes": len(body), "model_digest": logical, "parameters_digest": logical}
        self._load(artifact)
        return artifact

    def _load(self, artifact):
        if (artifact.get("bucket") != self.bucket or not artifact.get("version_id")
                or artifact["version_id"] == "null" or not any(artifact.get("key", "").startswith(prefix)
                  for prefix in (f"evidence/{self.run_id}/", f"models/candidates/{self.run_id}/"))):
            raise PersistentUnavailable("object_reference_outside_run_scope")
        options = {"Bucket": self.bucket, "Key": artifact["key"], "VersionId": artifact["version_id"], **self._owner()}
        head = self.s3.head_object(**options)
        response = self.s3.get_object(**options)
        stream = response["Body"]
        try:
            body = stream.read(64 * 1024 * 1024 + 1)
        finally:
            stream.close()
        if (len(body) > 64 * 1024 * 1024 or len(body) != artifact["size_bytes"]
                or head["ContentLength"] != len(body) or head.get("VersionId") != artifact["version_id"]
                or response.get("VersionId") != artifact["version_id"]
                or hashlib.sha256(body).hexdigest() != artifact["sha256"]):
            raise PersistentUnavailable("object_version_bytes_or_digest_mismatch")
        # Check declared expanded size before NumPy allocates any array. The
        # model schema is fixed and cannot legitimately exceed this bound.
        with zipfile.ZipFile(io.BytesIO(body)) as packed:
            if sum(info.file_size for info in packed.infolist()) > sum(value.nbytes for value in self.template) + 1024 * 1024:
                raise PersistentUnavailable("parameter_archive_expansion_exceeds_schema")
        with np.load(io.BytesIO(body), allow_pickle=False) as archive:
            if set(archive.files) != {f"arr_{i}" for i in range(len(self.template))}:
                raise PersistentUnavailable("invalid_parameter_archive")
            arrays = [archive[f"arr_{i}"].copy() for i in range(len(self.template))]
        validate_arrays(arrays, self.template)
        if arrays_digest(arrays) != artifact.get("parameters_digest", artifact.get("model_digest")):
            raise PersistentUnavailable("parameter_digest_mismatch")
        return arrays

    def _update_binding(self, update):
        return {key: update[key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order",
                                            "sample_count", "weights_digest", "model_schema_hash")}

    def receive(self, task_id, source_node, metadata, arrays):
        validate_arrays(arrays, self.template)
        with self.lock:
            artifact = None
            for _ in range(self.max_attempts):
                snapshot = self.snapshot()
                task = snapshot["items"].get(f"TASK#{task_id}")
                if not task or type(source_node) is not int or source_node != task["node_id"]:
                    raise ValueError("unauthenticated_or_unacknowledged_update")
                for field in ("task_id", "update_id", "org_id", "round_id", "purpose", "start_order", "model_schema_hash"):
                    if metadata.get(field) != task[field]:
                        raise ValueError("update_task_binding_mismatch")
                if digest(metadata.get("nonce")) != task["nonce_digest"]:
                    raise ValueError("update_nonce_mismatch")
                count = metadata.get("sample_count")
                if (type(count) is not int or not 1 <= count <= self.max_examples
                        or metadata.get("weights_digest") != arrays_digest(arrays)):
                    raise ValueError("invalid_update_count_or_payload_digest")
                uid = task["update_id"]
                existing = snapshot["items"].get(f"UPDATE#{uid}")
                if existing:
                    if existing["weights_digest"] != metadata["weights_digest"] or existing["sample_count"] != count:
                        raise ValueError("update_id_rebound")
                    return existing["status"]
                if f"ATTEMPT#{task_id}" in snapshot["items"]:
                    return "error"
                if snapshot["items"][f"ROUND#{task['round_id']}"]["status"] != "OPEN":
                    raise ValueError("late_update_for_closed_round")
                decision = self._authorization(snapshot, task["org_id"], task["start_order"], snapshot["order"] + 1, stage="receipt", task_id=task_id)
                if artifact is None:
                    artifact = self._stage(arrays, key=f"evidence/{self.run_id}/updates/{uid}/{metadata['weights_digest']}.npz")
                update = {key: metadata[key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order",
                                                         "sample_count", "weights_digest", "model_schema_hash")}
                identifier = self._txn_id("receipt")
                request = tx.build_register_update(self.table, run_id=self.run_id, round_id=task["round_id"],
                    expected_order=snapshot["order"], expected_round_generation=snapshot["items"][f"ROUND#{task['round_id']}"]["generation"],
                    update=update, authenticated_org=task["org_id"], observed_policy_epoch=snapshot["current"][task["org_id"]]["epoch"],
                    history_digest=digest(snapshot["histories"][task["org_id"]]), txn_id=identifier)
                request = _repack(request, [tx._put(self.table, self.pk, f"UPDATE_META#{uid}",
                    {"artifact_json": tx._json(artifact), "node_id": source_node, "opa_decision_json": tx._json(decision)})])
                try:
                    self._transact(request, identifier)
                    if not decision["valid"]:
                        self._reject_pending(uid, "authorization_interrupted")
                        return "rejected"
                    return "pending"
                except PersistentConflict:
                    continue
        raise PersistentUnavailable("receipt_retry_exhausted")

    def _policy_evidence(self, request, evaluations):
        """Bind OPA decision IDs/input to the same final decision and audit chain."""
        request = deepcopy(request)
        decisions = {}
        for action in request["TransactItems"]:
            values = action.get("Update", {}).get("ExpressionAttributeValues", {})
            if ":decision" in values:
                decision = json.loads(values[":decision"]["S"])
                evaluation = evaluations[decision["update_id"]]
                decision.update(policy_decision_id=evaluation["decision_id"], history_digest_scope="organization",
                                policy_query=evaluation.get("query"))
                decisions[decision["update_id"]] = decision
                values[":decision"] = {"S": tx._json(decision)}
        audits = sorted((action["Put"]["Item"] for action in request["TransactItems"]
                         if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": "audit_event"}),
                        key=lambda item: item["SK"]["S"])
        previous = None
        for item in audits:
            event = json.loads(item["event_json"]["S"])
            event["payload"] = decisions[event["payload"]["update_id"]]
            if previous is not None:
                event["prev_hash"] = previous
            previous = digest({key: event[key] for key in ("sequence", "prev_hash", "payload")})
            event["event_hash"] = previous
            item["event_json"], item["event_hash"] = {"S": tx._json(event)}, {"S": previous}
        for action in request["TransactItems"]:
            values = action.get("Update", {}).get("ExpressionAttributeValues", {})
            if ":new_head" in values and previous is not None:
                values[":new_head"] = {"S": previous}
            item = action.get("Put", {}).get("Item", {})
            if item.get("record_type") == {"S": "transaction_outcome"}:
                result = json.loads(item["result_json"]["S"])
                if "audit_head" in result and previous is not None:
                    result["audit_head"] = previous
                item["result_json"] = {"S": tx._json(result)}
        return _repack(request, [tx._put(self.table, self.pk, f"OPA_FINAL#{uid}", {
            "opa_decision_json": tx._json(evaluation)}) for uid, evaluation in sorted(evaluations.items())])

    def _reject_pending(self, uid, reason):
        for _ in range(self.max_attempts):
            snapshot = self.snapshot()
            update = snapshot["items"].get(f"UPDATE#{uid}")
            if not update:
                raise ValueError("unknown_pending_update")
            if update["status"] != "pending":
                return update["status"]
            evaluation = self._authorization(snapshot, update["org_id"], update["start_order"], snapshot["order"] + 1, stage="final", task_id=update["task_id"])
            identifier = self._txn_id("reject")
            head = snapshot["items"]["AUDIT_HEAD"]
            request = tx.build_rejection(self.table, run_id=self.run_id, round_id=update["round_id"],
                expected_order=snapshot["order"], update=self._update_binding(update), reason=reason,
                observed_policy_epoch=snapshot["current"][update["org_id"]]["epoch"],
                history_digest=digest(snapshot["histories"][update["org_id"]]), rule_bundle_hash=self.rule_hash,
                expected_audit_count=head["count"], expected_audit_head=head["head"], txn_id=identifier)
            try:
                self._transact(self._policy_evidence(request, {uid: evaluation}), identifier)
                return "rejected"
            except PersistentConflict:
                continue
        raise PersistentUnavailable("rejection_retry_exhausted")

    def fail(self, task_id, reason):
        with self.lock:
            for _ in range(self.max_attempts):
                try:
                    return self._fail_once(task_id, reason)
                except PersistentConflict:
                    continue
        raise PersistentUnavailable("attempt_finalization_retry_exhausted")

    def _fail_once(self, task_id, reason):
        snapshot = self.snapshot()
        task = snapshot["items"].get(f"TASK#{task_id}")
        if not task:
            raise ValueError("unknown_failed_task")
        uid = task["update_id"]
        if f"UPDATE#{uid}" in snapshot["items"]:
            return self._reject_pending(uid, reason)
        if f"ATTEMPT#{task_id}" in snapshot["items"]:
            return "error"
        identifier = self._txn_id("error")
        head = snapshot["items"]["AUDIT_HEAD"]
        order, count = snapshot["order"] + 1, head["count"] + 1
        decision = {"update_id": uid, "task_id": task_id, "org_id": task["org_id"], "round_id": task["round_id"],
                    "run_id": self.run_id, "rule_bundle_hash": self.rule_hash,
                    "authorization_status": "not_evaluated_operational_error", "policy_decision_id": None, "policy_query": None,
                    "purpose": task["purpose"], "start_order": task["start_order"], "outcome": "error", "reason": str(reason),
                    "evaluation_order": order, "observed_epoch": snapshot["current"][task["org_id"]]["epoch"],
                    "history_digest": digest(snapshot["histories"][task["org_id"]]), "history_digest_scope": "organization", "manifest_ref": None}
        body = {"sequence": count, "prev_hash": head["head"], "payload": decision}
        event_hash = digest(body)
        request = self._manual([tx._sequence_action(self.table, snapshot["order"], identifier),
            tx._put(self.table, self.pk, f"ATTEMPT#{task_id}", {"decision_json": tx._json(decision)}),
            tx._put(self.table, self.pk, f"AUDIT#{count:020d}", {"record_type": "audit_event",
                "event_json": tx._json({**body, "event_hash": event_hash}), "event_hash": event_hash}),
            tx._update(self.table, self.pk, "AUDIT_HEAD", "SET #count = :new_count, #head = :new_head",
                "#count = :old_count AND #head = :old_head", {"#count": "count", "#head": "head"},
                {":new_count": count, ":new_head": event_hash, ":old_count": head["count"], ":old_head": head["head"]})],
            identifier, "attempt_error", order, {"update_id": uid, "outcome": "error"})
        self._transact(request, identifier)
        return "error"

    def _close_empty(self, snapshot, round_id):
        identifier = self._txn_id("empty-round")
        record = snapshot["items"][f"ROUND#{round_id}"]
        request = self._manual([tx._sequence_action(self.table, snapshot["order"], identifier),
            tx._update(self.table, self.pk, f"ROUND#{round_id}", "SET #status = :closed",
                "#status = :open AND #pending = :zero AND #generation = :generation",
                {"#status": "status", "#pending": "pending_count", "#generation": "generation"},
                {":closed": "CLOSED", ":open": "OPEN", ":zero": 0, ":generation": record["generation"]}),
            tx._put(self.table, self.pk, f"EMPTY#{round_id}", {"outcome": "empty", "order": snapshot["order"] + 1})],
            identifier, "empty_round", snapshot["order"] + 1, {"round_id": round_id, "outcome": "empty"})
        self._transact(request, identifier)

    def publish(self, round_id, *, stage=None, before_commit=None):
        """Only the guarded durable pointer publishes; local stage is export-only."""
        with self.lock:
            for attempt in range(self.max_attempts):
                snapshot = self._ensure_round(round_id)
                record = snapshot["items"][f"ROUND#{round_id}"]
                if record["status"] == "CLOSED":
                    if record.get("manifest_id"):
                        return self._normalized_manifest(snapshot["items"][f"MANIFEST#{record['manifest_id']}"])
                    return None
                pending = [item for sk, item in snapshot["items"].items() if sk.startswith("UPDATE#")
                           and item["round_id"] == round_id and item["status"] == "pending"]
                invalid, evaluations = [], {}
                for update in pending:
                    evaluation = self._authorization(snapshot, update["org_id"], update["start_order"], snapshot["order"] + 1, stage="publication", task_id=update["task_id"])
                    evaluations[update["update_id"]] = evaluation
                    if not evaluation["valid"]:
                        invalid.append(update["update_id"])
                if invalid:
                    for uid in invalid:
                        self._reject_pending(uid, "authorization_interrupted")
                    continue
                if not pending:
                    try:
                        self._close_empty(snapshot, round_id)
                        return None
                    except PersistentConflict:
                        continue
                pending.sort(key=lambda update: (update["org_id"], update["update_id"]))
                total = sum(update["sample_count"] for update in pending)
                arrays = [np.zeros_like(value, dtype=np.float64) for value in self.template]
                for update in pending:
                    meta = snapshot["items"].get(f"UPDATE_META#{update['update_id']}")
                    if not meta:
                        raise PersistentUnavailable("missing_immutable_update_reference")
                    values = self._load(json.loads(meta["artifact_json"]))
                    if arrays_digest(values) != update["weights_digest"]:
                        raise PersistentUnavailable("pending_update_artifact_rebound")
                    for destination, value in zip(arrays, values, strict=True):
                        destination += value.astype(np.float64) * (update["sample_count"] / total)
                arrays = [value.astype(np.float32) for value in arrays]
                logical = arrays_digest(arrays)
                artifact = self._stage(arrays, key=f"models/candidates/{self.run_id}/{logical}.npz")
                if stage is not None:
                    stage([value.copy() for value in arrays], logical)
                context = {"snapshot_order": snapshot["order"], "parent_manifest_id": snapshot["items"]["POINTER"].get("manifest_id"),
                    "round_generation": record["generation"],
                    "policy_epochs": {update["org_id"]: snapshot["current"][update["org_id"]]["epoch"] for update in pending},
                    "history_digests": {update["org_id"]: digest(snapshot["histories"][update["org_id"]]) for update in pending},
                    "model_schema_hash": self.schema_hash, "rule_bundle_hash": self.rule_hash,
                    "model_digest": artifact["sha256"],
                    "s3": {key: artifact[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")},
                    "object_confirmation": {key: artifact[key] for key in ("version_id", "sha256", "size_bytes")},
                    "updates": [{key: update[key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order", "sample_count", "weights_digest")} for update in pending]}
                context = self._candidate_context(context)
                candidate = {**context, "candidate_id": tx.candidate_digest(context)}
                identifier = self._txn_id("publish")
                head = snapshot["items"]["AUDIT_HEAD"]
                request = self._publication_request(run_id=self.run_id, round_id=round_id,
                    txn_id=identifier, candidate=candidate, expected_audit_count=head["count"], expected_audit_head=head["head"])
                for action in request["TransactItems"]:
                    item = action.get("Put", {}).get("Item", {})
                    if item.get("record_type") == {"S": "publication_manifest"}:
                        raw = json.loads(item["manifest_json"]["S"])
                        raw.update(parameters_digest=logical, artifact=artifact)
                        item["manifest_json"] = {"S": tx._json(raw)}
                request = self._policy_evidence(request, evaluations)
                if before_commit:
                    before_commit(attempt)
                # Confirm the precise version again immediately before guarded release.
                self._load(artifact)
                try:
                    self._transact(request, identifier)
                    return self._normalized_manifest(self.item(self.pk, f"MANIFEST#{candidate['candidate_id']}"))
                except PersistentConflict:
                    continue
        raise PersistentUnavailable("publication_conflict_retry_exhausted")

    def _normalized_manifest(self, record):
        raw = json.loads(record["manifest_json"])
        candidate = raw["candidate"]
        if candidate.get("ablation_id") != getattr(self, "ablation_id", None):
            raise PersistentUnavailable("published_manifest_ablation_mismatch")
        if candidate.get("baseline_id", "P1") != getattr(self, "baseline_id", "P1"):
            raise PersistentUnavailable("published_manifest_method_mismatch")
        if candidate["candidate_id"] != tx.candidate_digest({key: value for key, value in candidate.items() if key != "candidate_id"}):
            raise PersistentUnavailable("durable_candidate_digest_mismatch")
        artifact = raw["artifact"]
        if (raw["manifest_id"] != candidate["candidate_id"] or raw["run_id"] != self.run_id
                or raw["commit_order"] != candidate["snapshot_order"] + 1
                or candidate["model_schema_hash"] != self.schema_hash or candidate["rule_bundle_hash"] != self.rule_hash
                or any(artifact.get(key) != value for key, value in candidate["s3"].items())
                or candidate["model_digest"] != artifact.get("sha256")
                or raw["parameters_digest"] != artifact.get("parameters_digest")):
            raise PersistentUnavailable("published_manifest_binding_mismatch")
        return {"manifest_id": raw["manifest_id"], "round_id": raw["round_id"], "run_id": self.run_id,
            "parent_manifest_id": candidate["parent_manifest_id"], "model_digest": raw["parameters_digest"],
            "model_schema_hash": candidate["model_schema_hash"], "included_update_ids": sorted(update["update_id"] for update in candidate["updates"]),
            "policy_epochs": candidate["policy_epochs"], "commit_order": raw["commit_order"], "artifact": artifact,
            "guarded_policy_publication": True, "persistent_protocol": "ddb-v1", "candidate_metadata": candidate,
            "commit_txn_id": raw["commit_txn_id"]}

    def parameters(self):
        pointer = self.item(self.pk, "POINTER")
        if not pointer.get("manifest_id"):
            return [value.copy() for value in self.template]
        record = self.item(self.pk, f"MANIFEST#{pointer['manifest_id']}")
        if not record:
            raise PersistentUnavailable("published_pointer_missing_manifest")
        manifest = self._normalized_manifest(record)
        arrays = self._load(manifest["artifact"])
        if arrays_digest(arrays) != manifest["model_digest"]:
            raise PersistentUnavailable("published_parameter_digest_mismatch")
        return arrays

    def record_update_artifact(self, update_id, artifact):
        update = self.item(self.pk, f"UPDATE#{update_id}")
        if not update or artifact.get("model_digest") != update["weights_digest"]:
            raise ValueError("retained_update_digest_mismatch")
        self._local_artifacts[update_id] = deepcopy(artifact)

    def evidence(self):
        snapshot = self.snapshot()
        items = snapshot["items"]
        tasks, updates, decisions, attempts, audit, manifests = [], [], {}, [], [], []
        for sk, record in items.items():
            if sk.startswith("TASK#"):
                tasks.append({key: record[key] for key in ("task_id", "update_id", "org_id", "node_id", "round_id", "purpose",
                    "issue_order", "start_order", "policy_epoch", "policy_hash", "model_schema_hash", "nonce_digest")})
            elif sk.startswith("UPDATE#"):
                meta = items.get(f"UPDATE_META#{record['update_id']}")
                if not meta:
                    raise PersistentUnavailable("missing_update_provenance")
                updates.append({**{key: record[key] for key in ("update_id", "task_id", "org_id", "round_id", "purpose",
                    "start_order", "received_order", "weights_digest", "model_schema_hash", "sample_count")},
                    "node_id": meta["node_id"], "artifact": json.loads(meta["artifact_json"])})
                if record.get("decision_json"):
                    decisions[record["update_id"]] = json.loads(record["decision_json"])
            elif sk.startswith("AUDIT#"):
                audit.append(json.loads(record["event_json"]))
            elif sk.startswith("MANIFEST#"):
                manifests.append(self._normalized_manifest(record))
            elif sk.startswith("ATTEMPT#"):
                attempts.append(json.loads(record["decision_json"]))
        audit.sort(key=lambda record: record["sequence"])
        manifests.sort(key=lambda record: record["commit_order"])
        head = items.get("AUDIT_HEAD", {"count": 0, "head": "0" * 64})
        pointer = items.get("POINTER", {})
        current = next((manifest["model_digest"] for manifest in manifests if manifest["manifest_id"] == pointer.get("manifest_id")), arrays_digest(self.template))
        return {"policy_events": snapshot["events"], "tasks": tasks, "updates": updates, "decisions": decisions,
            "attempt_failures": attempts, "published_manifests": manifests, "selection": deepcopy(self.selection),
            "current_model_digest": current, "model_schema_hash": self.schema_hash, "audit": audit,
            "anchor": {"count": head["count"], "head": head["head"]}, "authority_backend": "dynamodb-s3-opa",
            "conflict_count": self.conflicts, "persistent_run_id": self.run_id, "policy_rule_hash": self.rule_hash,
            "durable_evidence": {"run_records": list(items.values()), "policy_records": snapshot["policy_records"],
                                 "sequence": snapshot["sequence"]}}
