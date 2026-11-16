"""Pure request builders for a proposed single-region DynamoDB protocol.

These functions emit low-level ``TransactWriteItems`` request dictionaries; they
do not contact AWS, evaluate authorization, authenticate callers, or confirm S3
durability. A trusted adapter must supply a coherent validated snapshot and a
verified immutable S3 version. The independent oracle is never imported here.
"""

import hashlib
import json
import re


_ORGS = frozenset(f"org_{i:02d}" for i in range(1, 9))
_ACTIONS = frozenset({"train", "submit_update", "aggregate"})
_MAX_NUMBER = (1 << 63) - 1
MAX_REQUEST_BYTES = 3_000_000  # Conservative encoded-request bound, not AWS item accounting.
MAX_ITEM_BYTES = 380_000


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def candidate_digest(candidate_without_id):
    """Content address for candidate metadata, including every snapshot guard."""
    return _digest(candidate_without_id)


def _text(value, name, maximum=128):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"invalid_{name}")
    return value


def _identifier(value, name):
    _text(value, name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ValueError(f"invalid_{name}")
    return value


def _integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value < _MAX_NUMBER:
        raise ValueError(f"invalid_{name}")
    return value


def _hash(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"invalid_{name}")
    return value


def _table(table):
    if not isinstance(table, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table):
        raise ValueError("invalid_table_name")
    return table


def _attribute(value):
    if type(value) is int:
        return {"N": str(value)}
    if type(value) is bool:
        return {"BOOL": value}
    if value is None:
        return {"NULL": True}
    if isinstance(value, str):
        return {"S": value}
    raise ValueError("unsupported_attribute_type")


def _key(pk, sk):
    return {"PK": {"S": pk}, "SK": {"S": sk}}


def _put(table, pk, sk, fields):
    item = {**_key(pk, sk), **{name: _attribute(value) for name, value in fields.items()}}
    if len(_json(item).encode()) > MAX_ITEM_BYTES:
        raise ValueError("new_item_too_large")
    return {"Put": {"TableName": table, "Item": item,
                    "ConditionExpression": "attribute_not_exists(#pk)",
                    "ExpressionAttributeNames": {"#pk": "PK"}}}


def _update(table, pk, sk, expression, condition, names, values):
    return {"Update": {"TableName": table, "Key": _key(pk, sk),
                       "UpdateExpression": expression, "ConditionExpression": condition,
                       "ExpressionAttributeNames": names,
                       "ExpressionAttributeValues": {name: _attribute(value) for name, value in values.items()}}}


def _sequence_action(table, expected_order, txn_id):
    return _update(table, "AUTHORITY", "SEQUENCE", "SET #ord = :next, #txn = :txn",
                   "#ord = :expected", {"#ord": "order", "#txn": "last_txn_id"},
                   {":next": expected_order + 1, ":expected": expected_order, ":txn": txn_id})


def validate_transaction_request(request):
    """Reject conflicting item actions and oversized request plans before submission.

    AWS must still validate resulting item sizes, expressions and permissions.
    This deliberately accepts one table only, although AWS supports more.
    """
    actions = request.get("TransactItems") if isinstance(request, dict) else None
    if not isinstance(actions, list) or not 1 <= len(actions) <= 100:
        raise ValueError("invalid_transaction_action_count")
    seen, tables = set(), set()
    for action in actions:
        if not isinstance(action, dict) or len(action) != 1:
            raise ValueError("invalid_transaction_action")
        kind = next(iter(action))
        if kind not in {"Put", "Update", "Delete", "ConditionCheck"}:
            raise ValueError("invalid_transaction_action")
        body = action[kind]
        table = _table(body.get("TableName"))
        tables.add(table)
        key = body.get("Item") if kind == "Put" else body.get("Key")
        try:
            identity = (table, key["PK"]["S"], key["SK"]["S"])
            if not all(isinstance(value, str) and value for value in identity):
                raise ValueError("invalid_item_key")
        except (KeyError, TypeError) as error:
            raise ValueError("invalid_item_key") from error
        if identity in seen:
            raise ValueError("duplicate_transaction_item")
        seen.add(identity)
    if len(tables) != 1:
        raise ValueError("multiple_tables_not_supported")
    if len(_json(request).encode()) > MAX_REQUEST_BYTES:
        raise ValueError("transaction_request_too_large")


def _finish(actions):
    request = {"TransactItems": actions, "ReturnConsumedCapacity": "TOTAL"}
    request["ClientRequestToken"] = _digest(request)[:36]
    validate_transaction_request(request)
    return request


def recovery_get_request(table_name, txn_id, *, run_id=None):
    """Strongly read a durable transaction outcome after an ambiguous response."""
    _table(table_name)
    _identifier(txn_id, "txn_id")
    pk = f"RUN#{_identifier(run_id, 'run_id')}" if run_id is not None else "AUTHORITY"
    return {"TableName": table_name, "Key": _key(pk, f"TXN#{txn_id}"), "ConsistentRead": True}


def expected_outcome_digest(request):
    """Extract the fingerprint to compare with a recovered durable outcome."""
    matches = [action["Put"]["Item"]["request_digest"]["S"] for action in request["TransactItems"]
               if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": "transaction_outcome"}]
    if len(matches) != 1:
        raise ValueError("missing_unique_transaction_outcome")
    return matches[0]


def _outcome_action(table, pk, txn_id, kind, order, fingerprint, result):
    return _put(table, pk, f"TXN#{txn_id}",
                {"record_type": "transaction_outcome", "request_digest": fingerprint,
                 "operation_kind": kind, "order": order, "result_json": _json(result)})


def build_initialize_authority(table_name, *, txn_id):
    """One-time, conditional authority initialization; never overwrite existing state."""
    _table(table_name)
    _identifier(txn_id, "txn_id")
    fingerprint = _digest({"kind": "initialize_authority", "table": table_name, "txn_id": txn_id})
    return _finish([_put(table_name, "AUTHORITY", "SEQUENCE", {"order": 0}),
                    _outcome_action(table_name, "AUTHORITY", txn_id, "initialize_authority", 0,
                                    fingerprint, {"order": 0})])


def build_initialize_run(table_name, *, run_id, round_id, expected_order, txn_id):
    """Create a first-round pointer/membership/audit head under the global sequencer."""
    _table(table_name)
    _identifier(run_id, "run_id")
    _identifier(round_id, "round_id")
    _identifier(txn_id, "txn_id")
    _integer(expected_order, "expected_order")
    pk, order = f"RUN#{run_id}", expected_order + 1
    fingerprint = _digest({"kind": "initialize_run", "table": table_name, "run_id": run_id,
                           "round_id": round_id, "expected_order": expected_order, "txn_id": txn_id})
    return _finish([_sequence_action(table_name, expected_order, txn_id),
                    _put(table_name, pk, "POINTER", {"record_type": "model_pointer", "created_order": order}),
                    _put(table_name, pk, f"ROUND#{round_id}", {"status": "OPEN", "generation": 0, "pending_count": 0}),
                    _put(table_name, pk, "AUDIT_HEAD", {"count": 0, "head": "0" * 64}),
                    _outcome_action(table_name, pk, txn_id, "initialize_run", order, fingerprint,
                                    {"run_id": run_id, "round_id": round_id, "order": order})])


def _policy_guard(table, org, epoch, policy_hash=None):
    names, values = {"#epoch": "epoch"}, {":epoch": {"N": str(epoch)}}
    condition = "#epoch = :epoch"
    if policy_hash is not None:
        names["#hash"] = "policy_hash"
        values[":hash"] = {"S": policy_hash}
        condition += " AND #hash = :hash"
    return {"ConditionCheck": {"TableName": table, "Key": _key(f"POLICY#{org}", "CURRENT"),
                               "ConditionExpression": condition, "ExpressionAttributeNames": names,
                               "ExpressionAttributeValues": values}}


def build_task_authorization(table_name, *, run_id, round_id, expected_order, task, txn_id):
    """Persist an externally evaluated, acknowledged task with its start order.

    The trusted caller has authenticated the client and evaluated the requested
    purpose/actions. This builder binds that decision to the guarded policy state.
    """
    _table(table_name)
    for value, name in ((run_id, "run_id"), (round_id, "round_id"), (txn_id, "txn_id")):
        _identifier(value, name)
    _integer(expected_order, "expected_order")
    fields = {"task_id", "org_id", "purpose", "start_order", "policy_epoch", "policy_hash",
              "model_schema_hash", "nonce_digest"}
    if not isinstance(task, dict) or set(task) != fields:
        raise ValueError("incomplete_task_binding")
    _identifier(task["task_id"], "task_id")
    if not isinstance(task["org_id"], str) or task["org_id"] not in _ORGS:
        raise ValueError("invalid_organization")
    _text(task["purpose"], "purpose")
    _integer(task["policy_epoch"], "policy_epoch", 1)
    for name in ("policy_hash", "model_schema_hash", "nonce_digest"):
        _hash(task[name], name)
    if type(task["start_order"]) is not int or task["start_order"] != expected_order + 1:
        raise ValueError("task_start_does_not_match_sequencer")
    pk = f"RUN#{run_id}"
    fingerprint = _digest({"kind": "task_authorization", "table": table_name, "run_id": run_id,
                           "round_id": round_id, "expected_order": expected_order, "task": task, "txn_id": txn_id})
    return _finish([_sequence_action(table_name, expected_order, txn_id),
                    _policy_guard(table_name, task["org_id"], task["policy_epoch"], task["policy_hash"]),
                    {"ConditionCheck": {"TableName": table_name, "Key": _key(pk, f"ROUND#{round_id}"),
                                        "ConditionExpression": "#status = :open",
                                        "ExpressionAttributeNames": {"#status": "status"},
                                        "ExpressionAttributeValues": {":open": {"S": "OPEN"}}}},
                    _put(table_name, pk, f"TASK#{task['task_id']}",
                         {**task, "round_id": round_id, "status": "ACKNOWLEDGED"}),
                    _put(table_name, pk, f"TASK_ORG#{round_id}#{task['org_id']}",
                         {"task_id": task["task_id"], "start_order": task["start_order"]}),
                    _outcome_action(table_name, pk, txn_id, "task_authorization", task["start_order"],
                                    fingerprint, {"task_id": task["task_id"], "start_order": task["start_order"]})])


def _validate_received_update(update, expected_order):
    fields = {"update_id", "task_id", "org_id", "purpose", "start_order", "sample_count",
              "weights_digest", "model_schema_hash"}
    if not isinstance(update, dict) or set(update) != fields:
        raise ValueError("incomplete_update_binding")
    _identifier(update["update_id"], "update_id")
    _identifier(update["task_id"], "task_id")
    if not isinstance(update["org_id"], str) or update["org_id"] not in _ORGS:
        raise ValueError("invalid_organization")
    _text(update["purpose"], "purpose")
    _integer(update["start_order"], "start_order", 1)
    _integer(update["sample_count"], "sample_count", 1)
    _hash(update["weights_digest"], "weights_digest")
    _hash(update["model_schema_hash"], "model_schema_hash")
    if update["start_order"] > expected_order:
        raise ValueError("update_starts_after_snapshot")


def build_register_update(table_name, *, run_id, round_id, expected_order, expected_round_generation,
                          update, authenticated_org, observed_policy_epoch, history_digest, txn_id):
    """Record one validated receipt and increment round membership atomically."""
    _table(table_name)
    for value, name in ((run_id, "run_id"), (round_id, "round_id"), (txn_id, "txn_id")):
        _identifier(value, name)
    _integer(expected_order, "expected_order")
    _integer(expected_round_generation, "expected_round_generation")
    _integer(observed_policy_epoch, "observed_policy_epoch", 1)
    _hash(history_digest, "history_digest")
    _validate_received_update(update, expected_order)
    if authenticated_org != update["org_id"]:
        raise ValueError("authenticated_identity_mismatch")
    pk, order = f"RUN#{run_id}", expected_order + 1
    fingerprint = _digest({"kind": "register_update", "table": table_name, "run_id": run_id,
                           "round_id": round_id, "expected_order": expected_order,
                           "expected_round_generation": expected_round_generation, "update": update,
                           "authenticated_org": authenticated_org, "observed_policy_epoch": observed_policy_epoch,
                           "history_digest": history_digest, "txn_id": txn_id})
    task_names = {"#status": "status", "#update": "update_id", "#round": "round_id", "#org": "org_id",
                  "#purpose": "purpose", "#start": "start_order", "#schema": "model_schema_hash"}
    return _finish([_sequence_action(table_name, expected_order, txn_id),
                    _policy_guard(table_name, update["org_id"], observed_policy_epoch),
                    _update(table_name, pk, f"TASK#{update['task_id']}", "SET #status = :submitted, #update = :update",
                            "#status = :ack AND #round = :round AND #org = :org AND #purpose = :purpose AND #start = :start AND #schema = :schema",
                            task_names, {":submitted": "SUBMITTED", ":update": update["update_id"],
                                         ":ack": "ACKNOWLEDGED", ":round": round_id, ":org": update["org_id"],
                                         ":purpose": update["purpose"], ":start": update["start_order"],
                                         ":schema": update["model_schema_hash"]}),
                    _update(table_name, pk, f"ROUND#{round_id}", "SET #generation = :new ADD #pending :one",
                            "#status = :open AND #generation = :expected AND attribute_exists(#pending)",
                            {"#generation": "generation", "#status": "status", "#pending": "pending_count"},
                            {":new": expected_round_generation + 1, ":expected": expected_round_generation,
                             ":open": "OPEN", ":one": 1}),
                    _put(table_name, pk, f"UPDATE#{update['update_id']}",
                         {**update, "status": "pending", "round_id": round_id, "received_order": order,
                          "receipt_history_digest": history_digest}),
                    _outcome_action(table_name, pk, txn_id, "register_update", order, fingerprint,
                                    {"update_id": update["update_id"], "received_order": order,
                                     "round_generation": expected_round_generation + 1})])


def build_rejection(table_name, *, run_id, round_id, expected_order, update, reason,
                    observed_policy_epoch, history_digest, rule_bundle_hash,
                    expected_audit_count, expected_audit_head, txn_id):
    """Finalize one pending rejection and its audit atomically before round closure.

    The caller supplies the independently validated reason. A policy-epoch and
    global-order guard ensure the reason's snapshot cannot silently change.
    """
    _table(table_name)
    for value, name in ((run_id, "run_id"), (round_id, "round_id"), (txn_id, "txn_id")):
        _identifier(value, name)
    _integer(expected_order, "expected_order")
    _integer(expected_audit_count, "expected_audit_count")
    _integer(observed_policy_epoch, "observed_policy_epoch", 1)
    _hash(expected_audit_head, "expected_audit_head")
    _hash(history_digest, "history_digest")
    _hash(rule_bundle_hash, "rule_bundle_hash")
    _text(reason, "reason")
    _validate_received_update(update, expected_order)
    if (expected_audit_count == 0) != (expected_audit_head == "0" * 64):
        raise ValueError("incoherent_audit_anchor")
    pk, order, count = f"RUN#{run_id}", expected_order + 1, expected_audit_count + 1
    decision = {**update, "run_id": run_id, "round_id": round_id, "outcome": "rejected",
                "reason": reason, "evaluation_order": order, "observed_epoch": observed_policy_epoch,
                "history_digest": history_digest, "rule_bundle_hash": rule_bundle_hash, "manifest_ref": None}
    audit_body = {"sequence": count, "prev_hash": expected_audit_head, "payload": decision}
    event_hash = _digest(audit_body)
    fingerprint = _digest({"kind": "rejection", "table": table_name, "run_id": run_id,
                           "round_id": round_id, "expected_order": expected_order, "decision": decision,
                           "expected_audit_count": expected_audit_count,
                           "expected_audit_head": expected_audit_head, "txn_id": txn_id})
    return _finish([_sequence_action(table_name, expected_order, txn_id),
                    _policy_guard(table_name, update["org_id"], observed_policy_epoch),
                    _update(table_name, pk, f"ROUND#{round_id}", "ADD #pending :minus_one",
                            "#status = :open AND #pending >= :one",
                            {"#pending": "pending_count", "#status": "status"},
                            {":minus_one": -1, ":one": 1, ":open": "OPEN"}),
                    _update(table_name, pk, f"UPDATE#{update['update_id']}",
                            "SET #status = :rejected, #decision = :decision",
                            "#status = :pending AND #round = :round AND #org = :org AND #task = :task AND #digest = :digest AND #purpose = :purpose AND #start = :start AND #sample = :sample AND #schema = :schema",
                            {"#status": "status", "#decision": "decision_json", "#round": "round_id",
                             "#org": "org_id", "#task": "task_id", "#digest": "weights_digest",
                             "#purpose": "purpose", "#start": "start_order", "#sample": "sample_count",
                             "#schema": "model_schema_hash"},
                            {":rejected": "rejected", ":pending": "pending", ":decision": _json(decision),
                             ":round": round_id, ":org": update["org_id"], ":task": update["task_id"],
                             ":digest": update["weights_digest"], ":purpose": update["purpose"],
                             ":start": update["start_order"], ":sample": update["sample_count"],
                             ":schema": update["model_schema_hash"]}),
                    _put(table_name, pk, f"AUDIT#{count:020d}",
                         {"record_type": "audit_event", "event_json": _json({**audit_body, "event_hash": event_hash}),
                          "event_hash": event_hash}),
                    _update(table_name, pk, "AUDIT_HEAD", "SET #count = :new_count, #head = :new_head",
                            "#count = :old_count AND #head = :old_head",
                            {"#count": "count", "#head": "head"},
                            {":new_count": count, ":new_head": event_hash,
                             ":old_count": expected_audit_count, ":old_head": expected_audit_head}),
                    _outcome_action(table_name, pk, txn_id, "rejection", order, fingerprint,
                                    {"update_id": update["update_id"], "outcome": "rejected",
                                     "order": order, "audit_count": count, "audit_head": event_hash})])


def build_policy_mutation(table_name, *, expected_order, expected_epoch, event, txn_id):
    """Atomically advance sequencer/current epoch, append history and store outcome.

    ``event`` is a complete six-field replacement state. The authority sequencer
    must already exist with numeric ``order`` (zero at initialization).
    """
    _table(table_name)
    _identifier(txn_id, "txn_id")
    _integer(expected_order, "expected_order")
    _integer(expected_epoch, "expected_epoch")
    required = {"event_id", "org_id", "order", "epoch", "kind", "rules"}
    if not isinstance(event, dict) or set(event) != required:
        raise ValueError("incomplete_policy_event")
    _identifier(event["event_id"], "event_id")
    if not isinstance(event["org_id"], str) or event["org_id"] not in _ORGS:
        raise ValueError("invalid_organization")
    if type(event["order"]) is not int or event["order"] != expected_order + 1:
        raise ValueError("policy_order_does_not_match_sequencer")
    if type(event["epoch"]) is not int or event["epoch"] != expected_epoch + 1:
        raise ValueError("policy_epoch_not_incremented")
    if not isinstance(event["kind"], str) or event["kind"] not in {"GRANT", "CHANGE", "REVOKE", "EXPIRE"}:
        raise ValueError("invalid_policy_kind")
    if not isinstance(event["rules"], list):
        raise ValueError("invalid_rules")
    if event["kind"] in {"REVOKE", "EXPIRE"} and event["rules"]:
        raise ValueError("revocation_contains_rules")
    for rule in event["rules"]:
        if not isinstance(rule, dict) or set(rule) != {"purpose", "action", "effect"}:
            raise ValueError("invalid_rule")
        _text(rule["purpose"], "purpose")
        if (not isinstance(rule["action"], str) or rule["action"] not in _ACTIONS
                or not isinstance(rule["effect"], str) or rule["effect"] not in {"allow", "deny"}):
            raise ValueError("invalid_rule")
    operation_digest = _digest({"kind": "policy_mutation", "table": table_name, "txn_id": txn_id,
                                "expected_order": expected_order, "expected_epoch": expected_epoch,
                                "event": event})
    policy_pk = f"POLICY#{event['org_id']}"
    names = {"#epoch": "epoch", "#ord": "effective_order", "#hash": "policy_hash",
             "#payload": "event_json", "#event": "event_id"}
    values = {":epoch": event["epoch"], ":ord": event["order"], ":hash": _digest(event),
              ":payload": _json(event), ":event": event["event_id"]}
    if expected_epoch:
        condition = "#epoch = :expected"
        values[":expected"] = expected_epoch
    else:
        condition = "attribute_not_exists(#pk)"
        names["#pk"] = "PK"
    current = _update(table_name, policy_pk, "CURRENT",
                      "SET #epoch = :epoch, #ord = :ord, #hash = :hash, #payload = :payload, #event = :event",
                      condition, names, values)
    actions = [_sequence_action(table_name, expected_order, txn_id), current,
               _put(table_name, policy_pk, f"EVENT#{event['order']:020d}",
                    {"record_type": "policy_event", "epoch": event["epoch"],
                     "order": event["order"], "policy_hash": _digest(event), "event_json": _json(event)}),
               _put(table_name, "AUTHORITY", f"EVENT_ID#{event['event_id']}",
                    {"record_type": "policy_event_identity", "org_id": event["org_id"],
                     "order": event["order"], "epoch": event["epoch"], "policy_hash": _digest(event)}),
               _put(table_name, "AUTHORITY", f"TXN#{txn_id}",
                    {"record_type": "transaction_outcome", "request_digest": operation_digest,
                     "operation_kind": "policy_mutation", "order": event["order"],
                     "result_json": _json({"event_id": event["event_id"], "org_id": event["org_id"],
                                           "epoch": event["epoch"], "order": event["order"]})})]
    return _finish(actions)


def _validated_candidate(candidate):
    required = {"candidate_id", "snapshot_order", "parent_manifest_id", "round_generation",
                "policy_epochs", "history_digests", "model_schema_hash", "rule_bundle_hash",
                "model_digest", "s3", "object_confirmation", "updates"}
    if not isinstance(candidate, dict) or set(candidate) != required:
        raise ValueError("incomplete_candidate_context")
    _integer(candidate["snapshot_order"], "snapshot_order")
    _integer(candidate["round_generation"], "round_generation")
    _hash(candidate["candidate_id"], "candidate_id")
    for field in ("model_schema_hash", "rule_bundle_hash", "model_digest"):
        _hash(candidate[field], field)
    if candidate["parent_manifest_id"] is not None:
        _hash(candidate["parent_manifest_id"], "parent_manifest_id")
    if candidate["candidate_id"] != candidate_digest({k: v for k, v in candidate.items() if k != "candidate_id"}):
        raise ValueError("candidate_metadata_digest_mismatch")
    updates = candidate["updates"]
    if not isinstance(updates, list) or not 1 <= len(updates) <= 8:
        raise ValueError("invalid_candidate_updates")
    ids, orgs = set(), set()
    for update in updates:
        if not isinstance(update, dict) or set(update) != {
                "update_id", "task_id", "org_id", "purpose", "start_order", "sample_count", "weights_digest"}:
            raise ValueError("incomplete_update_binding")
        for field in ("update_id", "task_id"):
            _identifier(update[field], field)
        _text(update["purpose"], "purpose")
        _integer(update["start_order"], "start_order", 1)
        _integer(update["sample_count"], "sample_count", 1)
        _hash(update["weights_digest"], "weights_digest")
        if update["start_order"] > candidate["snapshot_order"]:
            raise ValueError("update_starts_after_snapshot")
        if (not isinstance(update["org_id"], str) or update["org_id"] not in _ORGS
                or update["update_id"] in ids or update["org_id"] in orgs):
            raise ValueError("duplicate_or_unknown_contributor")
        ids.add(update["update_id"])
        orgs.add(update["org_id"])
    for field in ("policy_epochs", "history_digests"):
        if not isinstance(candidate[field], dict) or set(candidate[field]) != orgs:
            raise ValueError("incomplete_policy_guards")
    for epoch in candidate["policy_epochs"].values():
        _integer(epoch, "policy_epoch", 1)
    for history_digest in candidate["history_digests"].values():
        _hash(history_digest, "history_digest")
    staged, confirmation = candidate["s3"], candidate["object_confirmation"]
    if not isinstance(staged, dict) or set(staged) != {"bucket", "key", "version_id", "sha256", "size_bytes"}:
        raise ValueError("incomplete_staged_object")
    _text(staged["bucket"], "s3_bucket", 63)
    _text(staged["key"], "s3_key", 1024)
    _text(staged["version_id"], "s3_version_id", 1024)
    if staged["version_id"] == "null":
        raise ValueError("unversioned_object_not_allowed")
    _integer(staged["size_bytes"], "s3_size_bytes", 1)
    _hash(staged["sha256"], "s3_sha256")
    if staged["sha256"] != candidate["model_digest"]:
        raise ValueError("staged_model_digest_mismatch")
    if not isinstance(confirmation, dict) or confirmation != {
            field: staged[field] for field in ("version_id", "sha256", "size_bytes")}:
        raise ValueError("missing_matching_object_confirmation")
    _integer(confirmation["size_bytes"], "confirmed_size_bytes", 1)


def build_publication(table_name, *, run_id, round_id, txn_id, candidate,
                      expected_audit_count, expected_audit_head):
    """Publish a previously authorized staged candidate with all guards atomically.

    Caller MUST validate full history with the version-pinned evaluator before
    calling. This builder cannot infer authorization or inspect S3 from metadata.
    """
    _table(table_name)
    for value, name in ((run_id, "run_id"), (round_id, "round_id"), (txn_id, "txn_id")):
        _identifier(value, name)
    _integer(expected_audit_count, "expected_audit_count")
    _hash(expected_audit_head, "expected_audit_head")
    if (expected_audit_count == 0) != (expected_audit_head == "0" * 64):
        raise ValueError("incoherent_audit_anchor")
    _validated_candidate(candidate)
    if expected_audit_count + len(candidate["updates"]) >= _MAX_NUMBER:
        raise ValueError("audit_sequence_exhausted")
    order = candidate["snapshot_order"] + 1
    run_pk = f"RUN#{run_id}"
    manifest_id = candidate["candidate_id"]
    manifest = {"manifest_id": manifest_id, "run_id": run_id, "round_id": round_id,
                "commit_order": order, "commit_txn_id": txn_id, "candidate": candidate}
    operation_digest = _digest({"kind": "publication", "table": table_name, "run_id": run_id,
                                "round_id": round_id, "txn_id": txn_id, "candidate": candidate,
                                "expected_audit_count": expected_audit_count,
                                "expected_audit_head": expected_audit_head})
    actions = [_sequence_action(table_name, candidate["snapshot_order"], txn_id)]
    for org, epoch in sorted(candidate["policy_epochs"].items()):
        actions.append({"ConditionCheck": {"TableName": table_name, "Key": _key(f"POLICY#{org}", "CURRENT"),
                                          "ConditionExpression": "#epoch = :epoch",
                                          "ExpressionAttributeNames": {"#epoch": "epoch"},
                                          "ExpressionAttributeValues": {":epoch": {"N": str(epoch)}}}})
    pointer_names = {"#pk": "PK", "#manifest": "manifest_id", "#order": "commit_order", "#round": "round_id"}
    pointer_values = {":manifest": manifest_id, ":order": order, ":round": round_id}
    if candidate["parent_manifest_id"] is None:
        pointer_condition = "attribute_exists(#pk) AND attribute_not_exists(#manifest)"
    else:
        pointer_condition = "attribute_exists(#pk) AND #manifest = :parent"
        pointer_values[":parent"] = candidate["parent_manifest_id"]
    actions.append(_update(table_name, run_pk, "POINTER",
                           "SET #manifest = :manifest, #order = :order, #round = :round",
                           pointer_condition, pointer_names, pointer_values))
    actions.append(_update(table_name, run_pk, f"ROUND#{round_id}",
                           "SET #status = :closed, #manifest = :manifest, #order = :order, #pending = :zero",
                           "#status = :open AND #generation = :generation AND #pending = :included",
                           {"#status": "status", "#manifest": "manifest_id", "#order": "commit_order",
                            "#generation": "generation", "#pending": "pending_count"},
                           {":closed": "CLOSED", ":open": "OPEN", ":manifest": manifest_id,
                            ":order": order, ":generation": candidate["round_generation"],
                            ":zero": 0, ":included": len(candidate["updates"])}))
    previous, count = expected_audit_head, expected_audit_count
    for update in sorted(candidate["updates"], key=lambda u: u["update_id"]):
        uid, org = update["update_id"], update["org_id"]
        decision = {**update, "run_id": run_id, "round_id": round_id, "outcome": "accepted",
                    "reason": "continuous_authorization", "evaluation_order": order,
                    "observed_epoch": candidate["policy_epochs"][org],
                    "history_digest": candidate["history_digests"][org],
                    "rule_bundle_hash": candidate["rule_bundle_hash"], "manifest_ref": manifest_id}
        actions.append(_update(table_name, run_pk, f"UPDATE#{uid}",
                               "SET #status = :accepted, #decision = :decision, #manifest = :manifest",
                               "#status = :pending AND #round = :round AND #org = :org AND #task = :task AND #digest = :digest AND #purpose = :purpose AND #start = :start AND #sample_count = :sample_count AND #schema = :schema",
                               {"#status": "status", "#decision": "decision_json", "#manifest": "manifest_id",
                                "#round": "round_id", "#org": "org_id", "#task": "task_id", "#digest": "weights_digest",
                                "#purpose": "purpose", "#start": "start_order", "#sample_count": "sample_count",
                                "#schema": "model_schema_hash"},
                               {":accepted": "accepted", ":pending": "pending", ":decision": _json(decision),
                                ":manifest": manifest_id, ":round": round_id, ":org": org,
                                ":task": update["task_id"], ":digest": update["weights_digest"],
                                ":purpose": update["purpose"], ":start": update["start_order"],
                                ":sample_count": update["sample_count"], ":schema": candidate["model_schema_hash"]}))
        count += 1
        audit_body = {"sequence": count, "prev_hash": previous, "payload": decision}
        event_hash = _digest(audit_body)
        audit_event = {**audit_body, "event_hash": event_hash}
        actions.append(_put(table_name, run_pk, f"AUDIT#{count:020d}",
                            {"record_type": "audit_event", "event_json": _json(audit_event), "event_hash": event_hash}))
        previous = event_hash
    actions.append(_update(table_name, run_pk, "AUDIT_HEAD", "SET #count = :new_count, #head = :new_head",
                           "#count = :old_count AND #head = :old_head",
                           {"#count": "count", "#head": "head"},
                           {":new_count": count, ":new_head": previous,
                            ":old_count": expected_audit_count, ":old_head": expected_audit_head}))
    actions.append(_put(table_name, run_pk, f"MANIFEST#{manifest_id}",
                        {"record_type": "publication_manifest", "manifest_json": _json(manifest),
                         "commit_order": order, "model_digest": candidate["model_digest"]}))
    actions.append(_put(table_name, run_pk, f"TXN#{txn_id}",
                        {"record_type": "transaction_outcome", "request_digest": operation_digest,
                         "operation_kind": "publication", "order": order,
                         "result_json": _json({"manifest_id": manifest_id, "commit_order": order,
                                               "audit_count": count, "audit_head": previous})}))
    return _finish(actions)
