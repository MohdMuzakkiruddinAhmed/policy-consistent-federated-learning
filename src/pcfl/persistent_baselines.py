"""Durable intentionally weaker governance comparators for matched cloud runs.

All transport identity, replay, array, object, transaction, pointer and audit
checks use the shared persistent engine. Baseline authorization is explicitly
limited to none, initial admission, or task dispatch. No posthoc OPA calls occur.
"""

from copy import deepcopy
import json

from . import aws_transactions as tx
from .contracts import digest
from .persistent import PersistentAuthority, PersistentConflict, PersistentUnavailable, _repack

MODES = {"B1": "none", "B2": "admission_cached", "B3": "dispatch_only"}
OMITTED_GUARDS = ["receipt_authorization", "continuous_interval_authorization", "publication_policy_epoch"]


def _without_policy_guards(request):
    result = deepcopy(request)
    result["TransactItems"] = [action for action in result["TransactItems"]
        if not action.get("ConditionCheck", {}).get("Key", {}).get("PK", {}).get("S", "").startswith("POLICY#")]
    return _repack(result)


def _replace_identity(value, old, new):
    if isinstance(value, dict):
        return {key: _replace_identity(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_identity(item, old, new) for item in value]
    if isinstance(value, str):
        if value == old:
            return new
        if value == "MANIFEST#" + old:
            return "MANIFEST#" + new
        if value.startswith("{") or value.startswith("["):
            try:
                return tx._json(_replace_identity(json.loads(value), old, new))
            except json.JSONDecodeError:
                pass
    return value


class PersistentBaselineAuthority(PersistentAuthority):
    def __init__(self, *args, baseline_id, policy_evaluator=None, **kwargs):
        if baseline_id not in MODES:
            raise ValueError("persistent_baseline_id_required")
        self.baseline_id, self.policy_mode = baseline_id, MODES[baseline_id]
        if baseline_id != "B1" and not callable(policy_evaluator):
            raise ValueError("admission_or_dispatch_requires_native_policy_evaluator")
        # B1 never invokes this function; a supplied evaluator is also unused.
        def forbidden(*_args, **_kwargs):
            raise RuntimeError("B1_must_not_call_OPA")
        super().__init__(*args, policy_evaluator=policy_evaluator if baseline_id != "B1" else forbidden, **kwargs)

    def _transact(self, request, txn_id, *, authority=False):
        # Policy state writes remain intact. Only authorization ConditionChecks
        # on run operations are omitted; structural sequencer/CAS guards remain.
        return super()._transact(request if authority else _without_policy_guards(request), txn_id, authority=authority)

    def _admission(self, snapshot, org):
        for _ in range(self.max_attempts):
            stored = snapshot["items"].get(f"ADMISSION#{org}")
            if stored:
                return json.loads(stored["opa_decision_json"])
            decision = self._policy(snapshot, org, snapshot["order"], snapshot["order"])
            identifier = self._txn_id("admission")
            request = self._manual([tx._sequence_action(self.table, snapshot["order"], identifier),
                tx._put(self.table, self.pk, f"ADMISSION#{org}", {"baseline_id": self.baseline_id,
                    "policy_decision_mode": self.policy_mode, "opa_decision_json": tx._json(decision)})],
                identifier, "baseline_admission", snapshot["order"] + 1,
                {"org_id": org, "allowed": decision["valid"], "policy_decision_id": decision["decision_id"]})
            try:
                self._transact(request, identifier)
                # Admission consumes an authority order. Refresh the same
                # caller snapshot before it builds the task transaction.
                snapshot.clear(); snapshot.update(self.snapshot())
                return decision
            except PersistentConflict:
                snapshot.clear(); snapshot.update(self.snapshot())
        raise PersistentUnavailable("baseline_admission_retry_exhausted")

    def _authorization(self, snapshot, org, start, end, *, stage, task_id=None):
        if self.baseline_id == "B1":
            return {"valid": True, "reason": "baseline_no_policy_check", "decision_id": None,
                    "query": None, "policy_decision_mode": "none", "rule_hash": self.rule_hash}
        if self.baseline_id == "B2":
            if stage == "issue":
                return self._admission(snapshot, org)
            admission = snapshot["items"].get(f"ADMISSION#{org}")
            if not admission:
                raise PersistentUnavailable("baseline_admission_provenance_missing")
            return json.loads(admission["opa_decision_json"])
        if stage == "issue":
            return self._policy(snapshot, org, start, end)
        issued = snapshot["items"].get(f"ISSUE#{task_id}")
        if not issued:
            raise PersistentUnavailable("baseline_dispatch_provenance_missing")
        return json.loads(issued["opa_decision_json"])

    def _acknowledgment_policy(self, snapshot, stored):
        # Receipt of an authenticated acknowledgment defines task start; a
        # baseline deliberately does not reauthorize after its last check.
        return None

    def _candidate_context(self, context):
        result = deepcopy(context)
        result.update(baseline_id=self.baseline_id, policy_decision_mode=self.policy_mode,
                      omitted_guards=list(OMITTED_GUARDS), observed_policy_epochs=result["policy_epochs"],
                      policy_epochs={})
        return result

    def _publication_request(self, **kwargs):
        actual = kwargs["candidate"]
        # Reuse typed structural request construction, then replace the
        # temporary P1-shaped metadata before any request can leave the process.
        temporary = {key: deepcopy(value) for key, value in actual.items()
                     if key not in {"candidate_id", "baseline_id", "policy_decision_mode", "omitted_guards", "observed_policy_epochs"}}
        temporary["policy_epochs"] = deepcopy(actual["observed_policy_epochs"])
        temporary["candidate_id"] = tx.candidate_digest(temporary)
        request = tx.build_publication(self.table, **{**kwargs, "candidate": temporary})
        request = _replace_identity(request, temporary["candidate_id"], actual["candidate_id"])
        for action in request["TransactItems"]:
            item = action.get("Put", {}).get("Item", {})
            if item.get("record_type") == {"S": "publication_manifest"}:
                manifest = json.loads(item["manifest_json"]["S"])
                manifest["candidate"] = deepcopy(actual)
                item["manifest_json"] = {"S": tx._json(manifest)}
        return _without_policy_guards(request)

    def _policy_evidence(self, request, evaluations):
        request = deepcopy(request)
        decisions, provenance = {}, {}
        for action in request["TransactItems"]:
            values = action.get("Update", {}).get("ExpressionAttributeValues", {})
            if ":decision" not in values:
                continue
            decision = json.loads(values[":decision"]["S"])
            evaluation = evaluations[decision["update_id"]]
            reference = None if self.baseline_id == "B1" else (f"ADMISSION#{decision['org_id']}" if self.baseline_id == "B2" else f"ISSUE#{decision['task_id']}")
            decision.update(baseline_id=self.baseline_id, policy_decision_mode=self.policy_mode,
                history_digest_scope="organization", policy_decision_id=evaluation.get("decision_id"),
                policy_query=evaluation.get("query"), policy_evidence_ref=reference)
            if decision["outcome"] == "accepted":
                decision["reason"] = "baseline_acceptance"
            decisions[decision["update_id"]] = decision
            provenance[decision["update_id"]] = {"baseline_id": self.baseline_id, "policy_decision_mode": self.policy_mode,
                "policy_evidence_ref": reference, "policy_evaluation": deepcopy(evaluation) if reference else None}
            values[":decision"] = {"S": tx._json(decision)}
        audits = sorted((action["Put"]["Item"] for action in request["TransactItems"] if "Put" in action
            and action["Put"]["Item"].get("record_type") == {"S": "audit_event"}), key=lambda item: item["SK"]["S"])
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
        return _repack(request, [tx._put(self.table, self.pk, f"BASELINE_FINAL#{uid}",
            {"provenance_json": tx._json(value)}) for uid, value in sorted(provenance.items())])

    def _normalized_manifest(self, record):
        result = super()._normalized_manifest(record)
        candidate = result["candidate_metadata"]
        if (candidate.get("baseline_id") != self.baseline_id or candidate.get("policy_decision_mode") != self.policy_mode
                or candidate.get("omitted_guards") != OMITTED_GUARDS or candidate["policy_epochs"] != {}):
            raise PersistentUnavailable("baseline_manifest_mode_binding_mismatch")
        result.update(guarded_policy_publication=False, baseline_id=self.baseline_id,
                      policy_decision_mode=self.policy_mode, baseline_comparator=True,
                      observed_policy_epochs=candidate["observed_policy_epochs"])
        return result

    def evidence(self):
        result = super().evidence()
        result.update(baseline_id=self.baseline_id, baseline_comparator=True, policy_decision_mode=self.policy_mode,
                      opa_used=self.baseline_id != "B1", publication_policy_epoch_guards=False)
        return result
