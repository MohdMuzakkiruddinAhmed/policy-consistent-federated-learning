"""Explicit partial-protocol variants; never silently replace full P1.

SDK clients are injected. These variants retain real weighted publication,
immutable objects, idempotency and all non-ablated structural conditions.
"""

from copy import deepcopy
import json

from . import aws_transactions as tx
from .contracts import digest
from .persistent import PersistentAuthority, PersistentUnavailable, _repack
from .persistent_baselines import _replace_identity

VARIANTS = {
    "Abl-1": {"omitted": ["receipt_native_authorization"], "epoch_checks": True, "audit": True, "full_interval": True},
    "Abl-2": {"omitted": ["publication_contributor_epoch_checks"], "epoch_checks": False, "audit": True, "full_interval": True},
    "Abl-3": {"omitted": ["persistent_audit_chain"], "epoch_checks": True, "audit": False, "full_interval": True},
    "Abl-4": {"omitted": ["continuous_authorization_history"], "epoch_checks": True, "audit": True, "full_interval": False},
}


def _publication(request):
    return any(action.get("Put", {}).get("Item", {}).get("record_type") == {"S": "publication_manifest"}
               for action in request["TransactItems"])


def _omit_audit(request):
    result = deepcopy(request)
    kept = []
    for action in result["TransactItems"]:
        operation = action.get("Put", action.get("Update", action.get("ConditionCheck", {})))
        item = operation.get("Item", operation.get("Key", {}))
        key = item.get("SK", {}).get("S", "")
        # Keep the empty bootstrap bookkeeping row required by the shared
        # lifecycle reader; omit every decision append and head advancement.
        if (key == "AUDIT_HEAD" and "Put" not in action) or key.startswith("AUDIT#"):
            continue
        if item.get("record_type") == {"S": "transaction_outcome"}:
            outcome = json.loads(item["result_json"]["S"])
            if "audit_count" in outcome or "audit_head" in outcome:
                outcome.pop("audit_count", None); outcome.pop("audit_head", None)
                outcome["audit_persistence"] = "omitted-by-Abl-3"
                item["result_json"] = {"S": tx._json(outcome)}
        kept.append(action)
    result["TransactItems"] = kept
    return _repack(result)


class PersistentAblationAuthority(PersistentAuthority):
    def __init__(self, *args, ablation_id, **kwargs):
        if ablation_id not in VARIANTS:
            raise ValueError("explicit_ablation_id_required")
        self.ablation_id = ablation_id
        self.variant = deepcopy(VARIANTS[ablation_id])
        self.native_policy_calls, self.authorization_trace, self.transaction_trace = 0, [], []
        super().__init__(*args, **kwargs)

    def _authorization(self, snapshot, org, start, end, *, stage, task_id=None):
        if self.ablation_id == "Abl-1" and stage == "receipt":
            result = {"valid": True, "reason": "Abl-1_receipt_check_omitted", "decision_id": None,
                      "query": None, "rule_hash": self.rule_hash, "native_policy_checked": False}
        else:
            query_start = end if self.ablation_id == "Abl-4" and stage in {"receipt", "publication", "final"} else start
            result = self._policy(snapshot, org, query_start, end)
            self.native_policy_calls += 1
        self.authorization_trace.append({"stage": stage, "task_id": task_id, "org_id": org,
            "actual_query": deepcopy(result.get("query")), "native_decision_id": result.get("decision_id"),
            "native_policy_checked": result.get("decision_id") is not None})
        return result

    def _candidate_context(self, context):
        result = deepcopy(context)
        result.update(ablation_id=self.ablation_id, ablated_safeguards=self.variant["omitted"], full_protocol=False,
            observed_policy_epochs=deepcopy(result["policy_epochs"]),
            guard_configuration={"publication_contributor_epoch_checks": self.variant["epoch_checks"],
                "global_policy_sequence_CAS": True, "continuous_authorization": self.variant["full_interval"],
                "persistent_audit": self.variant["audit"]})
        if not self.variant["epoch_checks"]:
            result["policy_epochs"] = {}
        return result

    def _publication_request(self, **kwargs):
        actual = kwargs["candidate"]
        extra = {"candidate_id", "ablation_id", "ablated_safeguards", "full_protocol", "observed_policy_epochs", "guard_configuration"}
        temporary = {key: deepcopy(value) for key, value in actual.items() if key not in extra}
        temporary["policy_epochs"] = deepcopy(actual["observed_policy_epochs"])
        temporary["candidate_id"] = digest(temporary)
        request = tx.build_publication(self.table, **{**kwargs, "candidate": temporary})
        request = _replace_identity(request, temporary["candidate_id"], actual["candidate_id"])
        for action in request["TransactItems"]:
            item = action.get("Put", {}).get("Item", {})
            if item.get("record_type") == {"S": "publication_manifest"}:
                raw = json.loads(item["manifest_json"]["S"])
                raw["candidate"] = deepcopy(actual)
                item["manifest_json"] = {"S": tx._json(raw)}
        return _repack(request)

    def _transact(self, request, txn_id, *, authority=False):
        request = deepcopy(request)
        publication = _publication(request)
        if not authority and publication and self.ablation_id == "Abl-2":
            request["TransactItems"] = [action for action in request["TransactItems"]
                if not action.get("ConditionCheck", {}).get("Key", {}).get("PK", {}).get("S", "").startswith("POLICY#")]
        if not authority and self.ablation_id == "Abl-3":
            request = _omit_audit(request)
        request = _repack(request)
        if publication:
            sequence = [action["Update"] for action in request["TransactItems"]
                if action.get("Update", {}).get("Key") == {"PK": {"S": "AUTHORITY"}, "SK": {"S": "SEQUENCE"}}]
            epoch_checks = sum(action.get("ConditionCheck", {}).get("Key", {}).get("PK", {}).get("S", "").startswith("POLICY#")
                               for action in request["TransactItems"])
            if len(sequence) != 1 or sequence[0].get("ConditionExpression") != "#ord = :expected":
                raise PersistentUnavailable("ablation_must_retain_global_sequence_CAS")
            self.transaction_trace.append({"transaction_id": txn_id, "publication": True,
                "global_sequence_CAS_retained": True, "contributor_epoch_checks": epoch_checks,
                "persistent_audit_actions": sum("AUDIT" in action.get("Put", action.get("Update", {})).get("Item",
                    action.get("Update", {}).get("Key", {})).get("SK", {}).get("S", "") for action in request["TransactItems"])})
        return super()._transact(request, txn_id, authority=authority)

    def _normalized_manifest(self, record):
        result = super()._normalized_manifest(record)
        candidate = result["candidate_metadata"]
        if candidate.get("ablation_id") != self.ablation_id or candidate.get("full_protocol") is not False:
            raise PersistentUnavailable("ablation_manifest_provenance_missing")
        result.update(ablation_id=self.ablation_id, full_protocol=False,
            guarded_policy_publication=self.variant["epoch_checks"], observed_policy_epochs=candidate["observed_policy_epochs"],
            guard_configuration=candidate["guard_configuration"])
        return result

    def evidence(self):
        result = super().evidence()
        result.update(ablation_id=self.ablation_id, full_protocol=False,
            ablated_safeguards=self.variant["omitted"], ablation_native_policy_calls=self.native_policy_calls,
            ablation_authorization_trace=deepcopy(self.authorization_trace), ablation_transaction_trace=deepcopy(self.transaction_trace),
            global_policy_sequence_fence_retained=True, unsafe_if_global_fence_absent=self.ablation_id == "Abl-2",
            persistent_audit_expected=self.variant["audit"])
        return result
