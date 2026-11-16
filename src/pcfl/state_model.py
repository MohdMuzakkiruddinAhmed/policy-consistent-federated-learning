"""Executable local specification of guarded publication.

An in-memory lock MODELS the future single-region transaction boundary. There is
no AWS adapter, durable storage, Rego runtime, network authentication, or FL
training here. Failure and concurrency tests establish local behavior only.
"""

from copy import deepcopy
from dataclasses import asdict
import math
import secrets
import threading

from .contracts import ACTIONS, ModelUpdate, ORGANIZATIONS, TaskAuthorization, digest, positive_integer
from .reference import evaluate_history, validate_event


class Unavailable(RuntimeError):
    """A required service is unavailable; no publication may proceed."""


class ConditionalConflict(RuntimeError):
    """Refresh authoritative state and recompute the complete candidate."""


class LocalProtocolModel:
    def __init__(self, dimension: int = 2):
        if not positive_integer(dimension):
            raise ValueError("invalid_model_dimension")
        self.dimension = dimension
        self.schema_hash = digest({"kind": "vector", "dimension": dimension})
        self._lock = threading.RLock()
        self._order = 0
        self._events = []
        self._epochs = {}
        self._tasks = {}
        self._updates = {}
        self._final = {}
        self._candidates = {}
        self._manifests = {}
        self._rounds = {}
        self._round_generations = {}
        self._pointer = None
        self._audit = []
        self.authority_available = True
        self.audit_available = True
        self.object_store_available = True

    def _require_authority(self):
        if not self.authority_available:
            raise Unavailable("policy_authority_unavailable")

    def _require_audit(self):
        if not self.audit_available:
            raise Unavailable("audit_unavailable")

    def _require_complete_snapshot(self):
        self._require_authority()
        try:
            tails = {}
            for event in self._events:
                tails[event["org_id"]] = event["epoch"]
            if tails != self._epochs:
                raise Unavailable("policy_history_tail_missing")
        except (KeyError, TypeError) as error:
            raise Unavailable("policy_history_unreadable") from error

    def mutate(self, org_id: str, kind: str, rules: list[dict]) -> dict:
        """State, epoch, and immutable history append share one atomic boundary."""
        with self._lock:
            self._require_authority()
            order = self._order + 1
            event = {"event_id": f"policy-{order}", "org_id": org_id, "order": order,
                     "epoch": self._epochs.get(org_id, 0) + 1, "kind": kind,
                     "rules": deepcopy(rules)}
            validate_event(event)
            self._events.append(event)
            self._epochs[org_id] = event["epoch"]
            self._order = order
            return deepcopy(event)

    def _query(self, task: TaskAuthorization, end: int) -> dict:
        return {"org_id": task.org_id, "purpose": task.purpose,
                "start_order": task.start_order, "commit_order": end,
                "actions": list(ACTIONS)}

    def authorize(self, org_id: str, purpose: str, round_id: str) -> TaskAuthorization:
        """Issue+acknowledge is one local transition, not a network token exchange."""
        with self._lock:
            self._require_complete_snapshot()
            if not isinstance(round_id, str) or not round_id.strip() or round_id in self._rounds:
                raise ValueError("invalid_or_closed_round")
            if any(t.org_id == org_id and t.round_id == round_id for t in self._tasks.values()):
                raise ValueError("organization_already_assigned")
            order = self._order + 1
            query = {"org_id": org_id, "purpose": purpose, "start_order": order,
                     "commit_order": order, "actions": list(ACTIONS)}
            if not evaluate_history(self._events, query)["valid"]:
                raise ValueError("dispatch_denied")
            latest = next(e for e in reversed(self._events) if e["org_id"] == org_id)
            task = TaskAuthorization(f"task-{order}", org_id, purpose, round_id, order,
                                     latest["epoch"], digest(latest), self.schema_hash,
                                     secrets.token_hex(16))
            self._tasks[task.task_id] = task
            self._order = order
            return task

    def _audit_records(self, decisions: list[dict]) -> list[dict]:
        """Build first; mutation of decisions/audit/pointer happens only after success."""
        self._require_audit()
        sequence = len(self._audit)
        previous = self._audit[-1]["event_hash"] if self._audit else "0" * 64
        additions = []
        for decision in decisions:
            sequence += 1
            body = {"sequence": sequence, "prev_hash": previous, "payload": deepcopy(decision)}
            previous = digest(body)
            additions.append({**body, "event_hash": previous})
        return additions

    def _reject(self, update: ModelUpdate, reason: str):
        order = self._order + 1
        decision = {"update_id": update.update_id, "org_id": update.task.org_id,
                    "outcome": "rejected", "reason": reason, "evaluation_order": order,
                    "observed_epoch": self._epochs.get(update.task.org_id, 0),
                    "history_digest": digest(self._events), "manifest_ref": None}
        additions = self._audit_records([decision])
        self._updates[update.update_id] = update
        self._final[update.update_id] = decision
        self._audit.extend(additions)
        self._order = order

    def present(self, update: ModelUpdate, authenticated_org: str) -> str:
        with self._lock:
            self._require_complete_snapshot()
            self._require_audit()
            update.validate(self.dimension)
            old = self._updates.get(update.update_id)
            if old is not None:
                # Transport identity must still be verified on a duplicate delivery.
                if authenticated_org != old.task.org_id or old.fingerprint() != update.fingerprint():
                    raise ValueError("update_id_rebound")
                return self._final.get(update.update_id, {}).get("outcome", "pending")
            task = update.task
            if authenticated_org != task.org_id or task.org_id not in ORGANIZATIONS:
                reason = "identity_mismatch"
            elif self._tasks.get(task.task_id) != task or task.model_schema_hash != self.schema_hash:
                reason = "task_binding_mismatch"
            elif task.round_id in self._rounds:
                reason = "round_already_published"
            elif any(u.task.task_id == task.task_id for u in self._updates.values()):
                reason = "task_already_has_update"
            elif not evaluate_history(self._events, self._query(task, self._order + 1))["valid"]:
                reason = "authorization_interrupted"
            else:
                self._updates[update.update_id] = update
                self._round_generations[task.round_id] = self._round_generations.get(task.round_id, 0) + 1
                self._order += 1
                return "pending"
            self._reject(update, reason)
            return "rejected"

    def prepare(self, round_id: str) -> str | None:
        with self._lock:
            self._require_complete_snapshot()
            self._require_audit()
            if round_id in self._rounds:
                raise ValueError("round_already_published")
            pending = [u for uid, u in self._updates.items()
                       if uid not in self._final and u.task.round_id == round_id]
            eligible = []
            for update in pending:
                result = evaluate_history(self._events, self._query(update.task, self._order + 1))
                if result["valid"]:
                    eligible.append(update)
                else:
                    self._reject(update, "authorization_interrupted")
            if not eligible:
                return None
            if not self.object_store_available:
                raise Unavailable("staging_unavailable")
            total = sum(u.sample_count for u in eligible)
            # Scale before summation to avoid overflow for ordinary finite inputs.
            weights = tuple(math.fsum((u.sample_count / total) * u.weights[i] for u in eligible)
                            for i in range(self.dimension))
            if not all(math.isfinite(v) for v in weights):
                raise ValueError("non_finite_candidate")
            snapshot = {"round_id": round_id, "update_ids": sorted(u.update_id for u in eligible),
                        "weights": weights, "model_digest": digest(weights),
                        "policy_epochs": {u.task.org_id: self._epochs[u.task.org_id] for u in eligible},
                        "round_generation": self._round_generations[round_id],
                        "parent_manifest": self._pointer, "history_digest": digest(self._events)}
            candidate_id = digest(snapshot)
            self._candidates[candidate_id] = deepcopy(snapshot)
            return candidate_id

    def commit(self, candidate_id: str) -> dict:
        with self._lock:
            # Durable production recovery needs a stored transaction ID; this is in-memory only.
            if candidate_id in self._manifests:
                return deepcopy(self._manifests[candidate_id])
            self._require_authority()
            self._require_audit()
            if not self.object_store_available:
                raise Unavailable("staged_object_unavailable")
            candidate = self._candidates[candidate_id]
            if digest(candidate) != candidate_id or candidate["model_digest"] != digest(candidate["weights"]):
                raise ValueError("staged_object_digest_mismatch")
            if candidate["parent_manifest"] != self._pointer or candidate["round_id"] in self._rounds:
                raise ConditionalConflict("publication_parent_changed")
            if candidate["round_generation"] != self._round_generations[candidate["round_id"]]:
                raise ConditionalConflict("round_membership_changed")
            for org, epoch in candidate["policy_epochs"].items():
                if self._epochs.get(org) != epoch:
                    raise ConditionalConflict("policy_epoch_changed")
            if any(uid in self._final for uid in candidate["update_ids"]):
                raise ConditionalConflict("update_already_final")
            order = self._order + 1
            manifest = {**deepcopy(candidate), "manifest_id": candidate_id,
                        "commit_order": order, "commit_txn_id": f"local-{order}"}
            decisions = [{"update_id": uid, "org_id": self._updates[uid].task.org_id,
                          "outcome": "accepted", "reason": "continuous_authorization",
                          "evaluation_order": order,
                          "observed_epoch": candidate["policy_epochs"][self._updates[uid].task.org_id],
                          "history_digest": candidate["history_digest"], "manifest_ref": candidate_id}
                         for uid in candidate["update_ids"]]
            additions = self._audit_records(decisions)
            # Local atomic linearization point: no readers/writers interleave inside this lock.
            self._manifests[candidate_id] = manifest
            self._rounds[candidate["round_id"]] = candidate_id
            self._final.update({d["update_id"]: d for d in decisions})
            self._audit.extend(additions)
            self._pointer = candidate_id
            self._order = order
            return deepcopy(manifest)

    def read_published(self) -> dict | None:
        with self._lock:
            return deepcopy(self._manifests[self._pointer]) if self._pointer else None

    def evidence(self) -> dict:
        """Synthetic-only local evidence. An anchor must be protected separately in deployment."""
        with self._lock:
            tasks = [{**{key: value for key, value in asdict(task).items() if key != "nonce"},
                      "nonce_digest": digest(task.nonce)} for task in self._tasks.values()]
            return deepcopy({"policy_events": self._events, "tasks": tasks,
                             "decisions": self._final, "manifests": list(self._manifests.values()),
                             "audit": self._audit,
                             "anchor": {"count": len(self._audit),
                                        "head": self._audit[-1]["event_hash"] if self._audit else "0" * 64}})
