"""Independent preloaded exploratory policy actor and bounded order barriers."""
from copy import deepcopy
import json
import re
import threading
import time

from .contracts import digest
from .robustness import PROTOCOL, factors, schedule
from .scenarios import ScenarioSignal, control_key


def changes(run_id, seed, rounds, value, phase, round_id):
    events = [event for event in schedule(seed, rounds, value) if event["phase"] == phase and event["round_id"] == round_id]
    result = []
    for event in events:
        request_id = "robust-policy-" + digest([PROTOCOL, run_id, event])[:40]
        result.append({**event, "request_id": request_id,
            "event_id": "policy-" + __import__("hashlib").sha256(request_id.encode()).hexdigest()[:40]})
    return result


class RobustScenarioSignal(ScenarioSignal):
    def __init__(self, dynamodb, table_name, run_id, scenario, *, value, seed, rounds, timeout=60, observer=None, **_):
        if scenario != "robustness" or type(timeout) not in (int, float) or not 0 < timeout <= 300:
            raise ValueError("explicit_bounded_robustness_policy_barrier_required")
        self.ddb, self.table, self.run, self.value = dynamodb, table_name, run_id, factors(value)
        self.seed, self.rounds, self.timeout = seed, rounds, timeout
        self.observer = observer

    def reach(self, phase, round_id="initial"):
        expected = changes(self.run, self.seed, self.rounds, self.value, phase, round_id)
        if not expected:
            return
        key = control_key(self.run, phase, round_id)
        item = {**key, "scenario_id": {"S": "robustness"}, "ready": {"BOOL": True},
            "protocol_digest": {"S": digest([PROTOCOL, self.seed, self.rounds, self.value])}}
        bracketed = False
        if self.observer:
            try:
                prior_control = self.ddb.get_item(TableName=self.table, Key=key, ConsistentRead=True).get("Item")
                prior_events = [self._outcome_event(change) for change in expected]
                bracketed = not prior_control and not any(prior_events)
            except Exception as error:
                self.observer.error("policy-window-before", round_id, error)
        signal_start = self.observer.now() if self.observer else None
        try:
            self.ddb.transact_write_items(TransactItems=[{"Put": {"TableName": self.table, "Item": item,
                "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)"}}], ClientRequestToken=digest(item)[:36])
        except Exception:
            bracketed = False
            saved = self.ddb.get_item(TableName=self.table, Key=key, ConsistentRead=True).get("Item", {})
            if saved != item:
                raise
        final = expected[-1]
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            current = self.ddb.get_item(TableName=self.table, ConsistentRead=True,
                Key={"PK": {"S": "POLICY#" + final["org_id"]}, "SK": {"S": "CURRENT"}}).get("Item", {})
            event = json.loads(current["event_json"]["S"]) if current.get("event_json") else None
            if event and event["event_id"] == final["event_id"]:
                if self.observer:
                    observed_end = self.observer.now()
                    for change in expected:
                        try:
                            observed = event if change["event_id"] == final["event_id"] else self._outcome_event(change)
                            if observed is None or any(observed[name] != change[name] for name in ("event_id", "org_id", "kind")):
                                raise ValueError("observed_policy_outcome_missing_or_rebound")
                            self.observer.policy_window(observed, phase=phase, round_id=round_id,
                                start=signal_start, end=observed_end, bracketed=bracketed)
                        except Exception as error:
                            self.observer.error("policy-window-after", round_id, error, event_id=change["event_id"])
                return
            time.sleep(min(.05, max(0, deadline-time.monotonic())))
        raise TimeoutError("independent_robustness_policy_actor_did_not_acknowledge")


class RobustScenarioWatcher:
    def __init__(self, writer, campaign, *, poll_seconds=.05):
        if (not isinstance(campaign, dict) or set(campaign) != {"protocol_id", "runs"} or campaign["protocol_id"] != PROTOCOL
                or not isinstance(campaign["runs"], list) or not 1 <= len(campaign["runs"]) <= 300):
            raise ValueError("fixed_exploratory_policy_campaign_required")
        ids = set()
        for run in campaign["runs"]:
            if (not isinstance(run, dict) or set(run) != {"run_id", "rounds", "seed", "factors"}
                    or not isinstance(run["run_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,80}", run["run_id"])
                    or run["run_id"] in ids or type(run["rounds"]) is not int or not 2 <= run["rounds"] <= 100
                    or type(run["seed"]) is not int or not 0 <= run["seed"] < 2**32):
                raise ValueError("fixed_exploratory_policy_run_binding_required")
            factors(run["factors"]); ids.add(run["run_id"])
        self.writer, self.runs, self.poll = writer, deepcopy(campaign["runs"]), poll_seconds
        self.stop_event, self.thread, self.error = threading.Event(), None, None

    def _run(self):
        try:
            for run in self.runs:
                phases = [("before_run", "initial")]
                phases += [(phase, f"round-{number}") for number in range(1, run["rounds"]+1)
                           for phase in ("before_round", "after_dispatch", "before_commit")]
                for phase, round_id in phases:
                    actions = changes(run["run_id"], run["seed"], run["rounds"], run["factors"], phase, round_id)
                    if not actions:
                        continue
                    key = control_key(run["run_id"], phase, round_id)
                    expected = {**key, "scenario_id": {"S": "robustness"}, "ready": {"BOOL": True},
                        "protocol_digest": {"S": digest([PROTOCOL, run["seed"], run["rounds"], factors(run["factors"])])}}
                    while not self.stop_event.is_set():
                        item = self.writer.ddb.get_item(TableName=self.writer.table, Key=key, ConsistentRead=True).get("Item", {})
                        if item:
                            if item != expected:
                                raise ValueError("robustness_policy_control_rebound")
                            break
                        self.stop_event.wait(self.poll)
                    if self.stop_event.is_set():
                        return
                    for action in actions:
                        event = self.writer.mutate(action["org_id"], action["kind"], request_id=action["request_id"])
                        if event["event_id"] != action["event_id"]:
                            raise ValueError("robustness_policy_mutation_identity_mismatch")
                        print(json.dumps({"kind": "exploratory-policy-mutation", "run_id": run["run_id"],
                            "phase": phase, "round_id": round_id, "org_id": action["org_id"], "event_id": event["event_id"],
                            "order": event["order"], "epoch": event["epoch"]}), flush=True)
        except Exception as error:
            self.error = type(error).__name__

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True, name="exploratory-policy-writer")
        self.thread.start()
        return self

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
