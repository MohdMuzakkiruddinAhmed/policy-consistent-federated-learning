"""Independent scripted policy actor and credential-free lifecycle barriers.

The coordinator can signal only a lifecycle phase. The governance task owns the
preloaded schedule and its writer identity. No policy-writer key reaches the
coordinator or a learning client.
"""

from copy import deepcopy
import hashlib
import json
import re
import threading
import time

from .contracts import ACTIONS, ORGANIZATIONS, digest

ALIASES = {"stable": "S0", "between_round": "S1", "mid_round": "S2", "delayed": "S3",
           "revoke_regrant": "S4", "purpose_change": "S5", "expiry": "S5", "near_commit": "S6"}


def transitions(run_id, scenario, phase, round_id, *, target_org="org_01", policy_action="EXPIRE"):
    if target_org not in ORGANIZATIONS:
        raise ValueError("unknown_scenario_organization")
    if policy_action not in {"EXPIRE", "CHANGE"}:
        raise ValueError("unknown_purpose_or_expiry_action")
    scenario = ALIASES.get(scenario, scenario)
    actions = []
    if phase == "before_run":
        actions = [(org, "GRANT", None) for org in ORGANIZATIONS]
    elif scenario == "S1" and phase == "before_round" and round_id == "round-2":
        actions = [(target_org, "REVOKE", None)]
    elif scenario in {"S2", "S3", "S4", "S5"} and phase == "after_dispatch" and round_id == "round-1":
        if scenario == "S5":
            actions = [(target_org, policy_action, [{"purpose": "unrelated_research", "action": action, "effect": "allow"}
                        for action in ACTIONS] if policy_action == "CHANGE" else [])]
        else:
            actions = [(target_org, "REVOKE", None)]
            if scenario == "S4":
                actions.append((target_org, "GRANT", None))
    elif scenario == "S6" and phase == "before_commit" and round_id == "round-1":
        actions = [(target_org, "REVOKE", None)]
    result = []
    for index, (org, kind, rules) in enumerate(actions):
        request_id = "scenario-" + digest([run_id, phase, round_id, index, org, kind])[:48]
        event_id = "policy-" + hashlib.sha256(request_id.encode()).hexdigest()[:40]
        result.append({"org_id": org, "kind": kind, "rules": rules, "request_id": request_id, "event_id": event_id})
    return result


def control_key(run_id, phase, round_id):
    if phase not in {"before_run", "before_round", "after_dispatch", "before_commit"}:
        raise ValueError("unknown_scenario_barrier")
    return {"PK": {"S": "RUN#" + run_id}, "SK": {"S": f"CONTROL#{phase}#{round_id}"}}


class ScenarioSignal:
    def __init__(self, dynamodb, table_name, run_id, scenario, *, timeout=60, target_org="org_01", policy_action="EXPIRE", observer=None):
        self.ddb, self.table, self.run, self.scenario = dynamodb, table_name, run_id, scenario
        self.timeout = timeout
        self.target_org = target_org
        self.policy_action = policy_action
        self.observer = observer

    def _outcome_event(self, change):
        item = self.ddb.get_item(TableName=self.table, Key={"PK": {"S": "AUTHORITY"},
            "SK": {"S": "TXN#" + change["event_id"]}}, ConsistentRead=True).get("Item", {})
        if not item:
            return None
        event = json.loads(item["result_json"]["S"])["event"]
        if any(event[name] != change[name] for name in ("event_id", "org_id", "kind")):
            raise ValueError("observed_policy_outcome_binding_mismatch")
        return event

    def reach(self, phase, round_id="initial"):
        expected = transitions(self.run, self.scenario, phase, round_id, target_org=self.target_org, policy_action=self.policy_action)
        if not expected:
            return
        key = control_key(self.run, phase, round_id)
        item = {**key, "scenario_id": {"S": ALIASES.get(self.scenario, self.scenario)}, "ready": {"BOOL": True}}
        # These read-only checks distinguish a new signal from an idempotent replay.
        # Observation failure must not change the existing barrier's semantics.
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
            current = self.ddb.get_item(TableName=self.table, Key={"PK": {"S": "POLICY#" + final["org_id"]}, "SK": {"S": "CURRENT"}},
                                        ConsistentRead=True).get("Item", {})
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
            time.sleep(0.05)
        raise TimeoutError("independent_policy_actor_did_not_acknowledge_barrier")


class ScenarioWatcher:
    def __init__(self, writer, campaign, *, poll_seconds=0.05):
        runs = campaign["runs"]
        if not isinstance(runs, list) or not runs or len(runs) > 300:
            raise ValueError("invalid_fixed_policy_campaign")
        run_ids = set()
        for run in runs:
            if (not isinstance(run, dict) or not {"run_id", "scenario_id", "rounds"} <= set(run)
                    or set(run) - {"run_id", "scenario_id", "rounds", "target_org", "policy_action"}
                    or not isinstance(run["run_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,80}", run["run_id"])
                    or ALIASES.get(run["scenario_id"], run["scenario_id"]) not in {f"S{i}" for i in range(9)}
                    or type(run["rounds"]) is not int or not 1 <= run["rounds"] <= 100
                    or run["run_id"] in run_ids or run.get("target_org", "org_01") not in ORGANIZATIONS
                    or run.get("policy_action", "EXPIRE") not in {"EXPIRE", "CHANGE"}):
                raise ValueError("invalid_fixed_policy_run")
            run_ids.add(run["run_id"])
        self.writer, self.runs, self.poll = writer, deepcopy(runs), poll_seconds
        self.stop_event = threading.Event()
        self.thread = None
        self.error = None

    def _run(self):
        try:
            for run in self.runs:
                run_id, scenario, rounds = run["run_id"], run["scenario_id"], run["rounds"]
                phases = [("before_run", "initial")]
                phases += [(phase, f"round-{number}") for number in range(1, rounds+1)
                           for phase in ("before_round", "after_dispatch", "before_commit")]
                for phase, round_id in phases:
                    changes = transitions(run_id, scenario, phase, round_id, target_org=run.get("target_org", "org_01"),
                                          policy_action=run.get("policy_action", "EXPIRE"))
                    if not changes:
                        continue
                    key = control_key(run_id, phase, round_id)
                    while not self.stop_event.is_set():
                        record = self.writer.ddb.get_item(TableName=self.writer.table, Key=key, ConsistentRead=True,
                            ProjectionExpression="#pk,#sk,#scenario,#ready",
                            ExpressionAttributeNames={"#pk": "PK", "#sk": "SK", "#scenario": "scenario_id", "#ready": "ready"}).get("Item", {})
                        if record:
                            if record != {**key, "scenario_id": {"S": ALIASES.get(scenario, scenario)}, "ready": {"BOOL": True}}:
                                raise ValueError("scenario_control_binding_mismatch")
                            break
                        self.stop_event.wait(self.poll)
                    if self.stop_event.is_set():
                        return
                    for change in changes:
                        started = time.perf_counter()
                        event = self.writer.mutate(change["org_id"], change["kind"], rules=change["rules"], request_id=change["request_id"])
                        if event["event_id"] != change["event_id"]:
                            raise ValueError("scenario_mutation_identity_mismatch")
                        print(json.dumps({"event": "scripted-policy-mutation", "run_id": run_id, "phase": phase,
                            "round_id": round_id, "event_id": event["event_id"], "order": event["order"], "epoch": event["epoch"],
                            "duration_ms": (time.perf_counter()-started)*1000}), flush=True)
        except Exception as error:
            self.error = type(error).__name__
            # The coordinator's barrier cannot complete after a writer error.
            # The actor exposes no guessed acknowledgment or permission.

    def start(self):
        self.thread = threading.Thread(target=self._run, name="fixed-policy-scenario", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
