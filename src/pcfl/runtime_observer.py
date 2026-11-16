"""Read-only, coordinator-local timing observations; never authorize or mutate policy.

All times are relative milliseconds from one perf_counter clock. Policy commit
times are brackets, not point timestamps. A missing observation stays missing.
"""
from contextlib import contextmanager
from copy import deepcopy
import time


class RuntimeObserver:
    def __init__(self, run_id, *, clock=None):
        self.clock = clock or time.perf_counter
        self.origin = self.clock()
        self.run_id = run_id
        self.policy_windows, self.operations, self.stages, self.errors = [], [], [], []
        self.closed = False

    def now(self):
        return (self.clock() - self.origin) * 1000

    def error(self, source, round_id, error, *, event_id=None):
        self.errors.append({"source": source, "round_id": round_id, "event_id": event_id,
                            "error_type": type(error).__name__})

    def policy_window(self, event, *, phase, round_id, start, end, bracketed):
        self.policy_windows.append({**{key: event[key] for key in ("event_id", "org_id", "kind", "order", "epoch")},
            "phase": phase, "round_id": round_id,
            "status": "bracketed-new-commit" if bracketed else "preexisting-or-replayed",
            "signal_start_ms": start if bracketed else None, "observed_end_ms": end if bracketed else None})

    def call(self, operation, function, *, round_id, org_id=None, task_id=None, update_id=None, describe=None):
        start = self.now()
        record = {"sequence": len(self.operations) + 1, "operation": operation, "round_id": round_id,
            "org_id": org_id, "task_id": task_id, "update_id": update_id, "start_ms": start, "end_ms": None,
            "outcome": None, "observation_order": None, "manifest_id": None,
            "included_update_ids": [], "excluded_update_ids": [], "pending_update_ids": []}
        try:
            result = function()
        except BaseException:
            record.update(end_ms=self.now(), outcome="exception")
            self.operations.append(record)
            raise
        record["end_ms"] = self.now()
        try:
            record.update(describe(result) if describe else {"outcome": result})
        except Exception as error:
            self.error("operation-description", round_id, error)
        else:
            self.operations.append(record)
        return result

    def stage(self, name, start, *, round_id=None, status="complete"):
        self.stages.append({"sequence": len(self.stages) + 1, "name": name, "round_id": round_id,
                            "start_ms": start, "end_ms": self.now(), "status": status})

    def close(self, *, status):
        if not self.closed:
            self.stage("run", 0.0, status=status)
            self.closed = True
        elif status == "error":
            self.stages[-1].update(end_ms=self.now(), status="error")

    def export(self):
        return deepcopy({"schema_version": "0.1.0", "clock": "coordinator-perf-counter-relative-ms",
            "run_id": self.run_id, "policy_windows": self.policy_windows, "operations": self.operations,
            "stages": self.stages, "errors": self.errors})


@contextmanager
def timed_stage(observer, name, *, round_id=None):
    start = observer.now() if observer else None
    try:
        yield
    except BaseException:
        if observer:
            observer.stage(name, start, round_id=round_id, status="error")
        raise
    else:
        if observer:
            observer.stage(name, start, round_id=round_id)


def observed_call(observer, operation, function, **options):
    return observer.call(operation, function, **options) if observer else function()
