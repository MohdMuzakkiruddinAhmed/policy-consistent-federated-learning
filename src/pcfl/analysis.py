"""Prespecified paired run/seed analysis of aggregate experiment attempts.

Never reads holdout records or imports the authorization/aggregation producer.
Incomplete, failed, synthetic, or unfrozen work cannot acquire a research verdict.
"""

from collections import Counter, defaultdict
import csv
import io
import json
import math
from pathlib import Path

import numpy as np

from .experiments import BASELINES, DISTRIBUTIONS, LATENCY_SERIES, SEEDS, digest, validate_attempt, validate_plan


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def h4_noninferior(lower_bound):
    return math.isfinite(lower_bound) and lower_bound > -0.02 and not math.isclose(lower_bound, -0.02, rel_tol=0, abs_tol=1e-12)


def paired_bootstrap(left, right, *, resamples=10000, seed=271828):
    """Resample matched independent seed indices, preserving each pair."""
    left, right = np.asarray(left, dtype=float), np.asarray(right, dtype=float)
    if (left.ndim != 1 or left.shape != right.shape or len(left) < 2
            or not np.isfinite(left).all() or not np.isfinite(right).all()
            or type(resamples) is not int or not 1000 <= resamples <= 1_000_000
            or type(seed) is not int or not 0 <= seed < 2**32):
        raise ValueError("bounded_finite_paired_seed_samples_required")
    differences = left - right
    rng = np.random.default_rng(seed)
    # Bound memory even when a caller requests many resamples.
    values = []
    for first in range(0, resamples, 10000):
        indices = rng.integers(0, len(left), size=(min(10000, resamples - first), len(left)))
        values.append(differences[indices].mean(axis=1))
    distribution = np.concatenate(values)
    return {"mean_difference": float(differences.mean()), "ci95_lower": float(np.quantile(distribution, 0.025)),
            "ci95_upper": float(np.quantile(distribution, 0.975)),
            "one_sided95_lower": float(np.quantile(distribution, 0.05)),
            "independent_seeds": len(left), "bootstrap_resamples": resamples,
            "bootstrap_seed": seed, "method": "paired-percentile-seed-clusters",
            "degenerate_observed_differences": bool(np.all(differences == differences[0]))}


def _counts(rows, numerator, denominator):
    n = sum(row["metrics"].get(numerator, 0) for row in rows)
    d = sum(row["metrics"].get(denominator, 0) for row in rows)
    missing = sum(not {numerator, denominator} <= set(row["metrics"]) for row in rows)
    return {"numerator": n, "denominator": d, "rate": rate(n, d) if not missing else None,
            "attempts_missing_counts": missing}


def responsiveness_tables(rows, baseline):
    """Describe measured brackets and censoring without an exact-lag estimate."""
    observations = [row["metrics"].get("revocation_response") for row in rows]
    present = [value for value in observations if value is not None]
    intervals = [{"baseline_id": baseline, "attempt_id": attempt["attempt_id"], "cell_id": attempt["cell_id"],
        "attempt_status": attempt["status"], **event} for attempt, value in zip(rows, observations) if value for event in value["events"]]
    upper = [row["response_upper_ms"] for row in intervals if row["status"] == "measured"]
    unknown = sum(value is None or value["opportunity_events"] is None for value in observations)
    summary = {"baseline_id": baseline, "attempts": len(rows),
        "no_event_attempts": sum(value["status"] == "no-event" for value in present),
        "missing_trace_attempts": unknown,
        "attempts_with_missing_measurements": sum(value is None or value["status"] == "missing" or value["missing_events"] not in (0, None) for value in observations),
        "opportunity_events": None if unknown else sum(value["opportunity_events"] for value in present),
        "measured_events": sum(value["measured_events"] for value in present),
        "right_censored_events": sum(value["right_censored_events"] for value in present),
        "missing_events": None if unknown else sum(value["missing_events"] for value in present),
        "exact_response_ms": None,
        "observed_upper_bound_p50_ms": float(np.quantile(upper, .50)) if upper else None,
        "observed_upper_bound_p95_ms": float(np.quantile(upper, .95)) if upper else None,
        "observed_upper_bound_p99_ms": float(np.quantile(upper, .99)) if upper else None,
        "quantile_scope": "measured-event-upper-bounds-only;not-exact-or-censor-adjusted",
        "inferential_unit": "descriptive-events-not-independent-seed-replicates",
        "post_revocation_invalid_publications": _counts(rows, "post_revocation_invalid_publications", "published_models")}
    return summary, intervals


def analyze_registry(plan, attempts, *, bootstrap_resamples=None, bootstrap_seed=None):
    validate_plan(plan)
    config = plan["configuration"]["analysis"]
    resamples = config["bootstrap_resamples"] if bootstrap_resamples is None else bootstrap_resamples
    seed = config["bootstrap_seed"] if bootstrap_seed is None else bootstrap_seed
    registered_statistics = resamples == config["bootstrap_resamples"] and seed == config["bootstrap_seed"]
    ids, by_cell = set(), defaultdict(list)
    for attempt in attempts:
        validate_attempt(plan, attempt, _plan_validated=True)
        if attempt["attempt_id"] in ids:
            raise ValueError("duplicate_attempt_identity_in_analysis")
        ids.add(attempt["attempt_id"])
        by_cell[attempt["cell_id"]].append(attempt)
    primary = plan["primary_cells"]
    primary_ids = {cell["cell_id"] for cell in primary}
    clean = {cell_id: rows[0] for cell_id, rows in by_cell.items() if len(rows) == 1 and rows[0]["status"] == "successful"}
    complete = all(cell["cell_id"] in clean for cell in primary)
    primary_attempts = [row for row in attempts if row["cell_id"] in primary_ids]
    genuine = all(row["metrics"].get("data_kind") == "clinical" and row["execution"].get("eight_separate_fargate_clients") is True
                  and len(set(row["execution"].get("client_task_ids", []))) == 8 for row in primary_attempts)
    can_decide = complete and genuine and plan["status"] == "accepted_frozen" and registered_statistics
    lookup = {(c["baseline_id"], c["distribution"], c["scenario_id"], c["seed"]): clean[c["cell_id"]]
              for c in primary if c["cell_id"] in clean}
    governance, utility, audit, latency, costs, responsiveness, collaboration, overhead = [], [], [], [], [], [], [], []
    for distribution in DISTRIBUTIONS:
        for scenario in ("S0", "S1", "S2", "S3"):
            for baseline in BASELINES:
                rows = [lookup[(baseline, distribution, scenario, value)] for value in SEEDS if (baseline, distribution, scenario, value) in lookup]
                violation = _counts(rows, "oracle_invalid_incorporations", "oracle_invalid_presented")
                rejection = _counts(rows, "oracle_valid_rejections", "oracle_valid_presented")
                governance.append({"baseline_id": baseline, "distribution": distribution, "scenario_id": scenario,
                    "independent_seeds": len(rows), "invalid_incorporations": violation["numerator"],
                    "invalid_presented": violation["denominator"], "invalid_rate": violation["rate"],
                    "valid_rejections": rejection["numerator"], "valid_presented": rejection["denominator"],
                    "incorrect_rejection_rate": rejection["rate"]})
    comparisons = []
    for comparator in ("B2", "B3"):
        for distribution, scenarios, name in [(d, (s,), f"{d}-{s}") for d in DISTRIBUTIONS for s in ("S1", "S2", "S3")] + [(None, ("S1", "S2", "S3"), "primary-seed-pooled")]:
            left, right, used = [], [], []
            for value in SEEDS:
                pairs = [(d, scenario) for d in DISTRIBUTIONS if distribution in (None, d) for scenario in scenarios]
                records = [[lookup.get((baseline, d, scenario, value)) for d, scenario in pairs] for baseline in ("P1", comparator)]
                if any(row is None for group in records for row in group):
                    continue
                rates = [_counts(group, "oracle_invalid_incorporations", "oracle_invalid_presented")["rate"] for group in records]
                if None not in rates:
                    left.append(rates[0]); right.append(rates[1]); used.append(value)
            stats = paired_bootstrap(left, right, resamples=resamples, seed=seed) if len(left) >= 2 else None
            comparisons.append({"table_id": "T-H2", "comparison": "P1-" + comparator, "stratum": name,
                "independent_seeds": len(used), "seeds": used, "statistics": stats,
                "verdict": ("supported" if stats["ci95_upper"] < 0 else "not supported") if can_decide and len(used) == 5 and stats else "inconclusive"})
    h4_ready = can_decide
    for distribution in DISTRIBUTIONS:
        left, right, used = [], [], []
        for value in SEEDS:
            p1, b3 = lookup.get(("P1", distribution, "S0", value)), lookup.get(("B3", distribution, "S0", value))
            if p1 and b3 and p1["metrics"].get("auroc") is not None and b3["metrics"].get("auroc") is not None:
                left.append(p1["metrics"]["auroc"]); right.append(b3["metrics"]["auroc"]); used.append(value)
                if any(row["metrics"].get("evaluation_split") != "test" or row["execution"].get("final_holdout_authorized") is not True for row in (p1, b3)):
                    h4_ready = False
        stats = paired_bootstrap(left, right, resamples=resamples, seed=seed) if len(left) >= 2 else None
        utility.append({"table_id": "T-H4", "distribution": distribution, "comparison": "P1-B3", "scenario_id": "S0",
            "independent_seeds": len(used), "statistics": stats, "noninferiority_margin": -0.02,
            "verdict": "inconclusive"})
    if h4_ready and all(row["independent_seeds"] == 5 for row in utility):
        for row in utility:
            row["verdict"] = "supported" if h4_noninferior(row["statistics"]["one_sided95_lower"]) else "not supported"
    cell_map = {cell["cell_id"]: cell for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells") for cell in plan[family]}
    responsiveness_intervals = []
    for baseline in BASELINES:
        rows = [row for row in attempts if row["cell_id"] in cell_map and cell_map[row["cell_id"]]["baseline_id"] == baseline and cell_map[row["cell_id"]]["variant"] is None]
        audit.append({"baseline_id": baseline, "attempts": len(rows),
            "completeness": _counts(rows, "audit_complete_decisions", "final_decisions"),
            "verification": _counts(rows, "audit_record_sets_verified", "audit_record_sets_tested"),
            "detection": _counts(rows, "tamper_detected", "tamper_attempted"),
            "attempts_missing_audit_counts": sum(not {"audit_complete_decisions", "final_decisions", "audit_record_sets_verified", "audit_record_sets_tested"} <= set(row["metrics"]) for row in rows)})
        for series in sorted(LATENCY_SERIES):
            values = [number for row in rows for number in row["metrics"].get("latency_ms", {}).get(series, [])]
            latency.append({"baseline_id": baseline, "series": series, "operation_samples": len(values),
                "attempts_missing_series": sum(series not in row["metrics"].get("latency_ms", {}) for row in rows),
                "p50_ms": float(np.quantile(values, .50)) if values else None,
                "p95_ms": float(np.quantile(values, .95)) if values else None,
                "p99_ms": float(np.quantile(values, .99)) if values else None,
                "inferential_unit": "descriptive-operations-not-independent-replicates"})
        measured = [row["metrics"]["cost_usd"] for row in rows if row["metrics"].get("cost_usd")]
        costs.append({"baseline_id": baseline, "attempts": len(rows), "attempts_with_costs": len(measured),
            "attempts_missing_costs": len(rows) - len(measured), "observed_total_usd": sum(x["total"] for x in measured),
            "measurement_counts": dict(Counter(x["measurement"] for x in measured)),
            "published_models": sum(row["metrics"].get("published_models", 0) for row in rows),
            "cost_per_published_model_usd": rate(sum(x["total"] for x in measured), sum(row["metrics"].get("published_models", 0) for row in rows)) if len(measured) == len(rows) else None})
        response_summary, response_intervals = responsiveness_tables(rows, baseline)
        responsiveness.append(response_summary)
        responsiveness_intervals.extend(response_intervals)
        collaboration.append({"baseline_id": baseline,
            "accepted_clients": _counts(rows, "accepted_clients", "selected_eligible_clients"),
            "accepted_updates": _counts(rows, "accepted_updates", "unique_presented_updates")})
    for baseline in ("B1", "B2", "P1"):
        for distribution in DISTRIBUTIONS:
            left, right = [], []
            for value in SEEDS:
                pair = [lookup.get((system, distribution, "S0", value)) for system in (baseline, "B3")]
                if all(row and row["metrics"].get("latency_ms", {}).get("round") for row in pair):
                    left.append(float(np.mean(pair[0]["metrics"]["latency_ms"]["round"])))
                    right.append(float(np.mean(pair[1]["metrics"]["latency_ms"]["round"])))
            overhead.append({"baseline_id": baseline, "reference": "B3", "distribution": distribution, "scenario_id": "S0",
                "independent_seeds": len(left), "mean_round_time_ratio": rate(float(np.mean(left)), float(np.mean(right))) if left else None,
                "round_time_difference_ms": paired_bootstrap(left, right, resamples=resamples, seed=seed) if len(left) >= 2 else None})
    all_costs = [row["metrics"]["cost_usd"] for row in attempts if row["metrics"].get("cost_usd")]
    costs.append({"baseline_id": "ALL-ATTEMPTS", "attempts": len(attempts), "attempts_with_costs": len(all_costs),
        "attempts_missing_costs": len(attempts) - len(all_costs), "observed_total_usd": sum(row["total"] for row in all_costs),
        "measurement_counts": dict(Counter(row["measurement"] for row in all_costs)),
        "scope": "includes-failed-aborted-excluded-and-unsafe-ablation-attempts"})
    p1_rows = [row for key, row in lookup.items() if key[0] == "P1" and key[2] in {"S1", "S2", "S3"}]
    violations = _counts(p1_rows, "oracle_invalid_incorporations", "oracle_invalid_presented")
    violating_seeds = {key[3] for key, row in lookup.items() if key[0] == "P1" and row["metrics"]["oracle_invalid_incorporations"] > 0}
    observed_seeds = {key[3] for key in lookup if key[0] == "P1"}
    h1 = {**violations, "independent_seeds": len(observed_seeds), "violating_seed_clusters": len(violating_seeds),
        "zero_violation_seed_probability_upper95": 1 - .05 ** (1 / len(observed_seeds)) if observed_seeds and not violating_seeds else None,
        "verdict": ("supported" if violations["numerator"] == 0 else "not supported") if can_decide and violations["denominator"] else "inconclusive",
        "scope": "registered-primary-suite-only; robustness separately reported"}
    h2_primary = [row for row in comparisons if row["stratum"] == "primary-seed-pooled"]
    h2_verdict = "inconclusive" if any(row["verdict"] == "inconclusive" for row in h2_primary) else ("supported" if all(row["verdict"] == "supported" for row in h2_primary) else "not supported")
    p1_audit = next(row for row in audit if row["baseline_id"] == "P1")
    targeted_complete = all(cell["cell_id"] in clean for cell in plan["targeted_cells"])
    h3_ready = can_decide and targeted_complete and not p1_audit["attempts_missing_audit_counts"] and p1_audit["detection"]["denominator"] > 0
    h3_verdict = "inconclusive"
    if h3_ready:
        h3_verdict = "supported" if all(p1_audit[key]["rate"] == 1 for key in ("completeness", "verification", "detection")) else "not supported"
    coverage = {family: {"planned": len(plan[family]), "clean_successful": sum(cell["cell_id"] in clean for cell in plan[family]),
        "unattempted": sum(cell["cell_id"] not in by_cell for cell in plan[family]),
        "failed_or_ambiguous": sum(cell["cell_id"] in by_cell and cell["cell_id"] not in clean for cell in plan[family])}
        for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells")}
    replications = []
    for cell in plan["replication_cells"]:
        original = lookup.get((cell["baseline_id"], cell["distribution"], cell["scenario_id"], cell["seed"]))
        repeated = clean.get(cell["cell_id"])
        fresh = bool(original and repeated and original["execution"].get("deployment_id") != repeated["execution"].get("deployment_id")
                     and original["execution"].get("namespace") != repeated["execution"].get("namespace")
                     and not set(original["execution"].get("client_task_ids", [])) & set(repeated["execution"].get("client_task_ids", []))
                     and len(repeated["execution"].get("client_task_ids", [])) == 8)
        replications.append({"cell_id": cell["cell_id"], "baseline_id": cell["baseline_id"], "scenario_id": cell["scenario_id"],
                             "distribution": cell["distribution"], "fresh_deployment_metadata_verified": fresh})
    return {"schema_version": "0.1.0", "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts),
        "analysis_configuration_registered": registered_statistics, "plan_status": plan["status"], "primary_matrix_complete": complete,
        "confirmatory_verdict_permitted": can_decide, "attempt_count": len(attempts), "status_counts": dict(Counter(row["status"] for row in attempts)),
        "development_observations": sum(row.get("observation", {}).get("scope") == "development" for row in attempts),
        "independent_seed_target": 5, "crossed_cells_are_not_independent_seeds": True, "coverage": coverage,
        "hypotheses": {"H1": h1, "H2": {"verdict": h2_verdict, "estimand": config["h2_primary_estimand"]},
            "H3": {"verdict": h3_verdict, "audit": p1_audit},
            "H4": {"verdict": "inconclusive" if any(row["verdict"] == "inconclusive" for row in utility) else ("supported" if all(row["verdict"] == "supported" for row in utility) else "not supported"), "margin": -0.02}},
        "tables": {"governance": governance, "paired_governance": comparisons, "stable_utility": utility, "audit": audit,
                   "latency": latency, "cost": costs, "responsiveness": responsiveness, "responsiveness_intervals": responsiveness_intervals, "collaboration": collaboration,
                   "overhead": overhead, "replications": replications},
        "all_attempts": attempts, "all_phases_complete": False,
        "limitations": ["Five seed clusters give limited interval precision; conditional on the frozen dataset and schedule.",
            "Percentile bootstrap is approximate; degenerate observed differences do not prove zero population risk.",
            "Zero invalid-update denominators are undefined and excluded from paired rate estimates with counts retained.",
            "Failed or repeated cells block confirmatory verdicts; all attempts and incurred costs remain reported.",
            "H4 requires authorized frozen-test summaries; validation summaries cannot establish non-inferiority."]}


def write_analysis(report, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    for name, rows in report["tables"].items():
        stream = io.StringIO(newline="")
        keys = sorted({key for row in rows for key in row})
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})
        (output / (name + ".csv")).write_text(stream.getvalue(), encoding="utf-8", newline="")
    claims = [{"RQ": rq, "hypothesis": hypothesis, "component": component, "scenarios": scenarios,
               "plan_digest": report["plan_digest"], "attempts_digest": report["attempts_digest"],
               "verdict": report["hypotheses"][hypothesis]["verdict"], "table_id": table}
              for rq, hypothesis, component, scenarios, table in (("RQ2", "H1", "guarded-publication", "S1-S3", "T-H1"),
                ("RQ3", "H2", "baseline-comparison", "S1-S3", "T-H2"), ("RQ3", "H3", "audit", "S0-S8", "T-H3"),
                ("RQ4", "H4", "stable-utility", "S0", "T-H4"))]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(claims[0]))
    writer.writeheader(); writer.writerows(claims)
    (output / "claim_evidence_matrix.csv").write_text(stream.getvalue(), encoding="utf-8", newline="")
