"""Create bound P11/P12 reporting drafts from retained aggregate evidence.

No training, holdout access, AWS calls, gate acceptance or study-completion claim.
All output paths are beneath a caller-selected new/empty directory.
"""
import argparse
from collections import Counter
from copy import deepcopy
import csv
import io
import json
import math
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.analysis import analyze_registry, write_analysis
from pcfl.experiments import (COUNT_METRICS, UTILITY_METRICS, digest, file_digest,
    load_attempts, scientific_binding, validate_gate_report, validate_plan)

from robustness_reporting import collect as collect_robustness, claim_row as robustness_claim

FAMILIES = ("primary", "targeted", "ablation", "replication")
CATEGORIES = {"validation", "fault", "cost", "exploratory", "replication", "reproducibility", "teardown"}
SHA = re.compile(r"[0-9a-f]{64}")
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
RQ1_FAILURE_MODES = {
    "S0": "stable-governance reference",
    "S1": "stale admission after authorization changes",
    "S2": "in-flight revocation during a client lifecycle",
    "S3": "delayed update crossing an authorization transition",
    "S4": "revoke-regrant interval gap hidden by current-state permission",
    "S5": "purpose change or authoritative explicit-expiry transition",
    "S6": "publication race against policy mutation",
    "S7": "duplicate, reordered, or restarted client delivery",
    "S8": "unavailable or tampered authority, storage, or audit dependency",
}


def json_read(path):
    def invalid(value):
        raise ValueError("nonfinite_json_forbidden:" + value)
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=invalid)


def owned_file(root, value):
    root = Path(root).resolve()
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("relative_owned_reporting_evidence_required")
    path = root / relative
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError("owned_regular_reporting_evidence_required")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_reporting_evidence_forbidden")
        if part == root:
            break
    return path


def bound_json(root, reference):
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not isinstance(reference["sha256"], str) or not SHA.fullmatch(reference["sha256"])):
        raise ValueError("strict_reporting_evidence_reference_required")
    path = owned_file(root, reference["path"])
    if file_digest(path) != reference["sha256"]:
        raise ValueError("reporting_evidence_digest_changed")
    return json_read(path)


def accepted_context(plan, root):
    validate_plan(plan)
    if plan["status"] != "accepted_frozen":
        raise ValueError("accepted_frozen_reporting_plan_required")
    provenance = plan["provenance"]
    if digest(provenance["source_files_sha256"]) != provenance["source_sha256"]:
        raise ValueError("reporting_source_manifest_mismatch")
    for name, expected in provenance["source_files_sha256"].items():
        if file_digest(owned_file(root, name)) != expected:
            raise ValueError("frozen_reporting_source_changed")
    candidate_ids = set()
    for gate_id, spec in plan["acceptance"]["gates"].items():
        reference = {key: spec[key] for key in ("path", "sha256")}
        report = bound_json(root, reference)
        candidate = report.get("candidate_plan_digest")
        if not isinstance(candidate, str) or not SHA.fullmatch(candidate):
            raise ValueError("accepted_gate_candidate_binding_required")
        candidate_ids.add(candidate)
        # Gate assessments bind the pre-acceptance digest and the same scientific
        # context. Administrative freeze fields deliberately do not alter science.
        context = {**plan, "plan_digest": candidate}
        validate_gate_report(context, gate_id, report, root)
        for leaf in report["evidence"]:
            bound_json(root, leaf)
    if len(candidate_ids) != 1:
        raise ValueError("accepted_gates_bind_different_candidates")


def verified_figures(path, *, plan_path, aggregate_path, analysis_path, attempts):
    if path is None:
        if aggregate_path is not None:
            raise ValueError("figure_attempts_without_figure_manifest")
        return []
    path = Path(path)
    manifest = json_read(path)
    if aggregate_path is None or digest(json_read(aggregate_path)) != digest(attempts):
        raise ValueError("figure_aggregate_attempts_mismatch")
    expected = {"plan": file_digest(plan_path), "attempts": file_digest(aggregate_path), "analysis": file_digest(analysis_path)}
    if (manifest.get("kind") != "reproducible-descriptive-research-figures"
            or manifest.get("plan_digest") != json_read(plan_path)["plan_digest"]
            or manifest.get("input_sha256") != expected
            or manifest.get("all_attempts_retained") != len(attempts)):
        raise ValueError("figure_input_binding_mismatch")
    figures, names = [], set()
    for reference in manifest.get("files", []):
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                or not isinstance(reference["path"], str) or Path(reference["path"]).name != reference["path"]
                or not re.fullmatch(r"[A-Za-z0-9_]+\.(png|svg|pdf)", reference["path"])
                or not isinstance(reference["sha256"], str) or not SHA.fullmatch(reference["sha256"])
                or reference["path"] in names):
            raise ValueError("strict_unique_figure_reference_required")
        artifact = owned_file(path.parent, reference["path"])
        if file_digest(artifact) != reference["sha256"]:
            raise ValueError("figure_artifact_digest_changed")
        names.add(reference["path"])
        figures.append({**reference, "figure_id": artifact.stem})
    if not figures:
        raise ValueError("nonempty_figure_manifest_required")
    return figures


def retained_evidence(path, plan, root, attempts):
    if path is None:
        return [], []
    index = json_read(path)
    if (set(index) != {"schema_version", "kind", "plan_digest", "reports"}
            or index["schema_version"] != "0.1.0" or index["kind"] != "reporting-evidence-index"
            or index["plan_digest"] != plan["plan_digest"] or not isinstance(index["reports"], dict)):
        raise ValueError("strict_plan_bound_reporting_index_required")
    records, costs, seen_costs = [], [], set()
    raw_bindings = {}
    for row in attempts:
        raw_bindings.setdefault((row["cell_id"], row["evidence"].get("raw_result_sha256")), []).append(row)
    for alias, spec in sorted(index["reports"].items()):
        if (not isinstance(alias, str) or not SAFE.fullmatch(alias) or not isinstance(spec, dict)
                or set(spec) != {"category", "path", "sha256"} or spec["category"] not in CATEGORIES):
            raise ValueError("typed_reporting_evidence_category_required")
        reference = {key: spec[key] for key in ("path", "sha256")}
        report = bound_json(root, reference)
        if not isinstance(report, dict):
            raise ValueError("reporting_evidence_object_required")
        for key in ("plan_digest", "accepted_plan_digest"):
            if key in report and report[key] != plan["plan_digest"]:
                raise ValueError("supplementary_report_plan_binding_mismatch")
        if "scientific_binding" in report and report["scientific_binding"] != scientific_binding(plan):
            raise ValueError("supplementary_report_scientific_binding_mismatch")
        records.append({"alias": alias, **spec, "kind": report.get("kind"),
            "reported_successful": report.get("successful") if type(report.get("successful")) is bool else None,
            "assessment": "retained-bound-evidence; not an independently inferred phase verdict"})
        if report.get("kind") == "retained-run-priced-usage-allocation":
            if spec["category"] != "cost" or report.get("actual_invoice") is not False:
                raise ValueError("inferred_run_cost_scope_required")
            for row in report.get("runs", []):
                identity = (row["cell_id"], row["raw_result"]["sha256"])
                if identity in seen_costs:
                    raise ValueError("duplicate_run_cost_binding")
                seen_costs.add(identity)
                matches = raw_bindings.get(identity, [])
                if not matches:
                    raise ValueError("run_cost_not_bound_to_retained_attempt")
                if len(matches) != 1:
                    raise ValueError("run_cost_ambiguous_retained_attempt")
                attempt = matches[0]
                values, resources = row.get("cost_usd"), row.get("resources")
                def nonnegative(value):
                    return type(value) in (int, float) and math.isfinite(value) and value >= 0
                if values is not None:
                    keys = {"measurement", "direct_compute", "allocated_shared_experimental_allowance",
                            "planning_upper_allocation", "per_published_round_planning_upper"}
                    if (not isinstance(values, dict) or set(values) != keys or values["measurement"] != "inferred-allocation"
                            or any(not nonnegative(values[key]) for key in keys - {"measurement", "per_published_round_planning_upper"})
                            or (values["per_published_round_planning_upper"] is not None and not nonnegative(values["per_published_round_planning_upper"]))
                            or not math.isclose(values["direct_compute"] + values["allocated_shared_experimental_allowance"],
                                                values["planning_upper_allocation"], rel_tol=1e-9, abs_tol=1e-9)):
                        raise ValueError("typed_inferred_run_cost_required")
                if resources is not None and (not isinstance(resources, dict)
                        or set(resources) != {"vcpu_seconds", "memory_gib_seconds"}
                        or any(not nonnegative(value) for value in resources.values())):
                    raise ValueError("reserved_resource_inference_required")
                costs.append({"attempt_id": attempt["attempt_id"], "run_id": attempt["execution"].get("namespace"),
                    "cell_id": row["cell_id"], "raw_result_sha256": identity[1], "report_alias": alias,
                    "report_sha256": spec["sha256"], "source_allocation_scope": report.get("scope", report.get("allocation_scope")),
                    "known_retained_applications_omitted": deepcopy(report.get("known_retained_applications_omitted")),
                    "timing_status": row.get("timing_status"), "cost_usd": deepcopy(row.get("cost_usd")),
                    "resources": deepcopy(row.get("resources")), "actual_invoice": False,
                    "data_kind": attempt["metrics"].get("data_kind"),
                    "source_report_successful": report.get("successful"),
                    "resource_coverage_complete": row.get("resource_coverage_complete", report.get("task_window_coverage_complete")),
                    "all_known_applications_supplied": report.get("all_known_applications_supplied"),
                    "allocation_status": "complete-supplied-scope" if report.get("successful") is True
                        and report.get("task_window_coverage_complete") is True and row.get("timing_status") == "observed"
                        and row.get("resource_coverage_complete", True) is True
                        else "pending-or-partial-supplied-scope",
                    "resource_measurement": "UTC reserved-vCPU/GiB overlap inference; CPU utilization unmeasured",
                    "shared_cost_scope": "experimental overhead planning allocation, not per-run invoice"})
    return records, costs


def csv_write(path, rows, *, fields=None):
    fields = fields or sorted({key for row in rows for key in row}) or ["status"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, allow_nan=False) if isinstance(value, (dict, list))
                         else value for key, value in row.items()})
    Path(path).write_text(stream.getvalue(), encoding="utf-8", newline="")


def json_write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def reporting_tables(plan, attempts, analysis, figures, evidence):
    cells = {cell["cell_id"]: cell for family in FAMILIES for cell in plan[family + "_cells"]}
    frequencies = Counter(row["cell_id"] for row in attempts)
    clean = {row["attempt_id"] for row in attempts if frequencies[row["cell_id"]] == 1 and row["status"] == "successful"}
    summaries = []
    for row in attempts:
        cell = cells.get(row["cell_id"], {})
        summaries.append({"attempt_id": row["attempt_id"], "run_id": row["execution"].get("namespace"),
            "cell_id": row["cell_id"], "family": cell.get("family", "development"),
            "baseline_id": cell.get("baseline_id", row.get("observation", {}).get("baseline_id")),
            "variant": cell.get("variant"), "distribution": cell.get("distribution"), "scenario_id": cell.get("scenario_id"),
            "seed": cell.get("seed"), "status": row["status"], "reason_code": row["reason_code"],
            "eligible_clean_cell": row["attempt_id"] in clean, "evaluation_split": row["metrics"].get("evaluation_split"),
            "eligible_clinical_cell": row["attempt_id"] in clean and row["metrics"].get("data_kind") == "clinical"
                and row["execution"].get("eight_separate_fargate_clients") is True
                and len(set(row["execution"].get("client_task_ids", []))) == 8,
            "final_holdout_authorized": row["execution"].get("final_holdout_authorized") is True,
            "data_kind": row["metrics"].get("data_kind"), "metrics": deepcopy(row["metrics"]),
            "evidence_sha256": deepcopy(row["evidence"]), "exclusion_reasons": row.get("observation", {}).get("exclusion_reasons", [])})
    figure_ids = {item["figure_id"] for item in figures}
    claims = []
    def add(rq, hypothesis, component, selected, statistical, tables, wanted_figures, categories, *, verdict=None, seeds=None, scenarios=None):
        eligible = [row for row in selected if row["eligible_clean_cell"] and (seeds is None or row["seed"] in seeds)]
        keys = ("oracle_invalid_presented", "oracle_invalid_incorporations", "oracle_valid_presented", "oracle_valid_rejections",
                "final_decisions", "audit_complete_decisions", "tamper_attempted", "tamper_detected")
        counts = {key: sum(row["metrics"][key] for row in eligible)
                  if eligible and all(key in row["metrics"] for row in eligible) else None for key in keys}
        refs = [item["alias"] for item in evidence if item["category"] in categories]
        stats = statistical.get("statistics") if isinstance(statistical, dict) else None
        clinical = bool(eligible) and all(row["eligible_clinical_cell"] for row in eligible)
        clinical = clinical and (hypothesis != "H4" or all(row["evaluation_split"] == "test" and row["final_holdout_authorized"] for row in eligible))
        claim_verdict = verdict or (analysis["hypotheses"][hypothesis]["verdict"] if hypothesis else "pending-interpretation")
        claims.append({"RQ": rq, "hypothesis": hypothesis, "component": component,
            "scenarios": scenarios if scenarios is not None else sorted({row["scenario_id"] for row in selected if row["scenario_id"]}),
            "plan_digest": plan["plan_digest"], "attempts_digest": analysis["attempts_digest"],
            "retained_attempt_ids": [row["attempt_id"] for row in selected],
            "eligible_attempt_ids": [row["attempt_id"] for row in eligible],
            "run_ids": [row["run_id"] for row in eligible if row["run_id"] is not None],
            "retained_run_ids": [row["run_id"] for row in selected if row["run_id"] is not None],
            "statistical_seed_ids": seeds,
            "not_used_in_statistical_sample_attempt_ids": [row["attempt_id"] for row in selected
                if row["eligible_clean_cell"] and row not in eligible],
            "missing_run_id_attempts": [row["attempt_id"] for row in eligible if row["run_id"] is None],
            "failed_or_ambiguous_attempt_ids": [row["attempt_id"] for row in selected if not row["eligible_clean_cell"]],
            "oracle_outcomes": counts, "statistical_result": statistical,
            "data_kind_counts": dict(Counter(row["data_kind"] or "unreported" for row in selected)),
            "clinical_eligible_attempt_ids": [row["attempt_id"] for row in eligible if row["eligible_clinical_cell"]],
            "clinical_confirmatory_claim_permitted": bool(hypothesis and analysis["confirmatory_verdict_permitted"]
                and clinical and claim_verdict in {"supported", "not supported"}),
            "counts_scope": "eligible retained clean attempts; data kinds explicit; synthetic observations are not clinical evidence",
            "effect_estimate": stats.get("mean_difference") if stats else None,
            "confidence_interval_95": {"two_sided_lower": stats.get("ci95_lower"), "two_sided_upper": stats.get("ci95_upper"),
                "one_sided_lower": stats.get("one_sided95_lower"), "method": stats.get("method"),
                "independent_seeds": stats.get("independent_seeds")} if stats else None,
            "verdict": claim_verdict,
            "table_ids": tables, "figure_ids": sorted(figure_ids & set(wanted_figures)),
            "pending_figure_ids": sorted(set(wanted_figures) - figure_ids), "evidence_aliases": refs,
            "inference_scope": "registered seed-level analysis only; supplements descriptive; no universal proof"})
    primary = lambda row: row["family"] == "primary"
    add("RQ1", None, "explicit-lifecycle-protocol-and-assumptions", summaries,
        {"effect": None, "confidence_interval": None, "status": "formal/specification evidence requires scoped interpretation"},
        ["T-RQ1-PROTOCOL"], [], {"validation"})
    for scenario, failure in RQ1_FAILURE_MODES.items():
        add("RQ1", None, "temporal-failure-mode:" + failure, [row for row in summaries if row["scenario_id"] == scenario],
            {"effect": None, "confidence_interval": None, "status": "retained trace evidence; no universal proof"},
            ["T-RQ1-PROTOCOL"], [], {"validation", "fault"}, scenarios=[scenario])
    add("RQ2", "H1", "guarded-publication", [row for row in summaries if primary(row) and row["baseline_id"] == "P1" and row["scenario_id"] in {"S1", "S2", "S3"}],
        analysis["hypotheses"]["H1"], ["T-H1", "governance"], ["invalid_incorporation_by_scenario"], {"validation", "fault"})
    for row in analysis["tables"]["paired_governance"]:
        selected = [item for item in summaries if primary(item) and item["baseline_id"] in {"P1", row["comparison"].split("-")[1]}
            and item["scenario_id"] in {"S1", "S2", "S3"} and (row["stratum"] == "primary-seed-pooled" or row["stratum"] == item["distribution"] + "-" + item["scenario_id"])]
        add("RQ3", "H2", "paired-baseline-comparison:" + row["comparison"] + ":" + row["stratum"], selected, row,
            ["T-H2", "paired_governance"], ["paired_effect_confidence_intervals"], {"validation"}, verdict=row["verdict"], seeds=row["seeds"])
    add("RQ3", "H3", "audit-completeness-and-tamper-evidence", [row for row in summaries if row["baseline_id"] == "P1" and row["variant"] is None],
        analysis["hypotheses"]["H3"], ["T-H3", "audit"], [], {"validation", "fault"})
    for row in analysis["tables"]["stable_utility"]:
        paired = [item for item in summaries if primary(item) and item["eligible_clean_cell"] and item["scenario_id"] == "S0"
                  and item["baseline_id"] in {"P1", "B3"} and item["distribution"] == row["distribution"]
                  and item["metrics"].get("auroc") is not None]
        used_seeds = sorted(seed for seed in {item["seed"] for item in paired}
                            if {item["baseline_id"] for item in paired if item["seed"] == seed} == {"P1", "B3"})
        add("RQ4", "H4", "stable-utility:" + row["distribution"], [item for item in summaries if primary(item)
            and item["scenario_id"] == "S0" and item["baseline_id"] in {"P1", "B3"} and item["distribution"] == row["distribution"]], row,
            ["T-H4", "stable_utility"], ["stable_test_auroc_pairs", "paired_effect_confidence_intervals"], {"cost"}, verdict=row["verdict"], seeds=used_seeds)
    add("RQ4", None, "exploratory-tradeoffs-and-failure-boundaries", [row for row in summaries if row["family"] != "primary"],
        {"effect": None, "confidence_interval": None, "status": "descriptive only; no confirmatory or n>1 claim"},
        ["targeted_attempts", "ablation_attempts", "replication_attempts", "exploratory_evidence"],
        ["participation_and_utility", "round_time_and_revocation_frequency"], {"exploratory", "fault", "replication", "cost"})
    return summaries, claims


def family_descriptives(summaries):
    """All-status, data-kind-separated summaries; no extra inferential samples."""
    groups = {}
    fields = ("family", "baseline_id", "variant", "distribution", "scenario_id", "data_kind", "evaluation_split")
    for row in summaries:
        groups.setdefault(tuple(row[key] for key in fields), []).append(row)
    result = []
    for group, rows in sorted(groups.items(), key=lambda item: json.dumps(item[0])):
        counts, utility = {}, {}
        for metric in sorted(COUNT_METRICS):
            values = [row["metrics"][metric] for row in rows if metric in row["metrics"]]
            counts[metric] = {"sum": sum(values) if values else None, "observed_attempts": len(values),
                              "missing_attempts": len(rows) - len(values)}
        for metric in sorted(UTILITY_METRICS - {"evaluation_split", "data_kind"}):
            values = [row["metrics"][metric] for row in rows if type(row["metrics"].get(metric)) in (int, float)]
            utility[metric] = {"mean": sum(values) / len(values) if values else None,
                "minimum": min(values) if values else None, "maximum": max(values) if values else None,
                "observed_attempts": len(values), "missing_attempts": len(rows) - len(values)}
        result.append({**dict(zip(fields, group)), "retained_attempts": len(rows),
            "status_counts": dict(Counter(row["status"] for row in rows)),
            "clean_successful_attempts": sum(row["eligible_clean_cell"] for row in rows),
            "clinical_eligible_attempts": sum(row["eligible_clinical_cell"] for row in rows),
            "distinct_registered_seeds": len({row["seed"] for row in rows if row["seed"] is not None}),
            "attempt_ids": [row["attempt_id"] for row in rows], "run_ids": [row["run_id"] for row in rows],
            "counts": counts, "utility_descriptives": utility, "effect": None, "confidence_interval": None,
            "inference_scope": "all retained attempts grouped descriptively; correlated crossed cells are not independent seeds"})
    return result


def resolve_claim_links(claims, figures, analysis):
    tables = {name: "tables/" + name + ".csv" for name in analysis["tables"]}
    tables.update({"T-H1": "tables/governance.csv", "T-H2": "tables/paired_governance.csv", "T-H3": "tables/audit.csv",
        "T-H4": "tables/stable_utility.csv", "T-RQ1-PROTOCOL": "tables/rq1_protocol_evidence.csv",
        "exploratory_evidence": "supplements/exploratory_evidence.json"})
    tables.update({family + "_attempts": "supplements/" + family + "_attempts.csv" for family in FAMILIES})
    for claim in claims:
        claim["table_links"] = [{"table_id": name, "path": tables[name]} for name in claim["table_ids"]]
        claim["figure_links"] = [{"figure_id": row["figure_id"], "path": "figures/" + row["path"], "sha256": row["sha256"]}
                                 for row in figures if row["figure_id"] in claim["figure_ids"]]


def generate(plan_path, ledger_path, analysis_path, output, *, evidence_root=ROOT,
             figure_manifest=None, figure_attempts=None, evidence_index=None):
    root, output = Path(evidence_root).resolve(), Path(output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("reporting_output_must_be_new_or_empty")
    if output.is_symlink() or (hasattr(output, "is_junction") and output.is_junction()):
        raise ValueError("linked_reporting_output_forbidden")
    plan = json_read(plan_path)
    accepted_context(plan, root)
    if not Path(ledger_path).is_file():
        raise ValueError("retained_attempt_ledger_required")
    attempts = load_attempts(ledger_path, plan)
    analysis = json_read(analysis_path)
    reproduced = analyze_registry(plan, attempts)
    if digest(analysis) != digest(reproduced):
        raise ValueError("reporting_analysis_not_exact_reproduction")
    figures = verified_figures(figure_manifest, plan_path=plan_path, aggregate_path=figure_attempts,
        analysis_path=analysis_path, attempts=attempts)
    evidence, costs = retained_evidence(evidence_index, plan, root, attempts)
    exploratory = collect_robustness(evidence, root=root, plan_digest=plan["plan_digest"])
    summaries, claims = reporting_tables(plan, attempts, analysis, figures, evidence)
    descriptives = family_descriptives(summaries)
    resolve_claim_links(claims, figures, analysis)
    if exploratory["reports"]:
        claims.append(robustness_claim(exploratory, plan_digest=plan["plan_digest"], attempts_digest=analysis["attempts_digest"]))
    protocol_rows = [{"scenario_id": scenario, "registered_failure_mode": failure,
        "retained_attempt_ids": [row["attempt_id"] for row in summaries if row["scenario_id"] == scenario],
        "retained_run_ids": [row["run_id"] for row in summaries if row["scenario_id"] == scenario],
        "status_counts": dict(Counter(row["status"] for row in summaries if row["scenario_id"] == scenario)),
        "data_kind_counts": dict(Counter(row["data_kind"] or "unreported" for row in summaries if row["scenario_id"] == scenario)),
        "context_validation_aliases": [row["alias"] for row in evidence if row["category"] in {"validation", "fault"}],
        "assessment": "trace catalogue; contextual references require interpretation; finite tests do not prove a universal invariant"}
        for scenario, failure in RQ1_FAILURE_MODES.items()]
    present_categories = {row["category"] for row in evidence}
    pending = ["bound-" + name + "-evidence" for name in sorted(CATEGORIES - present_categories)]
    pending += ["report-not-successful:" + row["alias"] for row in evidence if row["reported_successful"] is False]
    pending += [family + "-unaccounted-cells" for family, values in analysis["coverage"].items()
                if values["unattempted"] or values["failed_or_ambiguous"]]
    if not figures:
        pending.append("regenerated-bound-figures")
    elif any(row["pending_figure_ids"] for row in claims):
        pending.append("claim-linked-figures-incomplete")
    if "exploratory" in present_categories and not exploratory["reports"]:
        pending.append("exploratory-normalized-summaries-and-interpretation")
    if exploratory["reports"] and not exploratory["complete_verified_case_coverage"]:
        pending.append("exploratory-cases-unattempted-failed-or-ambiguous")
    if any(row["allocation_status"] != "complete-supplied-scope" for row in costs):
        pending.append("run-cost-partial-or-pending-source-coverage")
    costed = {row["attempt_id"] for row in costs if row["cost_usd"] is not None}
    if len(costed) != len(attempts):
        pending.append("run-cost-unaccounted-attempts")
    pending += [name + "-inconclusive" for name, value in analysis["hypotheses"].items() if value["verdict"] == "inconclusive"]
    pending += ["final-manuscript-interpretation", "independent-final-phase-assessment", "release-reproduction-and-retention-review"]
    output.mkdir(parents=True, exist_ok=True)
    for name in ("reports", "tables", "supplements"):
        (output / name).mkdir()
    write_analysis(analysis, output / "tables")
    csv_write(output / "tables/family_descriptives.csv", descriptives)
    json_write(output / "tables/family_descriptives.json", {"scope": "all retained attempts; data-kind-separated descriptive groups",
        "additional_independent_replicates_claimed": False, "rows": descriptives})
    csv_write(output / "tables/rq1_protocol_evidence.csv", protocol_rows)
    json_write(output / "tables/rq1_protocol_evidence.json", protocol_rows)
    if figures:
        (output / "figures").mkdir()
        for row in figures:
            target = output / "figures" / row["path"]
            shutil.copyfile(owned_file(Path(figure_manifest).parent, row["path"]), target)
            if file_digest(target) != row["sha256"]:
                raise ValueError("figure_changed_during_reporting_copy")
    csv_write(output / "claim_evidence_matrix.csv", claims)
    json_write(output / "claim_evidence_matrix.json", claims)
    for family in (*FAMILIES, "development"):
        rows = [row for row in summaries if row["family"] == family]
        csv_write(output / "supplements" / (family + "_attempts.csv"), rows,
            fields=list(summaries[0]) if summaries else ["attempt_id", "status", "metrics"])
        json_write(output / "supplements" / (family + "_attempts.json"), {"scope": "all retained attempts; descriptive only", "rows": rows})
    json_write(output / "supplements/exploratory_evidence.json", {"status": exploratory["status"],
        "references": [row for row in evidence if row["category"] == "exploratory"],
        "normalized_summary_bindings": exploratory["reports"], "verified_clinical_attempts": exploratory["verified_clinical_attempts"],
        "independent_seed_count": exploratory["independent_seed_count"], "confirmatory": False,
        "effect": None, "confidence_interval": None})
    for name, key, csv_key in (("exploratory_cases", "cases", "case_csv_rows"),
        ("exploratory_attempts", "attempts", "attempt_csv_rows"),
        ("exploratory_factor_levels", "factor_csv_rows", "factor_csv_rows"),
        ("exploratory_preparation_failures", "excluded_preparation_attempts", "excluded_preparation_attempts")):
        json_write(output / "supplements" / (name + ".json"), {"scope": "separate validation-only n=1 exploratory descriptives",
            "confirmatory": False, "effect": None, "confidence_interval": None, "rows": exploratory[key]})
        csv_write(output / "supplements" / (name + ".csv"), exploratory[csv_key],
            fields=None if exploratory[csv_key] else ["case_id", "status", "metrics", "effect", "confidence_interval"])
    json_write(output / "supplements/run_cost_allocations.json", {"scope": "inferred priced reserved usage and shared experimental allowance",
        "actual_invoice": False, "cpu_utilization_measured": False, "complete_seven_component_run_cost_ledger": False,
        "attempts_missing_allocation": [row["attempt_id"] for row in attempts if row["attempt_id"] not in costed], "runs": costs})
    csv_write(output / "supplements/run_cost_allocations.csv", costs,
        fields=list(costs[0]) if costs else ["attempt_id", "cell_id", "cost_usd", "resources", "actual_invoice"])
    json_write(output / "evidence_references.json", evidence)
    coverage = "\n".join(f"| {name} | {row['planned']} | {row['clean_successful']} | {row['unattempted']} | {row['failed_or_ambiguous']} |"
        for name, row in analysis["coverage"].items())
    hypotheses = "\n".join(f"| {name} | {value['verdict']} |" for name, value in analysis["hypotheses"].items())
    preamble = (f"Bound reporting draft for plan `{plan['plan_digest']}` and attempts `{analysis['attempts_digest']}`. "
        "This generator does not accept gates, authorize holdout access, or declare the study complete.\n\n")
    contents = {
        "results.md": preamble + f"Retained attempts: {len(attempts)}. Status counts: `{json.dumps(analysis['status_counts'], sort_keys=True)}`.\n\n"
            f"Data-kind counts: `{json.dumps(dict(Counter(row['data_kind'] or 'unreported' for row in summaries)), sort_keys=True)}`. "
            f"Clinical confirmatory verdicts permitted by the exact analysis: **{str(analysis['confirmatory_verdict_permitted']).lower()}**. "
            "Synthetic mechanism observations remain synthetic; they do not establish clinical utility or deployment effectiveness.\n\n"
            "| Family | Planned | Clean successful | Unattempted | Failed/ambiguous |\n|---|---:|---:|---:|---:|\n" + coverage +
            "\n\n| Hypothesis | Registered verdict |\n|---|---|\n" + hypotheses +
            "\n\nEffects, uncertainty and run-level bindings are retained in the [claim matrix](../claim_evidence_matrix.csv), "
            "[family descriptives](../tables/family_descriptives.csv), and [RQ1 trace catalogue](../tables/rq1_protocol_evidence.csv). "
            "Zero opportunity denominators remain undefined; failed/repeated cells are retained. "
            "Targeted, ablation and replication attempts are separate descriptive supplements.\n",
        "limitations.md": preamble + "\n".join("- " + value for value in analysis["limitations"]) +
            "\n- Single-account fictional organizations do not establish cross-institution deployment validity.\n"
            "- Safety depends on the stated identity, trusted authority, storage and independent-oracle assumptions.\n"
            "- Abstract-only related-work access cannot establish absence of mechanisms or a firstness claim.\n"
            "- Sensitivity with one development seed is descriptive; failed constrained preparation remains a negative finding.\n"
            "- Coordinator response intervals are bounded observations, not exact revocation times or a substitute for safety counts.\n"
            "- UTC-priced resource allocation estimates reserved vCPU/GiB use; shared overhead is a planning allocation, not an invoice or CPU-utilization measurement.\n",
        "design_principles.md": preamble +
            "| Principle | Evidence to interpret | Cost/limit |\n|---|---|---|\n"
            "| Preserve interval history | H1/S4 and Abl-4 | Full-history policy payload and query duration |\n"
            "| Guard atomic publication | S6 and unsafe Abl-2 | Transaction/retry/publication overhead |\n"
            "| Bind authenticated identities | Validation references and task bindings | Single-account simulated organizations |\n"
            "| Fail closed on dependency failure | S8 and fault references | Lost availability/empty rounds |\n"
            "| Anchor complete audit evidence | H3 and Abl-3 | Durable audit/storage overhead; detectability is not prevention |\n\n"
            "These are scoped design obligations. Their measured support, counterexamples and missing evidence remain in the claim matrix and supplements.\n",
        "validation_findings.md": preamble +
            "Retained fault/validation references are in `../evidence_references.json`. A supplied report's success flag is recorded as its claim, "
            "not promoted to a phase verdict. Clinical, synthetic mechanism, emulator and native-service scopes require separate interpretation. "
            "Unsafe ablations, excluded/failed attempts and bounded data-preparation failures must remain visible.\n\n"
            f"Bound validation/fault references: {sum(row['category'] in {'validation', 'fault'} for row in evidence)}. "
            "Absent evidence is pending, never a zero failure rate.\n",
        "final_validation.md": preamble +
            "Reporting input checks passed: accepted-plan/gate references, frozen source digests, ledger chain, exact registered analysis reproduction, "
            "and any supplied figure/evidence bindings. These checks validate reporting inputs, not all P0-P12 gates.\n\n"
            "All phases complete: **false**. Final study assessment remains the separate `finalize_research.py` workflow.\n\nPending:\n\n" +
            "\n".join("- " + item for item in pending) + "\n",
    }
    for name, body in contents.items():
        (output / "reports" / name).write_text(body, encoding="utf-8")
    inputs = {name: {"name": Path(path).name, "sha256": file_digest(path)} for name, path in
              (("accepted_plan", plan_path), ("attempt_ledger", ledger_path), ("analysis", analysis_path))}
    for name, path in (("figure_manifest", figure_manifest), ("figure_attempts", figure_attempts), ("evidence_index", evidence_index)):
        if path is not None:
            inputs[name] = {"name": Path(path).name, "sha256": file_digest(path)}
    manifest = {"schema_version": "0.1.0", "kind": "bound-final-reporting-drafts", "successful": True,
        "assessment_scope": "reporting-input-integrity-only", "all_phases_complete": False,
        "plan_digest": plan["plan_digest"], "attempts_digest": analysis["attempts_digest"],
        "scientific_binding": scientific_binding(plan), "accepted_gate_references": deepcopy(plan["acceptance"]["gates"]),
        "ledger_chain": {"records": len(attempts), "head_event_hash": json.loads(Path(ledger_path).read_text().splitlines()[-1])["event_hash"]
            if attempts else "0" * 64},
        "inputs": inputs, "source_sha256": file_digest(__file__), "figures": figures,
        "data_kind_counts": dict(Counter(row["data_kind"] or "unreported" for row in summaries)),
        "clinical_confirmatory_verdict_permitted": analysis["confirmatory_verdict_permitted"],
        "exploratory_summary_bindings": exploratory["reports"], "exploratory_attempt_count": len(exploratory["attempts"]),
        "robustness_reporting_source_sha256": file_digest(collect_robustness.__code__.co_filename),
        "attempt_count": len(attempts), "pending": pending, "clinical_records_read": False,
        "aws_calls": False, "holdout_authorization_issued": False,
        "files_sha256": {path.relative_to(output).as_posix(): file_digest(path) for path in sorted(output.rglob("*")) if path.is_file()}}
    json_write(output / "reporting_manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "attempts", "analysis", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--evidence-root", type=Path, default=ROOT)
    parser.add_argument("--figure-manifest", type=Path)
    parser.add_argument("--figure-attempts", type=Path, help="Exact aggregate_attempts.json used by plot_research.py")
    parser.add_argument("--evidence-index", type=Path)
    args = parser.parse_args()
    report = generate(args.plan, args.attempts, args.analysis, args.output, evidence_root=args.evidence_root,
        figure_manifest=args.figure_manifest, figure_attempts=args.figure_attempts, evidence_index=args.evidence_index)
    print(json.dumps({key: report[key] for key in ("successful", "assessment_scope", "attempt_count", "all_phases_complete")}))


if __name__ == "__main__":
    main()
