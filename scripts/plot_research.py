"""Reproduce descriptive scientific figures from aggregate attempt records."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


def make_figures(plan, attempts, output, analysis=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, MaxNLocator
    import numpy as np
    matplotlib.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.spines.top": False,
        "axes.spines.right": False, "svg.hashsalt": "pcfl-research-figures-v1", "savefig.dpi": 180})
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cells = {cell["cell_id"]: cell for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells") for cell in plan[family]}
    attempt_counts = Counter(row["cell_id"] for row in attempts)
    rows = [(cells[row["cell_id"]], row) for row in attempts
            if row["cell_id"] in cells and attempt_counts[row["cell_id"]] == 1 and row["status"] == "successful"
            and cells[row["cell_id"]]["family"] == "primary"]
    colors = {"B1": "#6a6a6a", "B2": "#cb7c29", "B3": "#347aa4", "P1": "#27856b"}
    figures = []
    def save(fig, name):
        fig.tight_layout()
        for suffix in ("png", "svg", "pdf"):
            destination = output / (name + "." + suffix)
            fig.savefig(destination, bbox_inches="tight", metadata=({"Date": None} if suffix == "svg" else
                {"CreationDate": None, "ModDate": None} if suffix == "pdf" else {}))
            figures.append({"path": destination.name, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
        plt.close(fig)
    def no_data(axis):
        axis.text(.5, .5, "No eligible observations", transform=axis.transAxes, ha="center", va="center")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.3), sharey=True)
    for axis, distribution in zip(axes, ("iid", "non_iid")):
        available = False
        labelled = set()
        for offset, (baseline, color) in enumerate(colors.items()):
            for x, scenario in enumerate(("S0", "S1", "S2", "S3")):
                rates = [row["metrics"]["oracle_invalid_incorporations"] / row["metrics"]["oracle_invalid_presented"]
                    for cell, row in rows if cell["distribution"] == distribution and cell["baseline_id"] == baseline
                    and cell["scenario_id"] == scenario and row["metrics"].get("oracle_invalid_presented", 0) > 0]
                if rates:
                    available = True
                    axis.scatter(np.full(len(rates), x + (offset - 1.5)*.13), rates, color=color, s=19, alpha=.7,
                                 label=baseline if baseline not in labelled else None)
                    labelled.add(baseline)
        if not available:
            no_data(axis)
        axis.set(xticks=range(4), xticklabels=["S0", "S1", "S2", "S3"], ylim=(-.04, 1.04),
                 title="IID" if distribution == "iid" else "Non-IID", xlabel="Policy scenario")
    axes[0].set_ylabel("Invalid incorporated / invalid presented\n(one point per run; undefined rates omitted)")
    handles, labels = axes[0].get_legend_handles_labels()
    if handles:
        axes[1].legend(handles, labels, frameon=False, loc="best")
    save(fig, "invalid_incorporation_by_scenario")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.3), sharey=True)
    for axis, distribution in zip(axes, ("iid", "non_iid")):
        observed = False
        for offset, (baseline, color) in enumerate(colors.items()):
            for x, scenario in enumerate(("S0", "S1", "S2", "S3")):
                rates = [row["metrics"]["oracle_valid_rejections"] / row["metrics"]["oracle_valid_presented"]
                    for cell, row in rows if cell["distribution"] == distribution and cell["baseline_id"] == baseline
                    and cell["scenario_id"] == scenario and row["metrics"].get("oracle_valid_presented", 0) > 0]
                if rates:
                    observed = True
                    axis.scatter(np.full(len(rates), x + (offset - 1.5)*.13), rates, color=color, s=19, alpha=.7,
                                 label=baseline if x == 0 else None)
        if not observed:
            no_data(axis)
        axis.set(xticks=range(4), xticklabels=["S0", "S1", "S2", "S3"], ylim=(-.04, 1.04),
                 title="IID" if distribution == "iid" else "Non-IID", xlabel="Policy scenario")
    axes[0].set_ylabel("Valid rejected / valid presented\n(one point per run; undefined rates omitted)")
    handles, labels = axes[0].get_legend_handles_labels()
    if handles:
        axes[1].legend(handles, labels, frameon=False)
    save(fig, "incorrect_rejection_by_scenario")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.3))
    for axis, metric in zip(axes, ("opa", "publication")):
        values, labels = [], []
        for baseline in colors:
            series = [value for cell, row in rows if cell["baseline_id"] == baseline
                      for value in row["metrics"].get("latency_ms", {}).get(metric, [])]
            if series:
                values.append(series)
                labels.append(baseline)
        if values:
            axis.boxplot(values, tick_labels=labels, showfliers=False)
            axis.set_yscale("symlog", linthresh=1)
        else:
            no_data(axis)
        axis.set(title="Native policy calls" if metric == "opa" else "Publication attempts", ylabel="Latency (ms)",
                 xlabel="Descriptive observations pooled across runs")
    save(fig, "policy_and_publication_latency")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.3), sharey=True)
    for axis, distribution in zip(axes, ("iid", "non_iid")):
        by_seed = defaultdict(dict)
        for cell, row in rows:
            metrics = row["metrics"]
            if (cell["distribution"] == distribution and cell["scenario_id"] == "S0"
                    and cell["baseline_id"] in {"B3", "P1"} and metrics.get("evaluation_split") == "test"
                    and metrics.get("auroc") is not None):
                by_seed[cell["seed"]][cell["baseline_id"]] = metrics["auroc"]
        eligible = [values for values in by_seed.values() if set(values) == {"B3", "P1"}]
        for values in eligible:
            axis.plot([0, 1], [values["B3"], values["P1"]], "o-", color="#347aa4", alpha=.65, markersize=4)
        if not eligible:
            no_data(axis)
        axis.set(xticks=[0, 1], xticklabels=["B3", "P1"], xlim=(-.3, 1.3), ylim=(0, 1),
                 title=("IID" if distribution == "iid" else "Non-IID") + f"; {len(eligible)} paired seeds",
                 xlabel="Stable scenario; final held-out models")
    axes[0].set_ylabel("Test AUROC")
    save(fig, "stable_test_auroc_pairs")
    fig, axis = plt.subplots(figsize=(5.7, 3.5))
    observed = False
    for baseline, color in colors.items():
        points = [(row["metrics"].get("accepted_updates"), row["metrics"].get("auroc"))
                  for cell, row in rows if cell["baseline_id"] == baseline]
        points = [(x, y) for x, y in points if x is not None and y is not None]
        if points:
            observed = True
            axis.scatter(*zip(*points), color=color, label=baseline, s=22, alpha=.6)
    if observed:
        axis.legend(frameon=False)
    else:
        no_data(axis)
    axis.set(xlabel="Accepted updates across all rounds", ylabel="Final model AUROC",
             title="Observed participation and utility (descriptive)")
    save(fig, "participation_and_utility")
    fig, axis = plt.subplots(figsize=(5.7, 3.5))
    observed = False
    round_count = plan["training_candidate"]["num_rounds"]
    for baseline, color in colors.items():
        points = [(row["metrics"]["revocations"] / round_count,
                   float(np.median(row["metrics"]["latency_ms"]["round"]))) for cell, row in rows
                  if cell["baseline_id"] == baseline and "revocations" in row["metrics"]
                  and row["metrics"].get("latency_ms", {}).get("round")]
        if points:
            observed = True
            axis.scatter(*zip(*points), color=color, label=baseline, s=22, alpha=.6)
    if observed:
        axis.legend(frameon=False)
    else:
        no_data(axis)
    axis.set(xlabel="Committed revocations / configured rounds", ylabel="Median round duration (ms)",
             title="Observed timing and revocation frequency (descriptive)")
    save(fig, "round_time_and_revocation_frequency")
    if analysis is not None:
        expected_attempts = hashlib.sha256(json.dumps(attempts, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if analysis.get("plan_digest") != plan["plan_digest"] or analysis.get("attempts_digest") != expected_attempts:
            raise ValueError("inference_figures_require_matching_registered_analysis")
        fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.5))
        h2 = [row for row in analysis["tables"]["paired_governance"] if row["stratum"] == "primary-seed-pooled" and row.get("statistics")]
        for y, row in enumerate(h2):
            stats = row["statistics"]
            mean = stats["mean_difference"]
            axes[0].errorbar(mean, y, xerr=[[max(0, mean-stats["ci95_lower"])], [max(0, stats["ci95_upper"]-mean)]],
                             fmt="o", color="#27856b", capsize=4)
        if h2:
            axes[0].set_yticks(range(len(h2)), [row["comparison"] + f"; n={row['independent_seeds']}" for row in h2])
        else:
            no_data(axes[0])
        axes[0].axvline(0, color="#666666", linestyle="--", linewidth=1)
        axes[0].set(title="Paired governance effect", xlabel="Rate difference; mean and two-sided 95% CI")
        test_distributions = {distribution for distribution in ("iid", "non_iid")
            if (observed := [row for cell, row in rows if cell["distribution"] == distribution
                and cell["scenario_id"] == "S0" and cell["baseline_id"] in {"B3", "P1"}])
            and all(row["metrics"].get("evaluation_split") == "test"
                    and row["execution"].get("final_holdout_authorized") is True for row in observed)}
        h4 = [row for row in analysis["tables"]["stable_utility"]
              if row.get("statistics") and row["distribution"] in test_distributions]
        for y, row in enumerate(h4):
            stats = row["statistics"]
            mean = stats["mean_difference"]
            axes[1].errorbar(mean, y, xerr=[[max(0, mean-stats["one_sided95_lower"])], [0]],
                             fmt="o", color="#347aa4", capsize=4)
        if h4:
            axes[1].set_yticks(range(len(h4)), [row["distribution"] + f"; n={row['independent_seeds']}" for row in h4])
        else:
            no_data(axes[1])
        axes[1].axvline(-.02, color="#b45442", linestyle="--", linewidth=1, label="Prespecified margin −0.02")
        axes[1].axvline(0, color="#999999", linewidth=.6)
        axes[1].legend(frameon=False, fontsize=8)
        axes[1].set(title="Stable final-holdout AUROC effect", xlabel="P1 − B3; mean and one-sided 95% lower bound")
        axes[1].xaxis.set_major_locator(MaxNLocator(nbins=4))
        axes[1].xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.3f}"))
        save(fig, "paired_effect_confidence_intervals")
    manifest = {"schema_version": "0.1.0", "kind": "reproducible-descriptive-research-figures", "plan_digest": plan["plan_digest"],
        "eligible_primary_successful_attempts": len(rows), "all_attempts_retained": len(attempts),
        "missing_rates_not_imputed": True, "confidence_intervals_source": "separate prespecified seed-level analysis",
        "matplotlib_version": matplotlib.__version__, "files": figures}
    (output / "figures_manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempts", required=True, help="Validated aggregate_attempts.json from the reproduction bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--analysis", help="Matching prespecified analysis.json; optional inference-interval figure")
    args = parser.parse_args()
    plan_path, attempts_path = Path(args.plan), Path(args.attempts)
    manifest = make_figures(json.loads(plan_path.read_text()), json.loads(attempts_path.read_text()), args.output,
        json.loads(Path(args.analysis).read_text()) if args.analysis else None)
    manifest["input_sha256"] = {"plan": hashlib.sha256(plan_path.read_bytes()).hexdigest(), "attempts": hashlib.sha256(attempts_path.read_bytes()).hexdigest()}
    if args.analysis:
        manifest["input_sha256"]["analysis"] = hashlib.sha256(Path(args.analysis).read_bytes()).hexdigest()
    (Path(args.output) / "figures_manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"figures": len(manifest["files"]), "eligible_attempts": manifest["eligible_primary_successful_attempts"]}))


if __name__ == "__main__":
    main()
