"""Regenerate descriptive/paired analysis from a locked plan and attempt ledger."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.analysis import analyze_registry, write_analysis
from pcfl.experiments import load_attempts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempts", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    report = analyze_registry(plan, load_attempts(args.attempts, plan))
    write_analysis(report, args.output)
    print(json.dumps({"attempt_count": report["attempt_count"], "primary_matrix_complete": report["primary_matrix_complete"],
        "confirmatory_verdict_permitted": report["confirmatory_verdict_permitted"],
        "hypotheses": {key: value["verdict"] for key, value in report["hypotheses"].items()}}))


if __name__ == "__main__":
    main()
