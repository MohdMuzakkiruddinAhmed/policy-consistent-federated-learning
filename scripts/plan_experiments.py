"""Prepare the complete comparison registry without executing any experiment."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.experiments import build_plan, digest, scientific_sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/experiments.json")
    parser.add_argument("--output", default="experiments/locked_plan.json")
    parser.add_argument("--provenance", help="Public source/image provenance JSON; never credentials")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    training = json.loads((ROOT / config["training_config"]).read_text(encoding="utf-8"))
    data = json.loads((ROOT / config["data_manifest"]).read_text(encoding="utf-8"))
    provenance = json.loads(Path(args.provenance).read_text(encoding="utf-8")) if args.provenance else {}
    if not provenance:
        sources = scientific_sources(ROOT)
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
        provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "image_digests": {},
                      "git_commit": commit.stdout.strip() if commit.returncode == 0 else None}
    plan = build_plan(config, training, data, provenance)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        previous = json.loads(destination.read_text(encoding="utf-8"))
        if previous != plan:
            raise ValueError("existing_locked_plan_differs_use_a_new_versioned_output")
    else:
        destination.write_text(json.dumps(plan, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": plan["status"], "plan_digest": plan["plan_digest"],
        "primary_runs": len(plan["primary_cells"]), "targeted_runs": len(plan["targeted_cells"]),
        "ablation_runs": len(plan["ablation_cells"]), "replication_runs": len(plan["replication_cells"]),
        "confirmatory_execution_enabled": plan["confirmatory_execution_enabled"], "final_holdout_opened": False}))


if __name__ == "__main__":
    main()
