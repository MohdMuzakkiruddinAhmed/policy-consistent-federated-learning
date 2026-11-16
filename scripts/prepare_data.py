"""Prepare and freeze public UCI 296 data; print aggregate metadata only."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.data import download_dataset, prepare_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=296)
    parser.add_argument("--alpha", type=float, default=0.5)
    parser.add_argument("--min-groups", type=int, default=100)
    parser.add_argument("--min-positives", type=int, default=25)
    parser.add_argument("--archive", type=Path, default=ROOT / "data/raw/uci296.zip")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/uci296-v0.1.0-seed296")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data_manifests/dataset.json")
    args = parser.parse_args()
    archive = download_dataset(args.archive)
    result = prepare_dataset(archive, args.output, args.manifest, args.seed, args.alpha,
                             args.min_groups, args.min_positives)
    print(json.dumps({"dataset_id": 296, "archive_sha256": result["source"]["archive_sha256"],
                      "source_counts": result["source_counts"], "splits": result["splits"],
                      "iid_clients": len(result["partitions"]["iid"]["organizations"]),
                      "non_iid_clients": len(result["partitions"]["non_iid"]["organizations"]),
                      "checks": result["checks"]}, indent=2))


if __name__ == "__main__":
    main()
