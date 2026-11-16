"""Verify partial-protocol evidence with an explicit external witness-key pin."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pcfl.ablation_verify import assess_case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("case", "witness", "public-key", "expected-public-key-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = assess_case(args.case, witness=json.loads(Path(args.witness).read_text()),
        public_key_pem=Path(args.public_key).read_bytes(), expected_public_key_sha256=args.expected_public_key_sha256)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
