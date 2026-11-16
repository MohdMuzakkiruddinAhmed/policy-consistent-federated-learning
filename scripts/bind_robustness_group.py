"""Prepare private role payloads after an operator supplies exact upload versions.

No SDK, AWS mutation, dataset reads or permission changes. The operator must
separately validate/build/deploy the additive adapter after P9 and P10.
"""
import argparse
import json
from pathlib import Path
import sys

STAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE / "src"))
from pcfl.robust_host import bind_group
from prepare_robustness import write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("registry", "group", "runtime-input-template", "private-role-configs", "upload-inventory", "adapter-validation-reports", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_bytes())
    bound = bind_group(read(args.registry), read(args.group), read(args.runtime_input_template), read(args.private_role_configs),
        read(args.upload_inventory), validation_reports=read(args.adapter_validation_reports))
    args.output.mkdir(parents=True, exist_ok=False)
    for role, value in bound.pop("private_role_configs").items():
        write(args.output / "private-role-payloads" / (role + ".json"), value)
    write(args.output / "runtime-input.json", bound.pop("runtime_input"))
    write(args.output / "binding.json", bound)
    print(json.dumps({"inputs_bound": True, "actual_AWS_calls": False, "execution_authorized": False}))


if __name__ == "__main__": main()
