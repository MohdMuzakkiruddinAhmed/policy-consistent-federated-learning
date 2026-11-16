"""Replay retained evidence using its exact frozen image with network disabled."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def replay(inventory_path, image):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("immutable_local_image_id_required")
    path = Path(inventory_path).resolve()
    inventory = json.loads(path.read_text())
    approved_images = [inventory["image"], *inventory.get("image_history", [])]
    if not any(item.get("reference", "").endswith("@" + image) for item in approved_images):
        raise ValueError("image_not_recorded_for_this_owned_campaign")
    checked = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                             capture_output=True, text=True, check=True)
    if checked.stdout.strip() != image:
        raise ValueError("frozen_local_image_pin_mismatch")
    export_root = Path(inventory["export"].get("export_root", path.parent / "r")).resolve()
    if not export_root.is_relative_to(path.parent):
        raise ValueError("retained_export_outside_owned_inventory")
    sanitized = {key: deepcopy(inventory[key]) for key in
                 ("campaign_id", "account_id", "region", "export", "observed_tasks", "runtime_contract")}
    sanitized["foundation"] = {"bucket_name": inventory["foundation"]["bucket_name"]}
    sanitized["export"]["export_root"] = "/evidence/r"
    code = ("import hashlib,importlib.util,json;from pathlib import Path;"
        "s=importlib.util.spec_from_file_location('historical_adapter','/adapter/scripts/replay.py');"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        "r=m.verify_export('/evidence/inventory.json');"
        "r['verifier_rule_sha256']=hashlib.sha256(Path('/app/policies/rego/pcfl.rego').read_bytes()).hexdigest();"
        "print(json.dumps(r,sort_keys=True))")
    with tempfile.TemporaryDirectory(prefix="pcfl-replay-") as temporary:
        sanitized_path = Path(temporary) / "inventory.json"
        sanitized_path.write_text(json.dumps(sanitized))
        command = ["docker", "run", "--rm", "--read-only", "--network", "none", "--entrypoint", "python",
            "--mount", f"type=bind,source={export_root},target=/evidence/r,readonly",
            "--mount", f"type=bind,source={sanitized_path},target=/evidence/inventory.json,readonly",
            "--mount", f"type=bind,source={ROOT / 'scripts/verify_cloud_campaign.py'},target=/adapter/scripts/replay.py,readonly",
            image, "-c", code]
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if result.returncode:
        raise RuntimeError("frozen_image_replay_failed:" + result.stderr[-1500:])
    report = json.loads(result.stdout)
    report.update(verifier_image_id=image, replay_network="none", mounted_payload="retained models/evidence and sanitized inventory only",
        aws_credentials_forwarded=False, clinical_partitions_mounted=False, holdout_mounted=False,
        host_cache_adapter_sha256=hashlib.sha256((ROOT / "scripts/verify_cloud_campaign.py").read_bytes()).hexdigest())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = replay(args.inventory, args.image)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"successful": report["successful"], "verified_cases": len(report["verified_cases"]),
                      "verifier_image_id": args.image, "network": "none"}))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
