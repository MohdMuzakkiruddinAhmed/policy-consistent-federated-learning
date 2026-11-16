"""Execute one authorized stage, retaining exact evidence even when a case fails."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]


def verify_private_deadline(public_campaign, private_coordinator):
    deadline = public_campaign.get("task_deadline_seconds")
    if (type(deadline) is not int or not 60 <= deadline <= 86400
            or private_coordinator.get("task_deadline_seconds") != deadline):
        raise ValueError("private_supervisor_deadline_must_match_reviewed_public_campaign")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--stage", required=True, choices=("connectivity", "training-pilot", "safety-pilot", "primary", "targeted", "ablation", "replication"))
    parser.add_argument("--distribution", choices=("iid", "non_iid"), default="iid")
    parser.add_argument("--attempt", default="1")
    parser.add_argument("--image")
    parser.add_argument("--plan")
    parser.add_argument("--final-test", action="store_true")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print(json.dumps({"aws_calls": False, "stage": args.stage, "distribution": args.distribution,
                          "apply_required": True, "final_holdout_requested": args.final_test}))
        return 0
    if args.final_test and (not args.plan or args.stage not in {"primary", "replication"}):
        raise ValueError("final_holdout_only_for_explicit_accepted_main_or_replication_stage")
    request_path = Path(args.request).resolve()
    directory = request_path.parent
    logs = directory / "host-logs" / (args.stage + "-" + args.distribution + "-" + uuid.uuid4().hex[:8])
    logs.mkdir(parents=True, exist_ok=False)
    def call(label, script, extra=(), *, required=True):
        command = [sys.executable, str(ROOT / script), *map(str, extra)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        (logs / (label + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8")
        print(json.dumps({"stage_step": label, "exit_code": result.returncode}), flush=True)
        if required and result.returncode:
            raise RuntimeError("cloud_stage_step_failed:" + label + ":" + str(logs / (label + ".log")))
        return result.returncode
    if args.image:
        request = json.loads(request_path.read_text())
        request["local_image_tag"] = args.image
        request_path.write_text(json.dumps(request, sort_keys=True, indent=2) + "\n")
    call("bind-reports", "scripts/prepare_campaign.py", ["refresh-reports", "--request", request_path])
    prepare = ["runtime", "--request", request_path, "--stage", args.stage, "--distribution", args.distribution, "--attempt", args.attempt]
    if args.plan:
        prepare += ["--plan", args.plan]
    call("prepare-public", "scripts/prepare_campaign.py", prepare)
    request = json.loads(request_path.read_text())
    application = request["application_campaign_id"]
    app_hash = hashlib.sha256(application.encode()).hexdigest()[:12]
    authorization_path = None
    if args.final_test:
        authorization_path = directory / (app_hash + "-holdout-authorization.json")
        campaign = directory / (app_hash + "-campaign.json")
        call("authorize-final-holdout", "scripts/authorize_holdout.py", ["--plan", args.plan, "--campaign", campaign,
             "--output", authorization_path, "--apply"])
        prepare += ["--holdout-authorization", authorization_path]
        call("prepare-public-authorized", "scripts/prepare_campaign.py", prepare)
    aws = ["--request", request_path, "--apply"]
    call("publish-inputs", "scripts/aws_campaign.py", [*aws, "--stage", "publish-inputs"])
    call("prepare-private", "scripts/prepare_campaign.py", prepare)
    prepared = json.loads(request_path.read_text())
    payloads = [row["payload_path"] for row in prepared["secrets"] if row["logical_name"] == "coordinator-config"]
    if len(payloads) != 1:
        raise ValueError("one_private_coordinator_payload_required")
    verify_private_deadline(json.loads((directory / (app_hash + "-campaign.json")).read_text()),
                            json.loads(Path(payloads[0]).read_text()))
    call("register-runtime", "scripts/aws_campaign.py", [*aws, "--stage", "register-runtime"])
    if args.probe:
        call("access-probes", "scripts/aws_campaign.py", [*aws, "--stage", "probe"])
    run_exit = call("run", "scripts/aws_campaign.py", [*aws, "--stage", "run"], required=False)
    call("collect", "scripts/aws_campaign.py", [*aws, "--stage", "collect"])
    inventory_path = directory / "inventory.json"
    call("operator-witness", "scripts/anchor_evidence.py", ["--inventory", inventory_path, "--apply"])
    report_dir = ROOT / "reports/cloud-stages" / app_hash
    report_dir.mkdir(parents=True, exist_ok=True)
    placement_exit = call("placement", "scripts/validate_cloud_placement.py", ["--inventory", inventory_path,
        "--refresh-image-relations", "--output", report_dir / "placement.json"], required=False)
    inventory = json.loads(inventory_path.read_text())
    snapshot = directory / (app_hash + "-inventory.json")
    if snapshot.exists():
        raise ValueError("existing_stage_snapshot_use_new_explicit_attempt")
    snapshot.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    from cryptography.hazmat.primitives import serialization
    public_path = directory / "operator-witness-public.pem"
    public = serialization.load_pem_public_key(public_path.read_bytes())
    pin = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    verify = ["--inventory", snapshot, "--output", report_dir / "verification.json", "--witness-public-key", public_path,
              "--witness-public-key-sha256", pin]
    if authorization_path:
        verify += ["--accepted-plan", args.plan, "--holdout-authorization", authorization_path]
    verify_exit = call("independent-verification", "scripts/verify_cloud_campaign.py", verify, required=False)
    summary = {"application_campaign_id": application, "inventory": str(snapshot), "reports": str(report_dir),
        "runtime_exit_code": run_exit, "placement_exit_code": placement_exit, "verification_exit_code": verify_exit,
        "successful": run_exit == placement_exit == verify_exit == 0, "raw_failures_retained": True,
        "protected_public_key_sha256": pin, "final_holdout_authorization": str(authorization_path) if authorization_path else None}
    (report_dir / "stage_summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
