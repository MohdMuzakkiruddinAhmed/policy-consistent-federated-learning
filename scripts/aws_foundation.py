"""Plan/apply a bounded foundation and tear down only its recorded resources.

Credentials stay in the AWS credential chain. Local plans, state and detailed
evidence are ignored by Git. This script never starts compute resources.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from aws_preflight import check_identity, find_aws

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra/terraform"
EVIDENCE = ROOT / "results/aws/foundation"
ALLOWED_TYPES = {"terraform_data", "aws_s3_bucket", "aws_s3_bucket_public_access_block",
                 "aws_s3_bucket_ownership_controls", "aws_s3_bucket_versioning",
                 "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy",
                 "aws_s3_bucket_lifecycle_configuration", "aws_dynamodb_table", "aws_ecr_repository",
                 "aws_cloudwatch_log_group", "aws_budgets_budget", "aws_iam_role", "aws_iam_role_policy"}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_digest():
    files = [p for p in INFRA.rglob("*") if p.is_file() and ".terraform" not in p.parts
             and (p.suffix in {".tf", ".tftpl"} or p.name == ".terraform.lock.hcl")]
    content = {p.relative_to(INFRA).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(files)}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def summarize_plan(plan, allowed_types=ALLOWED_TYPES):
    changes = []
    for change in plan.get("resource_changes", []):
        if change.get("mode") != "managed" or change["change"]["actions"] == ["no-op"]:
            continue
        if change["type"] not in allowed_types or change["change"]["actions"] != ["create"]:
            raise ValueError("foundation_plan_must_only_create_allowed_resources")
        changes.append({"address": change["address"], "type": change["type"], "actions": ["create"]})
    if not 1 <= len(changes) <= 100:
        raise ValueError("unexpected_foundation_resource_count")
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "outputs", "destroy"))
    args = parser.parse_args()
    config = json.loads((ROOT / "configs/project.json").read_text(encoding="utf-8"))["aws"]
    if not config["account_id"] or not config["approved_budget_usd"]:
        raise ValueError("account_and_concrete_budget_required")
    if args.action == "apply" and not config["deployment_enabled"]:
        raise ValueError("deployment_not_enabled_for_current_scope")
    identity = check_identity(find_aws(), config["account_id"], config["region"])
    terraform = shutil.which("terraform") or str(ROOT / ".tools/terraform/terraform.exe")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    def run(arguments, log):
        result = subprocess.run([terraform, *arguments], cwd=INFRA, capture_output=True,
                                text=True, check=False, timeout=240)
        (EVIDENCE / log).write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"terraform_command_failed; inspect results/aws/foundation/{log}")
        return result.stdout
    variables = {"expected_account_id": config["account_id"], "aws_region": config["region"],
                 "project_id": "pcfl-research", "resource_creation_enabled": True,
                 "budget_usd": config["approved_budget_usd"], "budget_time_unit": "MONTHLY",
                 "budget_alert_email": None, "log_retention_days": 3}
    variable_path = EVIDENCE / "smoke.tfvars.json"
    write_json(variable_path, variables)
    config_digest = hashlib.sha256(json.dumps(variables, sort_keys=True).encode()).hexdigest()
    plan_path = EVIDENCE / "foundation.tfplan"
    summary_path = EVIDENCE / "plan.summary.json"
    if args.action == "plan":
        run(["init", "-input=false", "-lockfile=readonly"], "init.log")
        run(["validate", "-json"], "validate.json")
        run(["plan", "-input=false", "-no-color", f"-var-file={variable_path}", f"-out={plan_path}"], "plan.log")
        plan = json.loads(run(["show", "-json", str(plan_path)], "plan.json"))
        summary = {"account_id": identity["account_id"], "region": config["region"],
                   "created_at_utc": datetime.now(timezone.utc).isoformat(),
                   "source_digest": source_digest(), "config_digest": config_digest,
                   "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                   "changes": summarize_plan(plan), "approved_total_smoke_budget_usd": config["approved_budget_usd"],
                   "monthly_monitor_is_not_total_cap": True, "external_alert_recipient_configured": False,
                   "starts_compute_or_networking": False}
        write_json(summary_path, summary)
        print(json.dumps({"plan_ready": True, "resource_count": len(summary["changes"]),
                          "account_id": identity["account_id"], "region": config["region"],
                          "summary": "results/aws/foundation/plan.summary.json"}, indent=2))
    elif args.action == "apply":
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(summary["created_at_utc"])).total_seconds()
        if (age > 3600 or summary["source_digest"] != source_digest()
                or summary["config_digest"] != config_digest
                or summary["plan_sha256"] != hashlib.sha256(plan_path.read_bytes()).hexdigest()):
            raise ValueError("plan_changed_or_expired; regenerate_and_review")
        run(["apply", "-input=false", "-no-color", str(plan_path)], "apply.log")
        outputs = json.loads(run(["output", "-json"], "outputs.json"))
        write_json(EVIDENCE / "outputs.json", outputs)
        print(json.dumps({"applied": True, "resource_count": len(summary["changes"]),
                          "outputs": "results/aws/foundation/outputs.json"}, indent=2))
    elif args.action == "outputs":
        print(run(["output", "-json"], "outputs.json"))
    else:
        # The smoke runner exports evidence first and explicitly removes only its
        # synthetic object versions. This refuses to discard a nonempty bucket.
        outputs = json.loads((EVIDENCE / "outputs.json").read_text(encoding="utf-8"))
        table = outputs["state_table_name"]["value"]
        if table != "pcfl-research-state":
            raise ValueError("unexpected_teardown_table")
        archive = ROOT / "results/aws/smoke.json"
        if not archive.is_file():
            raise ValueError("export_smoke_evidence_before_teardown")
        retained = json.loads(archive.read_text(encoding="utf-8"))
        if (not retained.get("successful") or retained.get("account_id") != config["account_id"]
                or retained.get("region") != config["region"]
                or not retained.get("retired_before_object_removal") or not retained.get("objects_removed")):
            raise ValueError("verified_retired_smoke_and_object_cleanup_required_before_teardown")
        cli = find_aws()
        result = subprocess.run([cli, "dynamodb", "update-table", "--table-name", table,
                                 "--no-deletion-protection-enabled", "--region", config["region"],
                                 "--no-cli-pager", "--output", "json"],
                                capture_output=True, text=True, check=False, timeout=30)
        if result.returncode:
            raise RuntimeError("could_not_disable_deletion_protection_for_recorded_smoke_table")
        run(["plan", "-destroy", "-input=false", "-no-color", f"-var-file={variable_path}",
             f"-out={EVIDENCE / 'destroy.tfplan'}"], "destroy-plan.log")
        destroy_plan = json.loads(run(["show", "-json", str(EVIDENCE / "destroy.tfplan")], "destroy-plan.json"))
        for change in destroy_plan.get("resource_changes", []):
            if change.get("mode") == "managed" and change["change"]["actions"] not in (["delete"], ["no-op"]):
                raise ValueError("unexpected_action_in_destroy_plan")
        run(["apply", "-input=false", "-no-color", str(EVIDENCE / "destroy.tfplan")], "destroy.log")
        state = json.loads(run(["show", "-json"], "state-after-destroy.json"))
        if state.get("values", {}).get("root_module", {}).get("resources"):
            raise RuntimeError("managed_resources_remain_after_destroy")
        write_json(EVIDENCE / "teardown.json", {"verified": True, "account_id": identity["account_id"],
                   "verified_at_utc": datetime.now(timezone.utc).isoformat(), "managed_resources_remaining": 0})
        print("Verified: no Terraform-managed foundation resources remain.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
