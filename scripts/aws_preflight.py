"""Read-only AWS identity check. No resource creation or credential export."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


class PreflightError(RuntimeError):
    pass


def find_aws() -> str:
    command = shutil.which("aws")
    if command:
        return command
    candidates = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Amazon/AWSCLIV2/aws.exe",
                  Path("C:/Program Files/Amazon/AWSCLIV2/aws.exe"),
                  ROOT / ".tools/aws-cli/aws.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise PreflightError("aws_cli_not_found")


def _command(aws_path: str, args: list[str]) -> str:
    try:
        result = subprocess.run([aws_path, *args], capture_output=True, text=True,
                                timeout=30, check=False, env={**os.environ, "AWS_PAGER": ""})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise PreflightError("aws_cli_unavailable_or_timeout") from None
    if result.returncode:
        # Never forward raw diagnostics: a provider error may contain credential material.
        match = re.search(r"An error occurred \(([A-Za-z0-9_.-]+)\)", result.stderr)
        raise PreflightError(match.group(1) if match else "aws_command_failed")
    return result.stdout.strip()


def check_identity(aws_path: str, expected_account: str, region: str,
                   profile: str | None = None) -> dict:
    if not re.fullmatch(r"[0-9]{12}", expected_account):
        raise PreflightError("invalid_expected_account")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+", region):
        raise PreflightError("invalid_region")
    version_output = _command(aws_path, ["--version"])
    match = re.search(r"aws-cli/(\d+\.\d+\.\d+)", version_output)
    if not match or int(match.group(1).split(".")[0]) != 2:
        raise PreflightError("aws_cli_v2_required")
    shared = ["--region", region, "--output", "json", "--no-cli-pager"]
    if profile:
        shared += ["--profile", profile]
    try:
        identity = json.loads(_command(aws_path, ["sts", "get-caller-identity", *shared]))
        account, arn = identity["Account"], identity["Arn"]
        if account != expected_account:
            raise PreflightError("authenticated_account_mismatch")
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            raise PreflightError("malformed_identity_response")
    except (json.JSONDecodeError, KeyError, TypeError):
        raise PreflightError("malformed_identity_response") from None
    principal_type = arn.split(":", 5)[-1].split("/")[0]
    return {"schema_version": "0.1.0", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "account_id": account, "region": region, "profile": profile,
            "authenticated": True, "target_account_matches": True,
            "principal_type": principal_type, "aws_cli_version": match.group(1),
            "operations": ["sts:GetCallerIdentity"], "resources_created": False,
            "deployment_permissions_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-account")
    parser.add_argument("--region")
    parser.add_argument("--profile")
    args = parser.parse_args()
    config = json.loads((ROOT / "configs/project.json").read_text(encoding="utf-8"))
    account = args.expected_account or config["aws"]["account_id"]
    region = args.region or config["aws"]["region"]
    try:
        report = check_identity(find_aws(), account or "", region, args.profile)
    except PreflightError as error:
        print(json.dumps({"authenticated": False, "reason": str(error), "resources_created": False}))
        return 1
    destination = ROOT / "results/aws/preflight.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
