import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("aws_preflight", ROOT / "scripts/aws_preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class AwsPreflightTests(unittest.TestCase):
    def responses(self, account="980322232249"):
        return [subprocess.CompletedProcess([], 0, "aws-cli/2.40.2 Python/3 Windows", ""),
                subprocess.CompletedProcess([], 0, json.dumps({"Account": account,
                    "Arn": f"arn:aws:iam::{account}:user/test-user"}), "")]

    @patch.object(preflight.subprocess, "run")
    def test_matching_account_without_secret_or_full_principal_export(self, run):
        run.side_effect = self.responses()
        report = preflight.check_identity("aws", "980322232249", "us-east-1")
        self.assertTrue(report["authenticated"])
        self.assertEqual(report["principal_type"], "user")
        self.assertFalse(report["resources_created"])
        self.assertNotIn("test-user", json.dumps(report))
        self.assertEqual(run.call_args.args[0][:3], ["aws", "sts", "get-caller-identity"])

    @patch.object(preflight.subprocess, "run")
    def test_wrong_account_fails_before_deployment(self, run):
        run.side_effect = self.responses("111111111111")
        with self.assertRaisesRegex(preflight.PreflightError, "account_mismatch"):
            preflight.check_identity("aws", "980322232249", "us-east-1")

    @patch.object(preflight.subprocess, "run")
    def test_raw_provider_errors_are_not_forwarded(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "An error occurred (InvalidClientTokenId): secret-key-data")
        with self.assertRaises(preflight.PreflightError) as caught:
            preflight.check_identity("aws", "980322232249", "us-east-1")
        self.assertEqual(str(caught.exception), "InvalidClientTokenId")
        self.assertNotIn("secret-key-data", str(caught.exception))

    @patch.object(preflight.subprocess, "run")
    def test_profile_passed_as_argument(self, run):
        run.side_effect = self.responses()
        preflight.check_identity("aws", "980322232249", "us-east-1", "pcfl")
        self.assertEqual(run.call_args.args[0][-2:], ["--profile", "pcfl"])

    @patch.object(preflight.subprocess, "run")
    def test_invalid_target_makes_no_call(self, run):
        with self.assertRaises(preflight.PreflightError):
            preflight.check_identity("aws", "", "us-east-1")
        run.assert_not_called()
