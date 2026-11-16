"""Static IAM contract tests, not live AWS authorization evidence."""

import fnmatch
import json
from pathlib import Path
import re
from string import Template
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infra/terraform"
BUCKET = "arn:aws:s3:::pcfl-test"
TABLE = "arn:aws:dynamodb:us-east-1:123456789012:table/pcfl-research-state"
ORGS = [f"org_{i:02d}" for i in range(1, 9)]


def render(name, **values):
    return json.loads(Template((MODULE / "policies" / f"{name}.json.tftpl").read_text()).substitute(values))


def matches(patterns, value):
    return any(fnmatch.fnmatchcase(value, p) for p in ([patterns] if isinstance(patterns, str) else patterns))


def permitted(policy, action, resource, leading_key=None, enclosing=None, prefix=None):
    """Model only this module's Allow-condition subset, failing unknown operators closed."""
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow" or not matches(statement["Action"], action):
            continue
        if not matches(statement["Resource"], resource):
            continue
        valid = True
        for operator, conditions in statement.get("Condition", {}).items():
            for key, expected in conditions.items():
                actual = {"dynamodb:LeadingKeys": leading_key, "dynamodb:EnclosingOperation": enclosing,
                          "s3:prefix": prefix}.get(key)
                if operator == "Null":
                    valid &= (actual is None) == (expected == "true")
                elif operator in {"ForAllValues:StringEquals", "ForAnyValue:StringEquals"}:
                    valid &= actual is not None and actual in expected
                elif operator in {"ForAllValues:StringLike", "StringLike"}:
                    valid &= actual is not None and matches(expected, actual)
                else:
                    valid = False
        if valid:
            return True
    return False


class InfrastructureContractTests(unittest.TestCase):
    def test_all_eight_client_roles_can_read_only_own_partitions(self):
        for org in ORGS:
            policy = render("client-data", bucket_arn=BUCKET, org_id=org)
            for other in ORGS:
                for distribution in ("iid", "non_iid"):
                    key = f"partitions/{distribution}/{other}/train.jsonl"
                    self.assertEqual(permitted(policy, "s3:GetObject", f"{BUCKET}/{key}"), org == other)
                    self.assertEqual(permitted(policy, "s3:ListBucket", BUCKET, prefix=key), org == other)
            for protected in ("evaluation/holdout.jsonl", "models/candidates/model.bin", "evidence/log.jsonl"):
                self.assertFalse(permitted(policy, "s3:GetObject", f"{BUCKET}/{protected}"))
            self.assertFalse(permitted(policy, "s3:PutObject", f"{BUCKET}/partitions/iid/{org}/train.jsonl"))
            self.assertFalse(permitted(policy, "dynamodb:UpdateItem", TABLE, leading_key="AUTHORITY", enclosing="TransactWriteItems"))

    def test_coordinator_cannot_mutate_policy_or_read_training_or_holdout(self):
        policy = render("coordinator", bucket_arn=BUCKET, table_arn=TABLE,
                        policy_partition_keys=json.dumps([f"POLICY#{org}" for org in ORGS]))
        for org in ORGS:
            self.assertTrue(permitted(policy, "dynamodb:ConditionCheckItem", TABLE, leading_key=f"POLICY#{org}", enclosing="TransactWriteItems"))
            for action in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"):
                self.assertFalse(permitted(policy, action, TABLE, leading_key=f"POLICY#{org}", enclosing="TransactWriteItems"))
            self.assertFalse(permitted(policy, "s3:GetObject", f"{BUCKET}/partitions/iid/{org}/train.jsonl"))
        self.assertFalse(permitted(policy, "s3:GetObject", f"{BUCKET}/evaluation/test.jsonl"))
        self.assertTrue(permitted(policy, "dynamodb:PutItem", TABLE, leading_key="RUN#trial1", enclosing="TransactWriteItems"))
        self.assertFalse(permitted(policy, "dynamodb:PutItem", TABLE, leading_key="RUN#trial1"))
        self.assertTrue(permitted(policy, "dynamodb:UpdateItem", TABLE, leading_key="AUTHORITY", enclosing="TransactWriteItems"))
        self.assertFalse(permitted(policy, "dynamodb:PutItem", TABLE, leading_key="AUTHORITY", enclosing="TransactWriteItems"))

    def test_governance_writes_require_transactions_and_exclude_run_partitions(self):
        keys = [f"POLICY#{org}" for org in ORGS] + ["AUTHORITY"]
        policy = render("governance", bucket_arn=BUCKET, table_arn=TABLE, policy_partition_keys=json.dumps(keys))
        for key in keys:
            self.assertTrue(permitted(policy, "dynamodb:PutItem", TABLE, leading_key=key, enclosing="TransactWriteItems"))
            self.assertFalse(permitted(policy, "dynamodb:PutItem", TABLE, leading_key=key))
        self.assertFalse(permitted(policy, "dynamodb:PutItem", TABLE, leading_key="RUN#trial", enclosing="TransactWriteItems"))
        self.assertFalse(permitted(policy, "dynamodb:Scan", TABLE))

    def test_evaluator_is_read_only_and_cannot_read_training(self):
        policy = render("evaluator", bucket_arn=BUCKET, table_arn=TABLE,
                        policy_partition_keys=json.dumps([f"POLICY#{org}" for org in ORGS] + ["RUN#*", "AUTHORITY"]))
        self.assertTrue(permitted(policy, "s3:GetObject", f"{BUCKET}/evaluation/test.jsonl"))
        self.assertFalse(permitted(policy, "s3:GetObject", f"{BUCKET}/partitions/iid/org_01/train.jsonl"))
        self.assertFalse(permitted(policy, "s3:PutObject", f"{BUCKET}/evaluation/test.jsonl"))
        self.assertTrue(permitted(policy, "dynamodb:GetItem", TABLE, leading_key="RUN#trial"))
        self.assertFalse(permitted(policy, "dynamodb:PutItem", TABLE, leading_key="RUN#trial", enclosing="TransactWriteItems"))

    def test_task_trust_limits_ecs_tasks_to_selected_account_region(self):
        statement = render("task-trust", account_id="123456789012", region="us-east-1", partition="aws")["Statement"][0]
        self.assertEqual(statement["Principal"], {"Service": "ecs-tasks.amazonaws.com"})
        self.assertEqual(statement["Condition"]["StringEquals"]["aws:SourceAccount"], "123456789012")
        self.assertEqual(statement["Condition"]["ArnLike"]["aws:SourceArn"], "arn:aws:ecs:us-east-1:123456789012:*")

    def test_security_controls_exact_pins_and_absence_of_compute_networking(self):
        source = "\n".join(p.read_text() for p in MODULE.glob("*.tf"))
        kinds = re.findall(r'resource\s+"([^"]+)"', source)
        self.assertFalse(any(k.startswith(("aws_ecs_", "aws_instance", "aws_nat_", "aws_lb", "aws_vpc")) for k in kinds))
        for required in ("aws_s3_bucket_public_access_block", "aws_s3_bucket_versioning",
                         "aws_s3_bucket_server_side_encryption_configuration", "aws_budgets_budget"):
            self.assertIn(required, kinds)
        self.assertIn('allowed_account_ids = [var.expected_account_id]', source)
        self.assertIn('condition     = var.resource_creation_enabled', source)
        self.assertIn('billing_mode                = "PAY_PER_REQUEST"', source)
        self.assertIn('deletion_protection_enabled = var.state_deletion_protection', source)
        self.assertIn('required_version = "= 1.17.2"', source)
        self.assertIn('version = "= 6.73.0"', source)
        self.assertNotIn('"dynamodb:TransactWriteItems"', source)
        self.assertNotIn('"dynamodb:*"', source)

    def test_bucket_tls_deny_covers_bucket_and_objects(self):
        statement = render("bucket-tls", bucket_arn=BUCKET)["Statement"][0]
        self.assertEqual(statement["Effect"], "Deny")
        self.assertEqual(statement["Resource"], [BUCKET, f"{BUCKET}/*"])
        self.assertEqual(statement["Condition"]["Bool"]["aws:SecureTransport"], "false")


if __name__ == "__main__":
    unittest.main()
