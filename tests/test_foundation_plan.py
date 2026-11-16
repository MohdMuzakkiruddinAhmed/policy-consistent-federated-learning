import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("aws_foundation", ROOT / "scripts/aws_foundation.py")
foundation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(foundation)


def change(kind="aws_dynamodb_table", actions=None):
    return {"mode": "managed", "address": f"{kind}.test", "type": kind,
            "change": {"actions": actions or ["create"]}}


class FoundationPlanTests(unittest.TestCase):
    def test_accepts_storage_creation_without_compute(self):
        result = foundation.summarize_plan({"resource_changes": [change()]})
        self.assertEqual(len(result), 1)

    def test_compute_and_existing_resource_changes_are_blocked(self):
        for item in (change("aws_ecs_service"), change("aws_nat_gateway"),
                     change(actions=["update"]), change(actions=["delete", "create"])):
            with self.assertRaises(ValueError):
                foundation.summarize_plan({"resource_changes": [item]})

    def test_empty_or_excessive_plans_are_blocked(self):
        for items in ([], [change()] * 101):
            with self.assertRaises(ValueError):
                foundation.summarize_plan({"resource_changes": items})
