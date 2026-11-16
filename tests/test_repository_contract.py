import ast
import hashlib
import json
from pathlib import Path
import sys
import unittest

from pcfl.contracts import ACTIONS, ORGANIZATIONS

ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_original_plan_is_preserved_byte_for_byte(self):
        self.assertEqual((ROOT / "plan (3).md").read_bytes(), (ROOT / "plan.md").read_bytes())

    def test_cloud_and_confirmatory_execution_require_bound_authorization(self):
        config = json.loads((ROOT / "configs/project.json").read_text(encoding="utf-8"))
        if config["research"]["confirmatory_execution_enabled"]:
            from pcfl.experiments import validate_plan, GATES, freeze_plan
            plan = json.loads((ROOT / config["research"]["accepted_plan"]).read_text(encoding="utf-8"))
            validate_plan(plan)
            self.assertEqual(plan["status"], "accepted_frozen")
            self.assertTrue(plan["confirmatory_execution_enabled"])
            self.assertEqual(set(plan["acceptance"]["gates"]), GATES)
            candidate = json.loads((ROOT / config["research"]["candidate_plan"]).read_text(encoding="utf-8"))
            self.assertEqual(freeze_plan(candidate, plan["acceptance"], ROOT), plan)
        self.assertEqual(config["organizations"], list(ORGANIZATIONS))
        if config["aws"]["deployment_enabled"]:
            self.assertRegex(config["aws"]["account_id"], r"^[0-9]{12}$")
            self.assertGreater(config["aws"]["approved_budget_usd"], 0)
            scope = config["aws"]["deployment_scope"]
            self.assertIn(scope, {"temporary-foundation-smoke-only", "remaining-phases-cloud-campaign"})
            if scope == "remaining-phases-cloud-campaign":
                authorization = json.loads((ROOT / config["aws"]["campaign_authorization"]).read_text(encoding="utf-8"))
                self.assertTrue(authorization["approved"])
                self.assertEqual(authorization["source"], "user-conversation")
                self.assertEqual(authorization["account_id"], config["aws"]["account_id"])
                self.assertEqual(authorization["region"], config["aws"]["region"])
                self.assertEqual(authorization["authorization_scope"], "remaining-phases-cloud-campaign-including-replication")
                self.assertEqual(config["aws"]["approved_budget_usd"], authorization["approved_total_usd"])
                if authorization.get("kind") == "campaign-authorization-amendment":
                    sys.path.insert(0, str(ROOT / "scripts"))
                    from aws_campaign import validate_authorization
                    from campaign_budget import validate_amendment
                    path = ROOT / config["aws"]["campaign_authorization"]
                    request = {"account_id": config["aws"]["account_id"], "region": config["aws"]["region"],
                        "campaign_budget_kind": "campaign-authorization-amendment",
                        "authorization": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
                    self.assertEqual(validate_authorization(request), authorization)
                    # This checks the immutable proposal, genuine decision and
                    # closed predecessor chain; no current live ledger is read.
                    context = validate_amendment(request, authorization, root=ROOT)
                    self.assertEqual(context["authorization_sha256"], request["authorization"]["sha256"])
                    self.assertEqual(authorization["max_vcpu"], 4)
                    self.assertEqual(authorization["max_memory_gib"], 14)
                    self.assertEqual(authorization["per_deployment_max_hours"], 24)
                    self.assertEqual(config["aws"]["campaign_approved_cumulative_total_usd"], authorization["approved_total_usd"])
                    self.assertEqual(config["aws"]["max_cumulative_fleet_hours"], authorization["max_cumulative_fleet_hours"])
                else:
                    self.assertLessEqual(authorization["approved_total_usd"], 20)
                    self.assertLessEqual(authorization["max_cumulative_fleet_hours"], 32)
                self.assertLessEqual(authorization["max_vcpu"], 4)
                self.assertLessEqual(authorization["max_memory_gib"], 14)
                self.assertTrue(authorization["automatic_expiry_required"])
                self.assertTrue(authorization["teardown_required"])

    def test_planned_coordinator_and_log_flow_excludes_source_records(self):
        spec = json.loads((ROOT / "configs/data_flow.json").read_text(encoding="utf-8"))
        flows = spec["flows"]
        self.assertEqual(len([f for f in flows if f["to"] == "coordinator"]), 1)
        for flow in flows:
            if flow["to"] in {"coordinator", "publisher", "experiment_log"}:
                self.assertFalse(set(flow["payload"]) & {"secondary_records", "grouping_keys",
                                                       "own_training_partition", "frozen_holdout"})

    def test_oracle_imports_no_enforcement_code(self):
        tree = ast.parse((ROOT / "src/pcfl/oracle.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                self.assertNotIn("pcfl", node.module or "")
            if isinstance(node, ast.Import):
                self.assertTrue(all(not alias.name.startswith("pcfl") for alias in node.names))

    def test_draft_schemas_parse_and_cover_core_contract_fields(self):
        event = json.loads((ROOT / "schemas/policy-event.schema.json").read_text(encoding="utf-8"))
        query = json.loads((ROOT / "schemas/interval-query.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(event["properties"]["rules"]["items"]["properties"]["action"]["enum"], list(ACTIONS))
        self.assertEqual(query["properties"]["actions"]["items"]["enum"], list(ACTIONS))
        self.assertTrue({"org_id", "epoch", "order", "rules"} <= set(event["required"]))
        self.assertTrue({"start_order", "commit_order", "purpose"} <= set(query["required"]))
