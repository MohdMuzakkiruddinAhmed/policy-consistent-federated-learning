"""Fictional successor records in discarded temp roots; no approval/AWS/data."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
PACKAGE = STAGE.parent
ROOT = next(path for path in STAGE.parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(PACKAGE), str(STAGE), str(ROOT / "scripts"), str(ROOT / "src")]
import campaign_budget as budget
import test_campaign_budget_lineage as lineage_fixture
import cost_scope_snapshot as snapshots
COST_SOURCE = STAGE / "reconcile_campaign_cost.py" if (STAGE / "reconcile_campaign_cost.py").is_file() else ROOT / "scripts/reconcile_campaign_cost.py"
spec = importlib.util.spec_from_file_location("amended_cost", COST_SOURCE)
cost = importlib.util.module_from_spec(spec); spec.loader.exec_module(cost)
NOW = datetime(2026, 11, 13, 6, tzinfo=timezone.utc)
RESERVES = {"endpoint_data_processing_up_to_30GB": .3, "secrets_and_api_calls": .6,
    "two_private_dns_namespaces_and_discovery": 1.1, "ECR_storage": .3, "S3_storage_requests_and_export": 1,
    "DynamoDB_requests_storage_backup": 2, "bounded_masked_logs": 1, "scheduler_lambda_SQS_and_monitoring": .2}


class AmendmentCostConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.f = lineage_fixture.Fixture(self.root)
        self.catalog = {"terms": {"OnDemand": {}}}
        rates = {}
        for name, amount in (("cpu", ".04048"), ("memory", ".004445")):
            sku, effective = name.upper(), "2026-11-01T00:00:00Z"
            rates[name] = {"sku": sku, "effective_date": effective, "usd": amount}
            self.catalog["terms"]["OnDemand"][sku] = {"term": {"effectiveDate": effective,
                "priceDimensions": {"dimension": {"pricePerUnit": {"USD": amount}}}}}
        self.catalog_ref = self.f.put("catalog.json", self.catalog)
        for quote in (self.f.old_quote, self.f.quote):
            quote.update(catalog_sha256=self.catalog_ref["sha256"], rates=deepcopy(rates),
                checked_at_utc="2026-11-13T03:00:00Z", other_allowances_usd=deepcopy(RESERVES))
        self.f.quote["estimated_bounded_total_usd"] = 25  # SYNTHETIC ONLY, not a project proposal.
        self.f.quote_cost["current_conservative_planning_estimate_usd"] = 10
        self.f.terminal_cost["current_conservative_planning_estimate_usd"] = 12
        for report in (self.f.quote_cost, self.f.terminal_cost):
            report.update(current_unmetered_service_reserves_usd=deepcopy(RESERVES), cumulative_fleet_equivalent_hours=1)
        contract = {"interface_endpoint_ids": ["vpce-" + str(n) for n in range(5)], "endpoint_az_count": 1,
            "secret_arns": {str(n): "fictional-secret-reference" for n in range(16)}}
        self.f.inventory["runtime_contract"] = deepcopy(contract)
        for row in self.f.inventory["observed_tasks"]: row.update(cpu=256, memory_mib=1024)
        self.request = self.f.build()
        self.request.update(schema_version="0.1.0", campaign_budget_kind=budget.KIND, namespace="synthetic.local",
            foundation_vars="never-opened.json", runtime_vars="never-opened.json", local_image_tag="synthetic:not-run", data_uploads=[], secrets=[])
        self.new_arn = f"arn:aws:ecs:{self.f.region}:{self.f.account}:task/{self.f.new_project}-runtime/" + "c" * 32
        self.new_image = f"{self.f.account}.dkr.ecr.{self.f.region}.amazonaws.com/{self.f.new_project}/coordinator@sha256:" + "f" * 64
        self.new_inventory = {"account_id": self.f.account, "region": self.f.region, "campaign_id": self.f.new_campaign,
            "project_id": self.f.new_project, "task_arns": [self.new_arn], "runtime_contract": contract,
            "foundation": {"image_repositories": {"coordinator": self.new_image.split("@")[0]}},
            "image": {"reference": self.new_image}, "observed_tasks": [{"task_arn": self.new_arn, "cpu": 256,
                "memory_mib": 1024, "billing_started_at": "2026-11-13T04:00:00Z", "stopped_at": "2026-11-13T05:00:00Z", "last_status": "STOPPED"}]}
        self.f.put(f"results/aws/{self.f.new_campaign}/inventory.json", self.new_inventory)
        self.ledger = budget.new_ledger(self.request, root=self.root)
        self.ledger["tasks"][self.new_arn] = {"campaign_id": self.f.new_campaign, "cpu": 256, "memory_mib": 1024,
            "vcpu_hours": .25, "gib_hours": 1, "last_status": "STOPPED"}
        self.ledger["deployments"]["new-0"] = {"campaign_id": self.f.new_campaign, "project_id": self.f.new_project,
            "started_at": "2026-11-13T04:00:00Z", "finished_at": None}
        self.ledger_relative = f"results/aws/budget-ledger-{self.request['authorization']['sha256']}.json"
        self.f.put(self.ledger_relative, self.ledger)
        self.f.put("results/aws/budget-authorization-retirements.json", budget.proposed_retirement_registry(self.request,
            budget.validate_amendment(self.request, root=self.root), root=self.root))
        self.f.put("results/aws/budget-lineage-required.json", {"required": True})
        self.request_ref = self.f.put("new-request.json", self.request)
        self.request_path = self.root / self.request_ref["path"]

    def tearDown(self): self.temp.cleanup()

    def load(self): return cost.load_scope(self.request_path, root=self.root)

    def report(self, *, remaining_cells=0, **kwargs):
        request, approval, ledger, inventories, inputs = self.load()
        quote, rates = cost.price_basis(self.root / approval["proposal_path"], self.root / self.catalog_ref["path"], request=request, approval=approval)
        old = cost.retained_image_observations(self.root / self.f.terminal_cost_ref["path"], self.f.terminal_cost_ref["sha256"],
            request=request, now=NOW, root=self.root)
        observations = {"images": [{"reference": self.new_image, "compressed_image_bytes": 200000, "pushed_at": "2026-11-13T03:00:00Z"}]}
        result = cost.reconcile(request, approval, ledger, inventories, quote, rates, root=self.root, now=NOW,
            throughput={"both_distributions_observed": True, "worst_observed_case_seconds": 100},
            remaining_cells=remaining_cells, observations=observations, retained_observations=old, **kwargs)
        result["source_inputs"] = inputs
        return result

    def test_native_loader_keeps_full_old_and_new_scope_without_writes(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*.json")}
        request, approval, ledger, inventories, inputs = self.load()
        self.assertEqual(set(inventories), {self.f.old_campaign, self.f.new_campaign})
        self.assertEqual(ledger["tasks"][self.f.old_arns[0]], self.f.terminal["tasks"][self.f.old_arns[0]])
        self.assertEqual(approval["approved_total_usd"], 30)
        self.assertTrue(any(row["sha256"] == self.f.terminal_cost_ref["sha256"] for row in inputs))
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*.json")})

    def test_fresh_cost_adds_above_inherited_floor_instead_of_being_absorbed(self):
        result = self.report()
        self.assertEqual(result["inherited_current_cost_floor_usd"], 12)
        self.assertGreater(result["new_measured_and_reserved_cost_above_inherited_floor_usd"], 0)
        self.assertGreater(result["current_conservative_planning_estimate_usd"], 12.1)
        self.assertAlmostEqual(result["current_conservative_planning_estimate_usd"],
            result["inherited_current_cost_floor_usd"] + result["new_measured_and_reserved_cost_above_inherited_floor_usd"])
        self.assertFalse(result["actual_bill_reconciled"])
        self.assertEqual(result["measurement"], "inferred")
        self.assertEqual(result["budget_semantics"], "cumulative-inclusive-of-predecessors")
        self.assertEqual(len(result["resources"]["tasks"]), 3)
        self.assertEqual(result["image_pull_endpoint_planning_envelope"]["missing_image_size_references"], [])

    def test_only_exact_terminal_ancestor_report_can_restore_retired_image_metadata(self):
        cost.retained_image_observations(self.root / self.f.terminal_cost_ref["path"], self.f.terminal_cost_ref["sha256"], request=self.request, now=NOW, root=self.root)
        with self.assertRaisesRegex(ValueError, "exact_approved_terminal"):
            cost.retained_image_observations(self.root / self.f.quote_cost_ref["path"], self.f.quote_cost_ref["sha256"], request=self.request, now=NOW, root=self.root)

    def test_missing_registration_or_missing_ledger_never_creates_an_empty_successor(self):
        registry = self.root / "results/aws/budget-authorization-retirements.json"
        before = registry.read_bytes(); registry.unlink()
        with self.assertRaisesRegex(ValueError, "registry_missing"):
            self.load()
        registry.write_bytes(before)
        (self.root / self.ledger_relative).unlink()
        with self.assertRaisesRegex(ValueError, "initialized_before_cost"):
            self.load()
        self.assertFalse((self.root / self.ledger_relative).exists())

    def test_request_marker_or_inherited_usage_tampering_is_rejected(self):
        changed = deepcopy(self.request); changed.pop("campaign_budget_kind")
        self.f.put("new-request.json", changed)
        with self.assertRaisesRegex(ValueError, "marker_and_approval"):
            self.load()
        self.f.put("new-request.json", self.request)
        self.ledger["tasks"][self.f.old_arns[0]]["vcpu_hours"] = 0
        self.f.put(self.ledger_relative, self.ledger)
        with self.assertRaisesRegex(ValueError, "predecessor_rows"):
            self.load()

    def test_exact_quote_and_original_rates_cannot_be_repriced(self):
        args = self.load(); quote, rates = cost.price_basis(self.root / self.f.quote_ref["path"], self.root / self.catalog_ref["path"], request=args[0], approval=args[1])
        rates["cpu"] = .00001
        with self.assertRaisesRegex(ValueError, "unchanged_locked_pricing"):
            cost.reconcile(*args[:4], quote, rates, root=self.root, now=NOW, throughput={}, remaining_cells=0)

    def test_frozen_successor_scope_replays_after_live_files_and_registry_change(self):
        receipt = snapshots.create(self.request_path, self.root / "snapshot-B", root=self.root, loader=cost.load_scope)
        frozen = self.root / receipt["request"]["path"]
        first = cost.load_scope(frozen, root=self.root)
        self.f.put(self.ledger_relative, {"changed-live": True})
        self.f.put(f"results/aws/{self.f.new_campaign}/inventory.json", {"changed-live": True})
        (self.root / "results/aws/budget-authorization-retirements.json").unlink()
        second = cost.load_scope(frozen, root=self.root)
        self.assertEqual(first, second)
        self.assertEqual(second[2]["tasks"][self.new_arn]["vcpu_hours"], .25)

    def test_native_P8_cost_replay_preserves_typed_limits_and_requires_scientific_forecast(self):
        request, approval, ledger, inventories, inputs = self.load()
        quote, rates = cost.price_basis(self.root / self.f.quote_ref["path"], self.root / self.catalog_ref["path"], request=request, approval=approval)
        prepared = cost.prepared_pilot_campaigns(request, inventories)
        throughput = cost.pilot_throughput(inventories, {}, 5, prepared)
        old = cost.retained_image_observations(self.root / self.f.terminal_cost_ref["path"], self.f.terminal_cost_ref["sha256"], request=request, now=NOW, root=self.root)
        result = cost.reconcile(request, approval, ledger, inventories, quote, rates, root=self.root, now=NOW,
            throughput=throughput, remaining_cells=0, retained_observations=old,
            observations={"images": [{"reference": self.new_image, "compressed_image_bytes": 200000, "pushed_at": "2026-11-13T03:00:00Z"}]})
        result.update(source_inputs=inputs, source_sha256={"scripts/reconcile_campaign_cost.py": cost.file_sha256(cost.__file__),
            "scripts/campaign_budget.py": cost.file_sha256(budget.__file__)})
        report_ref = self.f.put("replayed-report.json", result)
        source = STAGE / "assess_pilots.py" if (STAGE / "assess_pilots.py").is_file() else ROOT / "scripts/assess_pilots.py"
        spec = importlib.util.spec_from_file_location("amended_assessor", source)
        assessor = importlib.util.module_from_spec(spec); spec.loader.exec_module(assessor)
        plan = {"training_candidate": {"num_rounds": 5}, "provenance": {"source_files_sha256": result["source_sha256"]}}
        cost_spec = {"report": str(self.root / report_ref["path"]), "request": str(self.request_path),
            "quote": str(self.root / self.f.quote_ref["path"]), "catalog": str(self.root / self.catalog_ref["path"])}
        with patch.dict(sys.modules, {"reconcile_campaign_cost": cost}):
            facts = assessor.cost_facts(cost_spec, assessor.Evidence(self.root), plan, {})
        self.assertTrue(facts["reproduced"])
        self.assertTrue(facts["operator_budget"])
        self.assertTrue(facts["current_spend_accounted"])
        self.assertEqual(facts["approved_total_usd"], 30)
        self.assertEqual(facts["maximum_cumulative_fleet_hours"], 60)
        self.assertFalse(facts["projected_cost"])


if __name__ == "__main__": unittest.main()
