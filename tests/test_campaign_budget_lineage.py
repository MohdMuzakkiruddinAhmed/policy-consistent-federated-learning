"""Synthetic staged amendment contracts; no approval or AWS operation occurs."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

STAGE = Path(__file__).resolve().parent
ROOT = next(p for p in STAGE.parents if (p / "pyproject.toml").is_file())
sys.path.insert(0, str(STAGE))
sys.path.insert(0, str(ROOT / "scripts"))
import campaign_budget as budget
from reconcile_campaign_cost import merge_image_observations


class Fixture:
    """All apparent approvals below are fictional documents in a temp root."""
    account, region = "123456789012", "us-east-1"
    old_campaign, old_project = "synthetic-old", "pcfl-old"
    new_campaign, new_project = "synthetic-next", "pcfl-next"

    def __init__(self, root):
        self.root = root
        self.old_arns = [f"arn:aws:ecs:{self.region}:{self.account}:task/{self.old_project}-runtime/{c * 32}" for c in "ab"]
        self.old_image = f"{self.account}.dkr.ecr.{self.region}.amazonaws.com/{self.old_project}/coordinator@sha256:" + "e" * 64
        self.old_quote = {"schema_version": "0.1.0", "account_id": self.account, "region": self.region,
            "catalog_sha256": "c" * 64, "rates": {"cpu": {"usd": ".04"}, "memory": {"usd": ".004"}},
            "requested_additional_total_usd": 20}
        self.old_auth = {"account_id": self.account, "region": self.region, "approved": True,
            "source": "user-conversation", "authorization_scope": budget.SCOPE, "approved_total_usd": 20,
            "max_cumulative_fleet_hours": 32, "max_vcpu": 4, "max_memory_gib": 14, "per_deployment_max_hours": 24}
        self.snapshot = {"tasks": {arn: {"campaign_id": self.old_campaign, "cpu": 256, "memory_mib": 1024,
            "vcpu_hours": hours, "gib_hours": hours * 4, "last_status": "STOPPED"}
            for arn, hours in zip(self.old_arns, (1.25, .75))},
            "deployments": {"synthetic-old-0": {"campaign_id": self.old_campaign, "project_id": self.old_project,
                "started_at": "2026-11-13T00:00:00Z", "finished_at": "2026-11-13T01:00:00Z"}}}
        self.terminal = deepcopy(self.snapshot)
        self.inventory = {"account_id": self.account, "region": self.region, "campaign_id": self.old_campaign,
            "project_id": self.old_project, "teardown_complete": True, "task_arns": self.old_arns[:],
            "observed_tasks": [{"task_arn": arn, "last_status": "STOPPED", "billing_started_at": "2026-11-13T00:00:00Z",
                "stopped_at": "2026-11-13T00:59:00Z"} for arn in self.old_arns],
            "foundation": {"image_repositories": {"coordinator": self.old_image.split("@")[0]}},
            "image_history": [{"reference": self.old_image}]}
        self.readback = {"kind": "actual-aws-campaign-teardown-validation", "account_id": self.account,
            "region": self.region, "campaign_id": self.old_campaign, "project_id": self.old_project,
            "successful": True, "performed_read_only": True, "checked_at_utc": "2026-11-13T03:00:00Z",
            "checks": {key: True for key in budget.CHECKS}}
        self.quote_cost = self.cost(5)
        self.terminal_cost = self.cost(6)
        self.quote = {"schema_version": "0.1.0", "kind": "campaign-budget-amendment-proposal",
            "account_id": self.account, "region": self.region, "authorization_scope": budget.SCOPE,
            "budget_semantics": "cumulative-inclusive-of-predecessors", "requested_cumulative_total_usd": 30,
            "maximum_cumulative_fleet_hours": 60, "requested_incremental_usd": 10, "estimated_bounded_total_usd": 25,
            "catalog_sha256": self.old_quote["catalog_sha256"], "rates": deepcopy(self.old_quote["rates"])}
        self.decision = {"kind": "user-approved-campaign-budget-amendment", "account_id": self.account,
            "region": self.region, "source": "user-conversation", "approved": True,
            "user_statement": "SYNTHETIC UNIT TEST ONLY: fictional cumulative decision, no authority",
            "authorization_scope": budget.SCOPE, "budget_semantics": "cumulative-inclusive-of-predecessors",
            "approved_total_usd": 30, "max_cumulative_fleet_hours": 60, "max_vcpu": 4, "max_memory_gib": 14,
            "per_deployment_max_hours": 24}
        self.activation = {"kind": "terminal-campaign-budget-activation", "account_id": self.account, "region": self.region}
        self.approval = {"schema_version": "0.1.0", "kind": budget.KIND, **deepcopy(self.decision)}
        self.approval["kind"] = budget.KIND
        self.drop_terminal_source_pin = False
        self.extra_terminal_pairs = []

    def cost(self, amount):
        return {"kind": "campaign-priced-usage-reconciliation", "account_id": self.account, "region": self.region,
            "measurement": "inferred", "aws_mutations": False, "current_spend_accounted": True,
            "successful": False, "terminal_accounting_only": True, "as_of_utc": "2026-11-13T02:00:00Z",
            "current_conservative_planning_estimate_usd": amount,
            "resources": {"tasks": deepcopy(self.snapshot["tasks"])},
            "aws_observations": {"images": [{"reference": self.old_image, "compressed_image_bytes": 123456,
                "pushed_at": "2026-11-12T22:00:00Z"}]}}

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, allow_nan=True), encoding="utf-8")
        return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def build(self):
        self.old_quote_ref = self.put("old/quote.json", self.old_quote)
        self.old_auth.update(proposal_path=self.old_quote_ref["path"], proposal_sha256=self.old_quote_ref["sha256"])
        self.old_auth_ref = self.put("old/auth.json", self.old_auth)
        for ledger in (self.snapshot, self.terminal): ledger["authorization_sha256"] = self.old_auth_ref["sha256"]
        snapshot_ref = self.put("old/quote-ledger.json", self.snapshot)
        self.terminal_ref = self.put("old/terminal-ledger.json", self.terminal)
        self.inventory_ref = self.put("old/inventory.json", self.inventory)
        self.readback["inventory_sha256"] = self.inventory_ref["sha256"]
        self.readback_ref = self.put("old/readback.json", self.readback)
        self.quote_cost["source_inputs"] = [self.old_auth_ref, self.old_quote_ref, snapshot_ref]
        self.quote_cost_ref = self.put("old/quote-cost.json", self.quote_cost)
        self.terminal_cost["source_inputs"] = [self.old_auth_ref, self.old_quote_ref, self.terminal_ref, self.inventory_ref]
        if self.drop_terminal_source_pin: self.terminal_cost["source_inputs"].pop()
        self.terminal_cost_ref = self.put("old/terminal-cost.json", self.terminal_cost)
        self.quote.update(basis={"ledger": snapshot_ref, "cost_report": self.quote_cost_ref},
            predecessor_authorization_sha256=self.old_auth_ref["sha256"], predecessor_quote_sha256=self.old_quote_ref["sha256"])
        self.quote_ref = self.put("next/proposal.json", self.quote)
        self.decision["proposal_sha256"] = self.quote_ref["sha256"]
        decision_ref = self.put("next/fictional-decision.json", self.decision)
        self.activation.update(proposal_sha256=self.quote_ref["sha256"], approval_decision_sha256=decision_ref["sha256"],
            predecessor_authorization=self.old_auth_ref, predecessor_quote=self.old_quote_ref,
            terminal_ledger=self.terminal_ref, terminal_cost_report=self.terminal_cost_ref,
            terminal_campaigns=[{"inventory": self.inventory_ref, "readback": self.readback_ref}, *self.extra_terminal_pairs])
        activation_ref = self.put("next/activation.json", self.activation)
        self.approval.update(proposal_path=self.quote_ref["path"], proposal_sha256=self.quote_ref["sha256"],
            approval_decision=decision_ref, activation=activation_ref)
        self.request = {"account_id": self.account, "region": self.region, "campaign_id": self.new_campaign,
            "campaign_budget_kind": "campaign-authorization-amendment",
            "project_id": self.new_project, "authorization": self.put("next/fictional-authorization.json", self.approval)}
        return self.request


class CampaignBudgetLineageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.f = Fixture(self.root)
        self.f.build()

    def tearDown(self): self.temp.cleanup()

    def validate(self): return budget.validate_amendment(self.f.request, root=self.root)

    def test_exact_old_usage_and_failed_history_survive_pure_successor_creation(self):
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*.json")}
        context = self.validate()
        successor = budget.new_ledger(self.f.request, root=self.root)
        self.assertEqual(context["tasks"], self.f.terminal["tasks"])
        self.assertEqual(successor["deployments"], self.f.terminal["deployments"])
        self.assertEqual(context["usage_floors"]["vcpu_hours"], 2)
        self.assertEqual(context["usage_floors"]["gib_hours"], 8)
        self.assertEqual(context["usage_floors"]["endpoint_deployment_hours"], 1)
        self.assertEqual(context["usage_floors"]["conservative_planning_usd"], 6)
        self.assertEqual(budget.validate_ledger_lineage(self.f.request, successor, root=self.root), context)
        successor["tasks"][self.f.old_arns[0]]["vcpu_hours"] = 0
        self.assertEqual(context["tasks"][self.f.old_arns[0]]["vcpu_hours"], 1.25)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*.json")})

    def test_drop_or_change_any_inherited_usage_row_is_rejected(self):
        for collection in ("tasks", "deployments"):
            for mutation in ("drop", "change"):
                with self.subTest(collection=collection, mutation=mutation):
                    ledger = budget.new_ledger(self.f.request, root=self.root)
                    key = next(iter(ledger[collection]))
                    if mutation == "drop": del ledger[collection][key]
                    elif collection == "tasks": ledger[collection][key]["vcpu_hours"] = .001
                    else: ledger[collection][key]["finished_at"] = "2026-11-13T00:01:00Z"
                    with self.assertRaisesRegex(ValueError, "predecessor_rows"):
                        budget.validate_ledger_lineage(self.f.request, ledger, root=self.root)

    def test_quote_time_usage_can_grow_before_terminal_activation_without_losing_orphans(self):
        first = self.f.old_arns[0]
        self.f.snapshot["tasks"].pop(self.f.old_arns[1])
        self.f.snapshot["tasks"][first].update(last_status="RUNNING", vcpu_hours=.5, gib_hours=2)
        self.f.snapshot["deployments"]["synthetic-old-0"]["finished_at"] = None
        self.f.quote_cost["resources"]["tasks"] = deepcopy(self.f.snapshot["tasks"])
        self.f.build()
        context = self.validate()
        self.assertEqual(len(context["tasks"]), 2)
        self.assertEqual(context["usage_floors"]["vcpu_hours"], 2)
        self.assertEqual(context["tasks"][first]["last_status"], "STOPPED")

    def test_rebound_ancestor_image_observation_must_stay_in_exact_owned_history(self):
        for mutation in ("foreignrepository", "futurepush", "wrongsize"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self.root)
                image = fixture.terminal_cost["aws_observations"]["images"][0]
                if mutation == "foreignrepository": image["reference"] = image["reference"].replace("pcfl-old", "pcfl-stranger")
                elif mutation == "futurepush": image["pushed_at"] = "2026-11-14T00:00:00Z"
                else: image["compressed_image_bytes"] = True
                fixture.build()
                with self.assertRaises(ValueError): budget.validate_amendment(fixture.request, root=self.root)

    def test_carry_forward_receipt_and_history_cannot_be_rebound(self):
        for field in ("predecessor_authorization", "predecessor_ledger", "predecessor_cost_report", "campaign_ids", "usage_floors"):
            with self.subTest(field=field):
                ledger = budget.new_ledger(self.f.request, root=self.root)
                ledger["carry_forward"][field] = None
                with self.assertRaisesRegex(ValueError, "carry_forward_receipt"):
                    budget.validate_ledger_lineage(self.f.request, ledger, root=self.root)
        ledger = budget.new_ledger(self.f.request, root=self.root)
        ledger["authorization_history"] = ledger["authorization_history"][1:]
        with self.assertRaises(ValueError): budget.validate_ledger_lineage(self.f.request, ledger, root=self.root)

    def test_carry_forward_exactness_does_not_coerce_boolean_or_numeric_types(self):
        original = budget.new_ledger(self.f.request, root=self.root)
        for mutation in ("boolean-floor", "numeric-encoding"):
            with self.subTest(mutation=mutation):
                ledger = deepcopy(original)
                if mutation == "boolean-floor":
                    ledger["carry_forward"]["usage_floors"]["endpoint_deployment_hours"] = True
                else:
                    ledger["tasks"][self.f.old_arns[0]]["cpu"] = 256.0
                with self.assertRaises(ValueError):
                    budget.validate_ledger_lineage(self.f.request, ledger, root=self.root)

    def test_future_owned_records_append_without_reopening_retired_campaign(self):
        ledger = budget.new_ledger(self.f.request, root=self.root)
        inventory = {"account_id": self.f.account, "region": self.f.region, "campaign_id": self.f.new_campaign, "project_id": self.f.new_project}
        arn = f"arn:aws:ecs:{self.f.region}:{self.f.account}:task/{self.f.new_project}-runtime/" + "c" * 32
        inventory["task_arns"] = [arn]
        ledger["tasks"][arn] = {"campaign_id": self.f.new_campaign, "vcpu_hours": .1, "gib_hours": .4}
        ledger["deployments"]["next-0"] = {"campaign_id": self.f.new_campaign, "project_id": self.f.new_project,
            "started_at": "2026-11-13T04:00:00Z", "finished_at": None}
        budget.validate_ledger_lineage(self.f.request, ledger, root=self.root, campaign_inventories={self.f.new_campaign: inventory})
        for change in ("oldcampaign", "oldproject", "foreignaccount", "foreignarn", "missinginventory", "unrecordedtask"):
            with self.subTest(change=change):
                copied, owned = deepcopy(ledger), {self.f.new_campaign: deepcopy(inventory)}
                if change == "oldcampaign": copied["tasks"][arn]["campaign_id"] = self.f.old_campaign
                elif change == "oldproject": owned[self.f.new_campaign]["project_id"] = self.f.old_project
                elif change == "foreignaccount": owned[self.f.new_campaign]["account_id"] = "999999999999"
                elif change == "foreignarn": copied["tasks"][arn.replace(self.f.account, "999999999999")] = copied["tasks"].pop(arn)
                elif change == "unrecordedtask": owned[self.f.new_campaign]["task_arns"] = []
                else: owned = {}
                with self.assertRaises(ValueError): budget.validate_ledger_lineage(self.f.request, copied, root=self.root, campaign_inventories=owned)

    def test_terminal_open_clocks_running_tasks_or_decreased_quote_usage_reject(self):
        for mutation in ("openclock", "runningtask", "decreasedusage"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self.root)
                if mutation == "openclock":
                    fixture.snapshot["deployments"]["synthetic-old-0"]["finished_at"] = None
                    fixture.terminal["deployments"]["synthetic-old-0"]["finished_at"] = None
                elif mutation == "runningtask":
                    fixture.snapshot["tasks"][fixture.old_arns[0]]["last_status"] = "RUNNING"
                    fixture.terminal["tasks"][fixture.old_arns[0]]["last_status"] = "RUNNING"
                else: fixture.terminal["tasks"][fixture.old_arns[0]]["vcpu_hours"] = .1
                fixture.build()
                with self.assertRaises(ValueError): budget.validate_amendment(fixture.request, root=self.root)

    def test_complete_inventory_readback_set_and_exact_boolean_checks_required(self):
        for mutation in ("unretainedtask", "wrongproject", "foreignregion", "nonbooleancheck", "notclosed", "duplicate"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self.root)
                if mutation == "unretainedtask": fixture.inventory["task_arns"].pop()
                elif mutation == "wrongproject": fixture.readback["project_id"] = "pcfl-foreign"
                elif mutation == "foreignregion": fixture.inventory["region"] = "us-west-2"
                elif mutation == "nonbooleancheck": fixture.readback["checks"]["foundation_removed"] = 1
                elif mutation == "notclosed": fixture.inventory["teardown_complete"] = False
                fixture.build()
                if mutation == "duplicate":
                    fixture.extra_terminal_pairs = [{"inventory": fixture.inventory_ref, "readback": fixture.readback_ref}]
                    fixture.build()
                with self.assertRaises(ValueError): budget.validate_amendment(fixture.request, root=self.root)

    def test_terminal_cost_pin_clock_and_priced_usage_cannot_be_claimed_away(self):
        for mutation in ("missingpin", "oldcostclock", "missingpricedtask", "underpricedtask", "notaccounted", "lateactualtask"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self.root)
                if mutation == "missingpin": fixture.drop_terminal_source_pin = True
                elif mutation == "oldcostclock": fixture.terminal_cost["as_of_utc"] = "2026-11-13T00:30:00Z"
                elif mutation == "missingpricedtask": fixture.terminal_cost["resources"]["tasks"].pop(fixture.old_arns[0])
                elif mutation == "underpricedtask": fixture.terminal_cost["resources"]["tasks"][fixture.old_arns[0]]["gib_hours"] = 0
                elif mutation == "notaccounted": fixture.terminal_cost["current_spend_accounted"] = False
                else: fixture.inventory["observed_tasks"][0]["stopped_at"] = "2026-11-13T02:30:00Z"
                fixture.build()
                with self.assertRaises(ValueError): budget.validate_amendment(fixture.request, root=self.root)

    def test_cumulative_limits_original_rates_and_actual_decision_remain_bound(self):
        for mutation in ("semantics", "ambiguousadditional", "wrongincrement", "capacity", "frozenexpiry", "nancap", "boolcap", "decision", "rates"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self.root)
                if mutation == "semantics": fixture.approval["budget_semantics"] = "fresh-reset"
                elif mutation == "ambiguousadditional": fixture.quote["requested_additional_total_usd"] = 30
                elif mutation == "wrongincrement": fixture.quote["requested_incremental_usd"] = 30
                elif mutation == "capacity": fixture.approval["max_vcpu"] = 8
                elif mutation == "frozenexpiry": fixture.approval["per_deployment_max_hours"] = 48
                elif mutation == "nancap": fixture.approval["approved_total_usd"] = float("nan")
                elif mutation == "boolcap": fixture.approval["approved_total_usd"] = True
                elif mutation == "decision": fixture.decision["user_statement"] = ""
                else: fixture.quote["rates"]["cpu"]["usd"] = ".001"
                fixture.build()
                with self.assertRaises(ValueError): budget.validate_amendment(fixture.request, root=self.root)

    def test_changed_bound_bytes_and_external_paths_fail_closed(self):
        path = self.root / self.f.terminal_ref["path"]
        path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hash_changed"): self.validate()
        with self.assertRaises(ValueError): budget.bound(self.root, {"path": "../outside.json", "sha256": "0" * 64})

    def test_only_exact_ancestor_terminal_cost_allows_retired_ecr_metadata(self):
        accepted = budget.accepts_predecessor_cost_report(self.f.request, self.f.terminal_cost_ref, root=self.root)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["authorization_sha256"], self.f.old_auth_ref["sha256"])
        with self.assertRaises(ValueError):
            budget.accepts_predecessor_cost_report(self.f.request, self.f.quote_cost_ref, root=self.root)
        inventories = {self.f.old_campaign: self.f.inventory}
        result, _ = merge_image_observations(self.f.request, inventories, retained=self.f.terminal_cost["aws_observations"],
            now=datetime(2026, 11, 14, tzinfo=timezone.utc))
        self.assertEqual(result["images"][0]["reference"], self.f.old_image)
        foreign = deepcopy(self.f.terminal_cost["aws_observations"])
        foreign["images"][0]["reference"] = foreign["images"][0]["reference"].replace(self.f.account, "999999999999")
        with self.assertRaisesRegex(ValueError, "owned_history"):
            merge_image_observations(self.f.request, inventories, retained=foreign, now=datetime(2026, 11, 14, tzinfo=timezone.utc))


if __name__ == "__main__": unittest.main()
