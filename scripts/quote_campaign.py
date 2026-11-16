"""Prepare a bounded full-campaign cost proposal from public AWS prices; no AWS API."""

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonECS/current/us-east-1/index.json"


def main():
    with urlopen(CATALOG, timeout=30) as response:
        raw = response.read(30_000_001)
    if len(raw) > 30_000_000:
        raise ValueError("price_catalog_size_limit")
    catalog = json.loads(raw)
    rates = {}
    for sku, product in catalog["products"].items():
        attributes = product.get("attributes", {})
        usage = attributes.get("usagetype", "")
        label = "cpu" if usage == "USE1-Fargate-vCPU-Hours:perCPU" else "memory" if usage == "USE1-Fargate-GB-Hours" else None
        if label is None:
            continue
        terms = catalog["terms"]["OnDemand"].get(sku, {})
        if len(terms) != 1:
            raise ValueError("ambiguous_fargate_price")
        term = next(iter(terms.values()))
        dimensions = term["priceDimensions"]
        if len(dimensions) != 1:
            raise ValueError("ambiguous_price_dimensions")
        rate = next(iter(dimensions.values()))
        if label in rates:
            raise ValueError("duplicate_fargate_price")
        rates[label] = {"sku": sku, "effective_date": term["effectiveDate"], "usd": rate["pricePerUnit"]["USD"], "unit": rate["unit"]}
    if set(rates) != {"cpu", "memory"}:
        raise ValueError("linux_x86_on_demand_prices_missing")
    hours, cpu, memory, endpoints = Decimal(32), Decimal(4), Decimal(14), Decimal(5)
    compute = hours * (cpu * Decimal(rates["cpu"]["usd"]) + memory * Decimal(rates["memory"]["usd"]))
    endpoint_hours = hours * endpoints * Decimal("0.01")
    allowances = {"endpoint_data_processing_up_to_30GB": "0.30", "secrets_and_api_calls": "0.60",
                  "two_private_dns_namespaces_and_discovery": "1.10", "ECR_storage": "0.30",
                  "S3_storage_requests_and_export": "1.00", "DynamoDB_requests_storage_backup": "2.00",
                  "bounded_masked_logs": "1.00", "scheduler_lambda_SQS_and_monitoring": "0.20"}
    subtotal = compute + endpoint_hours + sum(Decimal(value) for value in allowances.values())
    proposal = {"schema_version": "0.1.0", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "account_id": "980322232249", "region": "us-east-1", "approval_status": "awaiting-user-authorization",
        "authorization_scope": "remaining-phases-cloud-campaign-including-replication",
        "requested_additional_total_usd": 20, "earlier_smoke_budget_is_separate": True,
        "maximum_cumulative_fleet_hours": 32, "maximum_concurrent_vcpu": 4, "maximum_concurrent_memory_gib": 14,
        "maximum_interface_endpoints_per_fleet": 5, "availability_zones": 1,
        "per_deployment_hard_expiry_hours": 24, "maximum_primary_runs": 160,
        "targeted_ablation_replication_runs": 98, "additional_validation_runs": "bounded by same cumulative resource-hours",
        "rates": rates, "fargate_allowance_usd": float(compute), "interface_endpoint_hours_allowance_usd": float(endpoint_hours),
        "other_allowances_usd": {key: float(value) for key, value in allowances.items()},
        "estimated_bounded_total_usd": float(subtotal), "contingency_to_requested_cap_usd": float(Decimal(20)-subtotal),
        "sources": {"Fargate_catalog": CATALOG, "PrivateLink": "https://aws.amazon.com/privatelink/pricing/",
            "Secrets_Manager": "https://aws.amazon.com/secrets-manager/pricing/", "Cloud_Map": "https://aws.amazon.com/cloud-map/pricing/"},
        "catalog_sha256": hashlib.sha256(raw).hexdigest(),
        "containment": ["one project VPC; no NAT, load balancers or public IPs",
            "private S3/DynamoDB gateway endpoints and five metered interface endpoints",
            "one-shot AWS cleanup stops own ECS tasks/services and deletes recorded metered endpoints at expiry",
            "local inventory refuses runs that exceed cumulative resource-hour allowance",
            "export evidence, destroy both recorded stacks and verify teardown",
            "record failed attempts; stop for a new spending decision if the approved budget is insufficient"],
        "limitations": ["Planning allowance, not an invoice or hard AWS billing cap; billing data can be delayed",
            "Other-service amounts are conservative allowances, not per-request quotes",
            "Main/targeted work is phase-gated; 258 planned cells are not asserted completed",
            "No Free Tier or promotional credits assumed; no cloud resources created by this script"]}
    if subtotal >= 20:
        raise ValueError("cost_proposal_exceeds_requested_cap")
    directory = ROOT / "results/aws/pricing"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "AmazonECS-us-east-1.json").write_bytes(raw)
    (ROOT / "reports/campaign_cost_proposal.json").write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8")
    lines = ["# Remaining-phase cloud cost proposal", "",
        "Account `980322232249`, region `us-east-1`. Awaiting authorization for **$20 additional total** for the remaining cloud work. The completed first-smoke authorization is separate.", "",
        "The prepared topology has eight client tasks, a coordinator, governance, OPA and evaluator, plus bounded access probes. It uses one private subnet/AZ, five interface endpoints and S3/DynamoDB gateway endpoints. It creates no NAT gateway, public task IP or load balancer.", "",
        "| Bounded resource | Planning amount (USD) |", "|---|---:|",
        f"| Up to 32 cumulative fleet-hours, at most 4 vCPU/14 GiB concurrently | {compute:.4f} |",
        f"| Five interface endpoints for the same cumulative hours | {endpoint_hours:.2f} |"]
    lines += [f"| {key.replace('_', ' ')} | {value} |" for key, value in allowances.items()]
    lines += [f"| Estimated bounded total | {subtotal:.4f} |", f"| Contingency within $20 requested cap | {Decimal(20)-subtotal:.4f} |", "",
        "The Fargate amounts use the [current AWS regional price catalog](" + CATALOG + ") saved with its checksum in the JSON proposal. The interface endpoint planning rate is $0.01/endpoint-hour from the [AWS PrivateLink US-East-1 example](https://aws.amazon.com/privatelink/pricing/). Other services use stated allowances; actual charges must be reconciled.", "",
        "The campaign covers the 160-cell primary matrix plus 98 planned targeted, ablation and fresh-deployment replication cells, subject to the same resource-hour allowance and accepted phase gates. No final holdout is unlocked by this proposal.", "",
        "Each deployment has an explicit expiry of at most 24 hours. A scoped AWS cleanup stops this project's compute and deletes its recorded charged endpoints even if the local runner disappears. Normal teardown exports evidence, removes both recorded stacks and verifies the inventory. Billing monitors are delayed alerts, not hard spending enforcement. Stop and obtain a new spending decision before extending any bound.", ""]
    (ROOT / "reports/campaign_cost_proposal.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"requested_additional_total_usd": 20, "estimated_bounded_total_usd": float(subtotal), "approval_status": proposal["approval_status"]}, indent=2))


if __name__ == "__main__":
    main()
