"""Read back this campaign's deployed expiry, private endpoints and machine alerts."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path


def inspect_controls(inventory, clients):
    contract = inventory["runtime_contract"]
    if clients["sts"].get_caller_identity()["Account"] != inventory["account_id"]:
        raise ValueError("cloud_controls_account_mismatch")
    cleanup = contract["automatic_cleanup"]
    schedules = []
    for arn in (cleanup["schedule_arn"], cleanup["provisional_schedule_arn"]):
        group, name = arn.split(":schedule/", 1)[1].split("/", 1)
        response = clients["scheduler"].get_schedule(Name=name, GroupName=group)
        configuration = clients["lambda"].get_function_configuration(FunctionName=response["Target"]["Arn"])
        schedules.append({"schedule_arn": arn, "state": response["State"], "expression": response["ScheduleExpression"],
            "function_arn": configuration["FunctionArn"], "function_state": configuration["State"],
            "last_update_status": configuration["LastUpdateStatus"], "target": response["Target"],
            "timezone": response.get("ScheduleExpressionTimezone"), "flexible_time_window": response.get("FlexibleTimeWindow"),
            "action_after_completion": response.get("ActionAfterCompletion"),
            "function_code_sha256": configuration.get("CodeSha256"), "function_role": configuration.get("Role")})
    endpoints = clients["ec2"].describe_vpc_endpoints(VpcEndpointIds=list(contract["interface_endpoint_ids"].values()))["VpcEndpoints"]
    endpoint_checks = []
    for endpoint in endpoints:
        tags = {tag["Key"]: tag["Value"] for tag in endpoint.get("Tags", [])}
        endpoint_checks.append({"endpoint_id": endpoint["VpcEndpointId"], "state": endpoint["State"],
            "private_dns_enabled": endpoint["PrivateDnsEnabled"], "expected_vpc": endpoint["VpcId"] == contract["vpc_id"],
            "expected_project_tags": tags.get("Project") == inventory["project_id"] and tags.get("Stage") == "runtime"})
    alerts = contract["machine_cost_alerts"]
    queue = clients["sqs"].get_queue_attributes(QueueUrl=alerts["queue_url"], AttributeNames=["QueueArn", "SqsManagedSseEnabled"])["Attributes"]
    subscriptions = clients["sns"].list_subscriptions_by_topic(TopicArn=alerts["sns_topic_arn"])["Subscriptions"]
    confirmed = any(item["Protocol"] == "sqs" and item["Endpoint"] == queue["QueueArn"]
        and item["SubscriptionArn"].startswith("arn:aws:sns:") for item in subscriptions)
    notifications = clients["budgets"].describe_notifications_for_budget(AccountId=inventory["account_id"], BudgetName=alerts["budget_name"])["Notifications"]
    expected_notification = {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
                             "Threshold": 80, "ThresholdType": "PERCENTAGE"}
    subscribers = clients["budgets"].describe_subscribers_for_notification(AccountId=inventory["account_id"],
        BudgetName=alerts["budget_name"], Notification=expected_notification)["Subscribers"]
    actual80 = (any(item["NotificationType"] == "ACTUAL" and item["Threshold"] == 80 for item in notifications)
        and any(item["SubscriptionType"] == "SNS" and item["Address"] == alerts["sns_topic_arn"] for item in subscribers))
    checks = {"two_enabled_active_expiry_backstops": len(schedules) == 2 and all(item["state"] == "ENABLED"
        and item["function_state"] == "Active" and item["last_update_status"] == "Successful" for item in schedules),
        "five_owned_available_private_interface_endpoints": len(endpoint_checks) == 5 and all(item["state"] == "available"
            and item["private_dns_enabled"] and item["expected_vpc"] and item["expected_project_tags"] for item in endpoint_checks),
        "machine_budget_subscription_confirmed": confirmed and actual80 and queue.get("SqsManagedSseEnabled") == "true"}
    return {"schema_version": "0.1.0", "campaign_id": inventory["campaign_id"], "account_id": inventory["account_id"],
        "region": inventory["region"], "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "successful": all(checks.values()), "checks": checks, "schedules": schedules, "endpoints": endpoint_checks,
        "machine_alert_evidence": {"queue": queue, "subscriptions": subscriptions, "notifications": notifications,
            "subscribers": subscribers, "expected_topic_arn": alerts["sns_topic_arn"], "budget_name": alerts["budget_name"],
            "subscribers_query_notification": expected_notification},
        "cost_alert_billing_delivery_observed": False, "human_notifications_configured": False,
        "performed_read_only": True, "limitations": ["Configured active controls do not prove future cleanup API success or a hard billing cap",
            "No budget threshold notification has been observed; this check confirms the machine subscription"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", default="reports/cloud_controls_validation.json")
    args = parser.parse_args()
    inventory = json.loads(Path(args.inventory).read_text())
    import boto3
    from botocore.config import Config
    clients = {service: boto3.client(service, region_name=inventory["region"], config=Config(ignore_configured_endpoint_urls=True))
               for service in ("sts", "scheduler", "lambda", "ec2", "sqs", "sns", "budgets")}
    report = inspect_controls(inventory, clients)
    Path(args.output).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"successful": report["successful"], "checks": report["checks"]}, indent=2))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
