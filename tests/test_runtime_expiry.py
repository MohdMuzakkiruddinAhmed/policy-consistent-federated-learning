"""Cost backstop boundaries; no AWS credential discovery or SDK calls."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).resolve().parents[1] / "infra/terraform/runtime/expiry_cleanup.py"
SPEC = importlib.util.spec_from_file_location("runtime_expiry", SOURCE)
expiry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(expiry)


def fixture():
    cluster = "arn:aws:ecs:us-east-1:123456789012:cluster/pcfl-research-runtime"
    inventory = {"account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-research",
        "hard_expiry_utc": "2026-01-01T01:00:00Z", "cluster_arn": cluster,
        "service_arns": ["arn:aws:ecs:us-east-1:123456789012:service/pcfl-research-runtime/pcfl-research-" + role
                         for role in ("coordinator", "governance", "opa", "evaluation")],
        "vpc_id": "vpc-0123456789abcdef0", "interface_endpoint_ids": [f"vpce-{index:017x}" for index in range(1, 6)]}
    ecs, ec2 = Mock(), Mock()
    ecs.describe_clusters.return_value = {"clusters": [{"clusterArn": cluster,
        "tags": [{"key": "Project", "value": "pcfl-research"}, {"key": "Stage", "value": "runtime"}]}]}
    prefix = "arn:aws:ecs:us-east-1:123456789012:task/pcfl-research-runtime/"
    ecs.list_tasks.side_effect = [{"taskArns": [prefix + "1" * 32], "nextToken": "page-two"},
                                  {"taskArns": [prefix + "2" * 32]}]
    def endpoint(**kwargs):
        return {"VpcEndpoints": [{"VpcEndpointId": kwargs["VpcEndpointIds"][0], "VpcId": inventory["vpc_id"],
            "VpcEndpointType": "Interface", "State": "available", "Tags": [
                {"Key": "Project", "Value": inventory["project_id"]}, {"Key": "Stage", "Value": "runtime"}]}]}
    ec2.describe_vpc_endpoints.side_effect = endpoint
    ec2.delete_vpc_endpoints.return_value = {"Unsuccessful": []}
    return inventory, ecs, ec2


class RuntimeExpiryTests(unittest.TestCase):
    def test_recorded_inventory_only_and_cluster_paginated_stops(self):
        inventory, ecs, ec2 = fixture()
        result = expiry.cleanup(inventory, ecs, ec2)
        self.assertTrue(result["successful"])
        self.assertEqual(result["tasks_stopped"], 2)
        self.assertEqual(result["interface_endpoints_deleted"], 5)
        self.assertTrue(all(call.kwargs["cluster"] == inventory["cluster_arn"] for call in ecs.list_tasks.call_args_list))
        self.assertEqual(ecs.list_tasks.call_args_list[1].kwargs["nextToken"], "page-two")
        self.assertEqual({call.kwargs["VpcEndpointIds"][0] for call in ec2.delete_vpc_endpoints.call_args_list}, set(inventory["interface_endpoint_ids"]))
        self.assertEqual(ecs.update_service.call_count, 4)

    def test_early_invocation_and_rebound_cluster_are_rejected_before_mutations(self):
        inventory, ecs, ec2 = fixture()
        with self.assertRaisesRegex(ValueError, "before_recorded_expiry"):
            expiry.cleanup(inventory, ecs, ec2, now=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc))
        inventory["cluster_arn"] = inventory["cluster_arn"].replace("123456789012", "999999999999")
        with self.assertRaisesRegex(ValueError, "invalid_bound_cluster"):
            expiry.cleanup(inventory, ecs, ec2)
        ecs.update_service.assert_not_called()
        ec2.delete_vpc_endpoints.assert_not_called()

    def test_wrong_cluster_project_tags_block_cleanup(self):
        inventory, ecs, ec2 = fixture()
        ecs.describe_clusters.return_value["clusters"][0]["tags"] = [{"key": "Project", "value": "unrelated-project"}]
        with self.assertRaisesRegex(ValueError, "recorded_project_tags"):
            expiry.cleanup(inventory, ecs, ec2)
        ecs.update_service.assert_not_called()
        ec2.delete_vpc_endpoints.assert_not_called()

    def test_foreign_task_is_never_stopped_and_failures_do_not_return_success(self):
        inventory, ecs, ec2 = fixture()
        ecs.list_tasks.side_effect = [{"taskArns": ["arn:aws:ecs:us-east-1:123456789012:task/other-cluster/" + "a" * 32]}]
        with self.assertRaisesRegex(RuntimeError, "cleanup_incomplete"):
            expiry.cleanup(inventory, ecs, ec2)
        ecs.stop_task.assert_not_called()
        self.assertEqual(ec2.delete_vpc_endpoints.call_count, 5)

    def test_wrong_vpc_or_tags_never_delete_endpoint_and_partial_errors_raise(self):
        inventory, ecs, ec2 = fixture()
        def rebound(**kwargs):
            return {"VpcEndpoints": [{"VpcEndpointId": kwargs["VpcEndpointIds"][0], "VpcId": "vpc-other",
                "VpcEndpointType": "Interface", "Tags": []}]}
        ec2.describe_vpc_endpoints.side_effect = rebound
        with self.assertRaisesRegex(RuntimeError, "cleanup_incomplete"):
            expiry.cleanup(inventory, ecs, ec2)
        ec2.delete_vpc_endpoints.assert_not_called()

    def test_api_errors_are_retried_by_platform_instead_of_reported_as_success(self):
        inventory, ecs, ec2 = fixture()
        ecs.update_service.side_effect = TimeoutError("transient AWS API failure")
        ec2.delete_vpc_endpoints.return_value = {"Unsuccessful": [{"Error": {"Code": "UnauthorizedOperation"}}]}
        with self.assertRaisesRegex(RuntimeError, "cleanup_incomplete"):
            expiry.cleanup(inventory, ecs, ec2)

    def test_replay_after_endpoint_deletion_is_safe(self):
        inventory, ecs, ec2 = fixture()
        ec2.describe_vpc_endpoints.side_effect = None
        ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}
        self.assertTrue(expiry.cleanup(inventory, ecs, ec2)["successful"])
        ec2.delete_vpc_endpoints.assert_not_called()

    def test_prearmed_partial_bootstrap_with_zero_endpoints_or_tasks_succeeds(self):
        inventory, ecs, ec2 = fixture()
        inventory.pop("interface_endpoint_ids")
        inventory.update(provisional=True, allowed_endpoint_services=[f"com.amazonaws.us-east-1.{name}" for name in ("ecr.api", "ecr.dkr", "logs", "secretsmanager", "sts")])
        ec2.describe_vpc_endpoints.side_effect = None
        ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}
        ecs.list_tasks.side_effect = None
        ecs.list_tasks.return_value = {"taskArns": []}
        result = expiry.cleanup(inventory, ecs, ec2)
        self.assertTrue(result["successful"])
        self.assertEqual(result["interface_endpoints_deleted"], 0)
        filters = ec2.describe_vpc_endpoints.call_args.kwargs["Filters"]
        self.assertIn({"Name": "vpc-id", "Values": [inventory["vpc_id"]]}, filters)
        self.assertIn({"Name": "tag:Project", "Values": [inventory["project_id"]]}, filters)

    def test_prearmed_guard_rejects_another_vpc_or_project_even_if_returned_by_api(self):
        for field, value in (("VpcId", "vpc-unrelated"), ("ServiceName", "com.amazonaws.us-east-1.ec2")):
            inventory, ecs, ec2 = fixture()
            inventory.pop("interface_endpoint_ids")
            inventory.update(provisional=True, allowed_endpoint_services=[f"com.amazonaws.us-east-1.{name}" for name in ("ecr.api", "ecr.dkr", "logs", "secretsmanager", "sts")])
            row = {"VpcId": inventory["vpc_id"], "VpcEndpointId": "vpce-00000000000000001", "VpcEndpointType": "Interface",
                "ServiceName": "com.amazonaws.us-east-1.sts", "Tags": [{"Key": "Project", "Value": inventory["project_id"]},
                    {"Key": "Stage", "Value": "runtime"}, {"Key": "RuntimeVpcId", "Value": inventory["vpc_id"]}]}
            row[field] = value
            ec2.describe_vpc_endpoints.side_effect = None
            ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": [row]}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "unbound_provisional"):
                expiry.cleanup(inventory, ecs, ec2)
            ec2.delete_vpc_endpoints.assert_not_called()


if __name__ == "__main__":
    unittest.main()
