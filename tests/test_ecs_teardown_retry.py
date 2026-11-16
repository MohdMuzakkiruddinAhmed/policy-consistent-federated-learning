"""Exact missing ECS resources are retryable; unknown/live resources are not."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
from botocore.exceptions import ClientError, EndpointConnectionError
import aws_campaign as campaign
from test_aws_campaign import clients, contract, request, stopped_task
import cloud_io


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "synthetic exact-resource response"}}, "UpdateService")


class ECSTeardownRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = patch.object(campaign, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.aws, self.sleep = clients(), Mock()
        self.runner = campaign.CampaignRunner(request(self.root), clients=self.aws, sleep=self.sleep)
        self.cluster = contract()["cluster_arn"]
        self.service = "pcfl-test-evaluation"
        runtime = contract()
        runtime["service_names"] = {"evaluation": self.service}
        prior = cloud_io.task_evidence(stopped_task(), "123456789012", "us-east-1", self.cluster)
        self.arn = prior["task_arn"]
        self.runner.inventory.update(runtime_contract=runtime, task_arns=[self.arn], observed_tasks=[prior])
        self.aws["ecs"].list_tasks.return_value = {"taskArns": []}
        self.aws["ecs"].describe_tasks.return_value = {"tasks": [], "failures": [{"arn": self.arn, "reason": "MISSING"}]}

    def absent_cluster(self, *, inactive=False):
        self.aws["ecs"].describe_clusters.return_value = ({"clusters": [{"clusterArn": self.cluster, "status": "INACTIVE",
            "runningTasksCount": 0, "pendingTasksCount": 0, "activeServicesCount": 0, "registeredContainerInstancesCount": 0}], "failures": []}
            if inactive else {"clusters": [], "failures": [{"arn": self.cluster, "reason": "MISSING"}]})

    def test_service_not_found_requires_exact_independent_missing_description(self):
        self.aws["ecs"].update_service.side_effect = error("ServiceNotFoundException")
        self.aws["ecs"].describe_services.return_value = {"services": [], "failures": [{"arn": self.service, "reason": "MISSING"}]}
        before = deepcopy(self.runner.inventory["observed_tasks"][0])
        self.runner.stop_recorded()
        self.assertTrue(self.runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertEqual(self.runner.inventory["observed_tasks"][0]["stopped_at"], before["stopped_at"])
        self.assertTrue(self.runner.inventory["observed_tasks"][0]["historical_only"])
        self.aws["ecs"].describe_services.assert_called_once_with(cluster=self.cluster, services=[self.service])
        self.aws["ecs"].stop_task.assert_not_called()
        self.assertGreater(self.runner.inventory["fleet_ledger"][self.arn]["vcpu_hours"], 0)

    def test_service_missing_accepts_its_exact_scoped_service_arn(self):
        self.aws["ecs"].update_service.side_effect = error("ServiceNotFoundException")
        service_arn = self.cluster.replace(":cluster/", ":service/") + "/" + self.service
        self.aws["ecs"].describe_services.return_value = {"services": [], "failures": [{"arn": service_arn, "reason": "MISSING"}]}
        self.runner.stop_recorded()
        self.assertTrue(self.runner.inventory["shutdown_confirmation"]["confirmed"])

    def test_deleted_cluster_error_requires_exact_missing_confirmation(self):
        self.aws["ecs"].update_service.side_effect = error("ClusterNotFoundException")
        self.aws["ecs"].list_tasks.side_effect = error("ClusterNotFoundException")
        self.absent_cluster()
        self.runner.stop_recorded()
        self.assertTrue(self.runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertEqual(self.runner.inventory["removed_runtime_cluster_confirmation"]["status"], "MISSING")
        for call in self.aws["ecs"].describe_clusters.call_args_list:
            self.assertEqual(call.kwargs, {"clusters": [self.cluster]})
        self.aws["ecs"].describe_tasks.assert_not_called()
        self.assertIn(self.arn, self.runner.inventory["shared_fleet_ledger"])

    def test_deleted_inactive_cluster_zero_counts_is_explicitly_confirmed(self):
        self.aws["ecs"].update_service.side_effect = error("ClusterNotFoundException")
        self.aws["ecs"].describe_tasks.side_effect = error("ClusterNotFoundException")
        self.absent_cluster(inactive=True)
        self.runner.stop_recorded()
        self.assertTrue(self.runner.inventory["shutdown_confirmation"]["confirmed"])
        self.assertEqual(self.runner.inventory["removed_runtime_cluster_confirmation"]["status"], "INACTIVE")
        self.assertTrue(self.runner.inventory["observed_tasks"][0]["historical_only"])

    def test_service_then_cluster_not_found_has_independent_cluster_confirmation(self):
        self.aws["ecs"].update_service.side_effect = error("ServiceNotFoundException")
        self.aws["ecs"].describe_services.side_effect = error("ClusterNotFoundException")
        self.absent_cluster()
        self.runner.stop_recorded()
        self.assertTrue(self.runner.inventory["shutdown_confirmation"]["confirmed"])

    def test_unknown_update_errors_are_never_converted_to_absence(self):
        for cause in (error("AccessDeniedException"), error("ClientException"),
                      EndpointConnectionError(endpoint_url="https://ecs.invalid"), RuntimeError("ServiceNotFoundException")):
            with self.subTest(cause=type(cause).__name__):
                self.aws["ecs"].update_service.side_effect = cause
                with self.assertRaisesRegex(RuntimeError, "service:evaluation"):
                    self.runner.stop_recorded()
                self.assertFalse(self.runner.inventory["shutdown_confirmation"]["confirmed"])
        self.aws["ecs"].describe_services.assert_not_called()
        self.aws["ecs"].describe_clusters.assert_not_called()

    def test_empty_foreign_or_live_service_response_is_not_missing(self):
        self.aws["ecs"].update_service.side_effect = error("ServiceNotFoundException")
        for response in ({"services": [], "failures": []},
                         {"services": [], "failures": [{"arn": "foreign-service", "reason": "MISSING"}]},
                         {"services": [{"serviceName": self.service, "status": "ACTIVE"}], "failures": []}):
            with self.subTest(response=response):
                self.aws["ecs"].describe_services.return_value = response
                with self.assertRaisesRegex(RuntimeError, "service:evaluation"):
                    self.runner.stop_recorded()

    def test_unknown_confirmation_failure_keeps_shutdown_failed(self):
        self.aws["ecs"].update_service.side_effect = error("ServiceNotFoundException")
        self.aws["ecs"].describe_services.side_effect = error("AccessDeniedException")
        with self.assertRaisesRegex(RuntimeError, "service:evaluation"):
            self.runner.stop_recorded()
        self.assertFalse(self.runner.inventory["shutdown_confirmation"]["confirmed"])

    def test_foreign_active_nonzero_or_incomplete_cluster_confirmation_fails(self):
        self.aws["ecs"].list_tasks.side_effect = error("ClusterNotFoundException")
        for response in ({"clusters": [], "failures": []},
                         {"clusters": [], "failures": [{"arn": self.cluster+"-foreign", "reason": "MISSING"}]},
                         {"clusters": [{"clusterArn": self.cluster, "status": "ACTIVE"}], "failures": []},
                         {"clusters": [{"clusterArn": self.cluster, "status": "INACTIVE", "runningTasksCount": 1,
                            "pendingTasksCount": 0, "activeServicesCount": 0, "registeredContainerInstancesCount": 0}], "failures": []}):
            with self.subTest(response=response):
                self.aws["ecs"].describe_clusters.return_value = response
                with self.assertRaises(ClientError):
                    self.runner.observed_tasks()

    def test_unobserved_accepted_task_cannot_be_declared_stopped_by_cluster_absence(self):
        self.aws["ecs"].list_tasks.side_effect = error("ClusterNotFoundException")
        self.absent_cluster()
        self.runner.inventory["observed_tasks"] = []
        with self.assertRaisesRegex(RuntimeError, "unconfirmed_recorded_tasks"):
            self.runner.observed_tasks()

    def test_prior_running_or_uncertain_launch_remains_unconfirmed(self):
        self.aws["ecs"].list_tasks.side_effect = error("ClusterNotFoundException")
        self.absent_cluster()
        self.runner.inventory["observed_tasks"][0]["last_status"] = "RUNNING"
        with self.assertRaisesRegex(RuntimeError, "unconfirmed_recorded_tasks"):
            self.runner.observed_tasks()
        self.runner.inventory["observed_tasks"][0]["last_status"] = "STOPPED"
        self.runner.inventory["task_observation_history"] = {}
        self.runner.inventory["launch_intents"] = {"pending-token": {"state": "issuing"}}
        with self.assertRaisesRegex(RuntimeError, "unconfirmed_recorded_tasks"):
            self.runner.observed_tasks()

    def test_observation_access_denied_and_transport_error_still_propagate(self):
        for cause in (error("AccessDeniedException"), EndpointConnectionError(endpoint_url="https://ecs.invalid")):
            self.aws["ecs"].list_tasks.side_effect = cause
            with self.assertRaises(type(cause)):
                self.runner.observed_tasks()
        self.aws["ecs"].describe_clusters.assert_not_called()


if __name__ == "__main__":
    unittest.main()
