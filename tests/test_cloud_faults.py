"""Bounded restart orchestration tests; SDK boundaries are mocked."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cloud_faults


def fixture():
    spec = {"request_id": "restart-one", "org_id": "org_03", "run_id": "run-one", "phase": "between-rounds", "round_id": "round-2"}
    runner = Mock()
    runner.request = {"host_restarts": [spec]}
    runner.inventory = {"runtime_generation": "g" * 64, "runtime_contract": {"cluster_arn": "recorded-cluster"}, "foundation": {"state_table_name": "recorded-table"}}
    runner.application_id.return_value = "application-one"
    clients = {"ecs": Mock(), "dynamodb": Mock()}
    runner.sdk.return_value = clients
    marker = {**{field: {"S": value} for field, value in spec.items()}, "kind": {"S": "client_restart"}, "status": {"S": "READY"}}
    clients["dynamodb"].get_item.return_value = {"Item": marker}
    before = [{"task_arn": "task-" + name, "private_ip": "10.1.0." + str(index), "last_status": "RUNNING", "effective_commands": {name: ["client"]}}
              for index, name in enumerate(sorted(cloud_faults.ORGS), 10)]
    stopped = deepcopy(before)
    stopped[2]["last_status"] = "STOPPED"
    after = deepcopy(before)
    after[2].update(task_arn="new-task-org_03", private_ip="10.1.0.30")
    runner.start_task.return_value = "new-task-org_03"
    runner.budget_check.side_effect = [stopped, after]
    return runner, clients, spec, marker, before, stopped, after


class RestartTests(unittest.TestCase):
    def test_only_explicit_bounded_unique_controls_are_accepted(self):
        spec = fixture()[2]
        self.assertEqual(cloud_faults.validate_restarts([spec]), [spec])
        for invalid in ([spec, spec], [{**spec, "org_id": "org_99"}], [{**spec, "run_id": "../foreign"}],
                        [{**spec, "extra": True}], [{**spec, "phase": "before-case"}], [spec] * 33):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cloud_faults.validate_restarts(invalid)

    def test_missing_control_causes_no_stop_launch_or_ack(self):
        runner, clients, _, _, before, _, _ = fixture()
        clients["dynamodb"].get_item.return_value = {}
        cloud_faults.handle_client_restarts(runner, before)
        clients["ecs"].stop_task.assert_not_called()
        runner.start_task.assert_not_called()
        clients["dynamodb"].update_item.assert_not_called()

    def test_replacement_and_seven_unchanged_peers_precede_conditional_ack(self):
        runner, clients, spec, _, before, _, after = fixture()
        order = []
        clients["ecs"].stop_task.side_effect = lambda **kwargs: order.append("stop")
        runner.start_task.side_effect = lambda *args, **kwargs: order.append("start") or "new-task-org_03"
        def acknowledge(**kwargs):
            order.append("ack")
            values = kwargs["ExpressionAttributeValues"]
            clients["dynamodb"].get_item.return_value["Item"].update(status={"S": "ACKNOWLEDGED"}, completed={"BOOL": True},
                old_task_arn_sha256=values[":old"], new_task_arn_sha256=values[":new"])
        clients["dynamodb"].update_item.side_effect = acknowledge
        snapshots = [{"snapshot_sha256": "before"}, {"snapshot_sha256": "after"}]
        with patch("validate_cloud_placement.capture_placement", side_effect=snapshots), patch("validate_cloud_placement.validate_snapshot", return_value={"actual": True}):
            cloud_faults.handle_client_restarts(runner, before)
        self.assertEqual(order, ["stop", "start", "ack"])
        runner.start_task.assert_called_once_with("org_03", launch_intent="host-restart:restart-one")
        event = runner.inventory["client_restart_events"]["restart-one"]
        self.assertTrue(event["completed"])
        self.assertEqual(event["before_snapshot"], snapshots[0])
        self.assertEqual(event["after_snapshot"], snapshots[1])
        self.assertEqual(event["control_acknowledged"]["status"], {"S": "ACKNOWLEDGED"})
        ack = clients["dynamodb"].update_item.call_args.kwargs
        self.assertEqual(ack["Key"], {"PK": {"S": "RUN#run-one"}, "SK": {"S": "CONTROL#HOST_RESTART#restart-one"}})
        self.assertIn("#status = :ready", ack["ConditionExpression"])
        self.assertEqual(ack["ExpressionAttributeValues"][":old"], {"S": hashlib.sha256(b"task-org_03").hexdigest()})
        self.assertEqual(ack["ExpressionAttributeValues"][":new"], {"S": hashlib.sha256(b"new-task-org_03").hexdigest()})

    def test_peer_disruption_fails_without_ack(self):
        runner, clients, _, _, before, stopped, _ = fixture()
        stopped[0]["last_status"] = "STOPPED"
        runner.budget_check.side_effect = [stopped]
        with patch("validate_cloud_placement.capture_placement", return_value={}), patch("validate_cloud_placement.validate_snapshot", return_value={"actual": True}), self.assertRaisesRegex(RuntimeError, "seven_peer"):
            cloud_faults.handle_client_restarts(runner, before)
        runner.start_task.assert_not_called()
        clients["dynamodb"].update_item.assert_not_called()

    def test_replayed_old_launch_or_unverified_after_snapshot_never_ack(self):
        for replay in (True, False):
            runner, clients, _, _, before, _, _ = fixture()
            if replay:
                runner.start_task.return_value = "task-org_03"
            with patch("validate_cloud_placement.capture_placement", return_value={}), patch("validate_cloud_placement.validate_snapshot", side_effect=[{"actual": True}, {"actual": False}]), self.assertRaises(RuntimeError):
                cloud_faults.handle_client_restarts(runner, before)
            clients["dynamodb"].update_item.assert_not_called()

    def test_foreign_marker_and_unattributed_ack_never_stop_tasks(self):
        for change in ({"org_id": {"S": "org_08"}}, {"status": {"S": "ACKNOWLEDGED"}, "completed": {"BOOL": True}}):
            runner, clients, _, marker, before, _, _ = fixture()
            marker.update(change)
            with self.assertRaises(ValueError):
                cloud_faults.handle_client_restarts(runner, before)
            clients["ecs"].stop_task.assert_not_called()
            clients["dynamodb"].update_item.assert_not_called()

    def test_timeout_leaves_marker_unacknowledged(self):
        runner, clients, _, _, before, _, _ = fixture()
        runner.budget_check.side_effect = [before]
        with patch("validate_cloud_placement.capture_placement", return_value={}), patch("validate_cloud_placement.validate_snapshot", return_value={"actual": True}), self.assertRaisesRegex(RuntimeError, "stop_timeout"):
            cloud_faults.handle_client_restarts(runner, before, monotonic=Mock(side_effect=[0, 280]))
        runner.start_task.assert_not_called()
        clients["dynamodb"].update_item.assert_not_called()

    def test_retained_restart_replays_both_snapshots_peer_identity_and_control_hashes(self):
        from test_cloud_placement import snapshot
        import validate_cloud_placement as placement
        spec = fixture()[2]
        before, after = snapshot(), snapshot()
        target = next(row for row in after["tasks"] if row["name"] == "org_03")
        old_arn = target["task_arn"]
        target["task_arn"] = "new-task-org_03"
        after["snapshot_sha256"] = placement.sha({key: value for key, value in after.items() if key != "snapshot_sha256"})
        control = {**{field: {"S": value} for field, value in spec.items()}, "PK": {"S": "RUN#run-one"},
                   "SK": {"S": "CONTROL#HOST_RESTART#restart-one"}, "kind": {"S": "client_restart"}, "status": {"S": "READY"}}
        ack = {**control, "status": {"S": "ACKNOWLEDGED"}, "completed": {"BOOL": True},
            "old_task_arn_sha256": {"S": hashlib.sha256(old_arn.encode()).hexdigest()},
            "new_task_arn_sha256": {"S": hashlib.sha256(b"new-task-org_03").hexdigest()}}
        event = {"spec": spec, "application_campaign_id": "campaign-one", "runtime_generation": before["runtime_generation"], "completed": True,
            "before_snapshot": before, "after_snapshot": after, "old_task_arn": old_arn, "new_task_arn": "new-task-org_03",
            "control_ready": control, "control_acknowledged": ack}
        inventory = {"campaign_id": "campaign-one", "runtime_generation": before["runtime_generation"],
            "runtime_contract": {"cluster_arn": before["cluster_arn"], "task_role_arns": before["expected_roles"]},
            "host_restart_requests_by_application": {"campaign-one": [spec]}, "client_restart_events": {spec["request_id"]: event}}
        self.assertTrue(cloud_faults.validate_restart_evidence(inventory)["successful"])
        for kind in ("changed-peer", "wrong-control-hash", "wrong-key", "different-application"):
            changed = deepcopy(inventory)
            altered = changed["client_restart_events"][spec["request_id"]]
            if kind == "changed-peer":
                altered["after_snapshot"]["tasks"][0]["task_arn"] = "another-peer-task"
                altered["after_snapshot"]["snapshot_sha256"] = placement.sha({key: value for key, value in altered["after_snapshot"].items() if key != "snapshot_sha256"})
            elif kind == "wrong-control-hash":
                altered["control_acknowledged"]["new_task_arn_sha256"] = {"S": "a" * 64}
            elif kind == "wrong-key":
                altered["control_ready"]["PK"] = {"S": "RUN#unrelated"}
            else:
                altered["application_campaign_id"] = "other-application"
            with self.subTest(kind=kind):
                self.assertFalse(cloud_faults.validate_restart_evidence(changed)["successful"])


if __name__ == "__main__":
    unittest.main()
