"""Bounded restart/transport-injection boundaries; no AWS or clinical rows."""
from copy import deepcopy
import hashlib
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

from botocore.exceptions import ClientError

from pcfl.runtime_faults import AuditTransportGate, host_restart_barrier, validate_host_restart
from pcfl import service_runtime
import test_integrated_runtime as integrated
from pcfl.flower_app import run_server


class RuntimeFaultTests(unittest.TestCase):
    def spec(self):
        return {"request_id": "restart-1", "org_id": "org_01", "run_id": "run-1", "phase": "between-rounds", "round_id": "round-2"}

    def test_host_restart_requires_exact_run_phase_and_bounded_completion(self):
        spec = self.spec()
        self.assertEqual(validate_host_restart(spec, "run-1", scenario="S7", rounds=2), spec)
        for fields in ({"run_id": "other"}, {"org_id": "org_09"}, {"round_id": "round-1"}, {"extra": True}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate_host_restart({**spec, **fields}, "run-1", scenario="S7", rounds=2)
        ddb = Mock()
        def ack(**_):
            request = ddb.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"]
            return {"Item": {**request, "status": {"S": "ACKNOWLEDGED"}, "completed": {"BOOL": True},
                "old_task_arn_sha256": {"S": "a" * 64}, "new_task_arn_sha256": {"S": "b" * 64}}}
        ddb.get_item.side_effect = ack
        trace = host_restart_barrier(ddb, "test-state", spec, timeout=1)
        self.assertTrue(trace["completed"])
        self.assertEqual(ddb.get_item.call_args.kwargs["Key"]["SK"]["S"], "CONTROL#HOST_RESTART#restart-1")
        self.assertTrue(ddb.get_item.call_args.kwargs["ConsistentRead"])
        self.assertIn("attribute_not_exists", ddb.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["ConditionExpression"])

    def test_host_restart_wrong_ack_and_missing_host_are_not_success(self):
        for mode in ("rebound", "same-task", "timeout"):
            ddb = Mock()
            def saved(**_):
                item = deepcopy(ddb.transact_write_items.call_args.kwargs["TransactItems"][0]["Put"]["Item"])
                if mode != "timeout":
                    item.update(status={"S": "ACKNOWLEDGED"}, completed={"BOOL": True},
                        old_task_arn_sha256={"S": "a" * 64}, new_task_arn_sha256={"S": "a" * 64 if mode == "same-task" else "b" * 64})
                    if mode == "rebound": item["run_id"] = {"S": "other-run"}
                return {"Item": item}
            ddb.get_item.side_effect = saved
            with self.subTest(mode=mode), self.assertRaises((ValueError, TimeoutError)):
                host_restart_barrier(ddb, "test-state", self.spec(), timeout=.01)

    def test_audit_transport_gate_only_blocks_real_audit_dispatch_and_recovers(self):
        client = Mock()
        gate = AuditTransportGate(client)
        audit = {"TransactItems": [{"Put": {"Item": {"SK": {"S": "AUDIT#0001"}}}}]}
        ordinary = {"TransactItems": [{"Put": {"Item": {"SK": {"S": "MANIFEST#id"}}}}]}
        gate.armed = True
        with self.assertRaisesRegex(OSError, "before_dispatch"):
            gate.transact_write_items(**audit)
        client.transact_write_items.assert_not_called()
        gate.transact_write_items(**ordinary)
        self.assertEqual(gate.blocked_calls, 1)
        gate.armed = False
        gate.transact_write_items(**audit)
        self.assertEqual(client.transact_write_items.call_count, 2)

    def test_existing_anchor_conditional_probe_accepts_access_denial_only(self):
        owner = "123456789012"
        for code in ("AccessDenied", "PreconditionFailed"):
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "own.json"; path.write_text("synthetic")
                ddb, s3, sts = Mock(), Mock(), Mock()
                ddb.put_item.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "PutItem")
                s3.put_object.side_effect = ClientError({"Error": {"Code": code}}, "PutObject")
                sts.get_caller_identity.return_value = {"Arn": "arn:aws:sts::123456789012:assumed-role/coordinator/session"}
                reference = {"bucket": "synthetic", "key": "metadata/model.json", "version_id": "v1", "sha256": "a" * 64}
                config = {"storage": {"expected_account_id": owner, "region": "us-east-1"}, "bucket": "synthetic",
                    "table_name": "test-state", "role_kind": "coordinator", "allowed_object": reference, "denied_objects": [],
                    "expected_task_role_arn": "arn:aws:iam::123456789012:role/coordinator",
                    "protected_anchor_object": {**reference, "key": "anchors/existing.json"}}
                with patch.object(service_runtime, "sdk_clients", return_value=(ddb, s3)), \
                     patch.object(service_runtime, "fetch_pinned", return_value=str(path)), patch("boto3.client", return_value=sts):
                    if code == "AccessDenied":
                        self.assertTrue(service_runtime.probe_access(config)["anchor_write_denied"])
                    else:
                        with self.assertRaisesRegex(ValueError, "permission_not_denied"):
                            service_runtime.probe_access(config)
                request = s3.put_object.call_args.kwargs
                self.assertEqual(request["IfNoneMatch"], "*")
                self.assertEqual(request["ExpectedBucketOwner"], owner)
                self.assertEqual(request["Key"], "anchors/existing.json")
                self.assertEqual(request["ServerSideEncryption"], "AES256")


class RuntimeFactoryFaultBoundaries(unittest.TestCase):
    def setUp(self):
        integrated.IntegratedCoordinatorBoundaryTests.setUpClass()
        self.metadata = integrated.IntegratedCoordinatorBoundaryTests.metadata
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.grid = integrated.EightNodeGrid()

    def test_ambiguous_ablation_and_unbound_faults_fail_before_sdk_or_messages(self):
        for fields in ({"ablation_id": "Abl-1"}, {"authority_backend": "dynamodb-s3-ablation"},
                       {"authority_backend": "dynamodb-s3-ablation", "ablation_id": "Abl-2", "full_protocol": True},
                       {"scenario_id": "S7", "rounds": 2}, {"scenario_id": "S8", "rounds": 2},
                       {"scripted_fault": "opa_transport_unavailable"}):
            config = {**integrated.IntegratedCoordinatorBoundaryTests.configuration(self), **fields}
            with self.subTest(fields=fields), integrated.IntegratedCoordinatorBoundaryTests.service_boundaries(self) as state:
                with self.assertRaises(ValueError): run_server(self.grid, config)
                state.storage.assert_not_called()
                self.assertEqual(self.grid.messages_sent, 0)

    def test_explicit_ablation_uses_separate_factory_and_stays_validation_only(self):
        config = {**integrated.IntegratedCoordinatorBoundaryTests.configuration(self),
                  "authority_backend": "dynamodb-s3-ablation", "ablation_id": "Abl-1"}
        with integrated.IntegratedCoordinatorBoundaryTests.service_boundaries(self) as state:
            factory = state.authority_factory.side_effect
            with patch("pcfl.ablations.PersistentAblationAuthority", side_effect=factory) as ablation_factory:
                result = run_server(self.grid, config)
            self.assertEqual(ablation_factory.call_args.kwargs["ablation_id"], "Abl-1")
            state.authority_factory.assert_not_called()
        self.assertFalse(result["test_holdout_evaluated"])
        self.assertEqual(result["measurement_manifest"], {"schema_version": "0.1.0", "tamper_scope": "this-runtime-invocation",
            "tamper_mode": "none_declared", "tamper_results": []})

    def test_S7_consumption_replay_is_idempotent_after_bound_restart_ack(self):
        config = {**integrated.IntegratedCoordinatorBoundaryTests.configuration(self), "scenario_id": "S7", "rounds": 2,
            "host_restart": {"request_id": "restart-1", "org_id": "org_01", "run_id": "boundary-run", "phase": "between-rounds", "round_id": "round-2"}}
        with integrated.IntegratedCoordinatorBoundaryTests.service_boundaries(self), \
             patch("pcfl.runtime_faults.host_restart_barrier", return_value={"completed": True}) as restart:
            result = run_server(self.grid, config)
        restart.assert_called_once()
        self.assertTrue(result["successful"])
        self.assertEqual(len(result["updates"]), 16)
        self.assertEqual(len(result["decisions"]), 16)
        self.assertEqual(sum(record["kind"] == "duplicate_idempotent_receipt" for record in result["fault_trace"]), 2)
        self.assertEqual(sum(len(manifest["included_update_ids"]) for manifest in result["published_manifests"]), 16)

    def test_S8_fault_failure_preserves_prior_commit_and_explicit_recovery_counts(self):
        for kind in ("opa_transport_unavailable", "audit_transport_unavailable"):
            self.grid = integrated.EightNodeGrid()
            config = {**integrated.IntegratedCoordinatorBoundaryTests.configuration(self), "scenario_id": "S8", "rounds": 2,
                      "scripted_fault": kind, "output_dir": str(self.output / kind)}
            with self.subTest(kind=kind), integrated.IntegratedCoordinatorBoundaryTests.service_boundaries(self) as state:
                state.storage.return_value = (Mock(), object())
                state.opa.endpoint = "https://opa.invalid"
                def policy(*_):
                    if state.opa.endpoint == "https://127.0.0.1:1": raise URLError("synthetic-transport-boundary")
                    return {"valid": True}
                state.opa.evaluate.side_effect = policy
                original_factory = state.authority_factory.side_effect
                def factory(ddb, s3, **options):
                    authority = original_factory(ddb, s3, **options)
                    ordinary = authority.publish
                    def publish(round_id, **kwargs):
                        if round_id == "round-2":
                            if kind == "audit_transport_unavailable":
                                ddb.transact_write_items(TransactItems=[{"Put": {"Item": {"SK": {"S": "AUDIT#synthetic"}}}}])
                            else:
                                options["policy_evaluator"]([], {"org_id": "org_01", "start_order": 1, "commit_order": 2})
                        return ordinary(round_id, **kwargs)
                    authority.publish = publish
                    return authority
                state.authority_factory.side_effect = factory
                with self.assertRaises((URLError, OSError)):
                    run_server(self.grid, config)
            report = json.loads((Path(config["output_dir"]) / "runtime_result.json").read_text())
            self.assertFalse(report["successful"])
            self.assertEqual(len(report["published_manifests"]), 1)
            trace = report["fault_trace"][-1]
            self.assertTrue(trace["pointer_unchanged"])
            self.assertEqual(trace["published_models_during_fault"], 0)
            self.assertEqual(trace["indeterminate_tasks_before_recovery"], 8)
            self.assertEqual(trace["recovery_errors"], [])
            self.assertEqual(report["measurement_manifest"]["tamper_mode"], "none_declared")


if __name__ == "__main__":
    unittest.main()
