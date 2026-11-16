"""Policy actor identity, immutable request binding, and durable retry tests."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pcfl.governance_service import PolicyClient, PolicyWriter, create_policy_server
from pcfl.service_io import service_identities

ROOT = Path(__file__).resolve().parents[1]
HAS_BOTO = importlib.util.find_spec("boto3") is not None
HAS_TLS = HAS_BOTO and importlib.util.find_spec("cryptography") is not None


class MemoryDynamo:
    """Small writer I/O double; AWS transaction-expression tests live separately."""
    def __init__(self):
        self.items, self.requests, self.reads = {}, [], []
        self.fail_once = None

    def get_item(self, **request):
        self.reads.append(deepcopy(request))
        key = (request["Key"]["PK"]["S"], request["Key"]["SK"]["S"])
        return {"Item": deepcopy(self.items.get(key, {}))}

    def transact_write_items(self, **request):
        from botocore.exceptions import ClientError
        self.requests.append(deepcopy(request))
        mode, self.fail_once = self.fail_once, None
        if mode == "conflict":
            self.items[("AUTHORITY", "SEQUENCE")]["order"] = {"N": "1"}
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
        for action in request["TransactItems"]:
            if "Put" in action:
                item = deepcopy(action["Put"]["Item"])
                self.items[(item["PK"]["S"], item["SK"]["S"])] = item
            elif "Update" in action:
                body = action["Update"]
                key = (body["Key"]["PK"]["S"], body["Key"]["SK"]["S"])
                item = self.items.setdefault(key, deepcopy(body["Key"]))
                values = body["ExpressionAttributeValues"]
                if key == ("AUTHORITY", "SEQUENCE"):
                    item["order"] = deepcopy(values[":next"])
                    item["last_txn_id"] = deepcopy(values[":txn"])
                else:
                    for field, placeholder in (("epoch", ":epoch"), ("effective_order", ":ord"),
                            ("policy_hash", ":hash"), ("event_json", ":payload"), ("event_id", ":event")):
                        item[field] = deepcopy(values[placeholder])
        if mode == "lost_response":
            raise TimeoutError("committed response was lost")
        return {}


@unittest.skipUnless(HAS_BOTO, "boto3 is installed in the pinned runtime")
class PolicyWriterTests(unittest.TestCase):
    def setUp(self):
        self.ddb = MemoryDynamo()
        self.writer = PolicyWriter(self.ddb, "pcfl-test-state")
        self.writer.initialize()

    def test_durable_replay_after_writer_restart_has_no_second_write(self):
        first = self.writer.mutate("org_01", "GRANT", request_id="stable-request")
        writes = len(self.ddb.requests)
        replay = PolicyWriter(self.ddb, "pcfl-test-state").mutate("org_01", "GRANT", request_id="stable-request")
        self.assertEqual(replay, first)
        self.assertEqual(len(self.ddb.requests), writes)
        self.assertTrue(all(read["ConsistentRead"] for read in self.ddb.reads))
        replay["rules"].clear()
        self.assertEqual(self.writer.mutate("org_01", "GRANT", request_id="stable-request"), first)

    def test_request_id_cannot_be_rebound_to_other_org_kind_or_rules(self):
        self.writer.mutate("org_01", "GRANT", request_id="binding")
        attempts = [("org_02", "GRANT", None), ("org_01", "REVOKE", None), ("org_01", "GRANT", [])]
        for org, kind, rules in attempts:
            with self.subTest(org=org, kind=kind), self.assertRaisesRegex(ValueError, "rebound"):
                self.writer.mutate(org, kind, rules=rules, request_id="binding")

    def test_conflict_retry_refreshes_order_and_changes_transport_token(self):
        self.ddb.fail_once = "conflict"
        event = self.writer.mutate("org_01", "GRANT", request_id="conflicting")
        self.assertEqual(event["order"], 2)
        first, retry = self.ddb.requests[-2:]
        self.assertNotEqual(first["ClientRequestToken"], retry["ClientRequestToken"])
        self.assertEqual(first["TransactItems"][0]["Update"]["ExpressionAttributeValues"][":expected"], {"N": "0"})
        self.assertEqual(retry["TransactItems"][0]["Update"]["ExpressionAttributeValues"][":expected"], {"N": "1"})

    def test_last_attempt_recovers_committed_write_after_lost_response(self):
        self.ddb.fail_once = "lost_response"
        event = PolicyWriter(self.ddb, "pcfl-test-state", max_attempts=1).mutate("org_01", "GRANT", request_id="lost")
        self.assertEqual(event["order"], 1)
        self.assertEqual(self.writer.mutate("org_01", "GRANT", request_id="lost"), event)

    def test_invalid_inputs_fail_before_any_database_access(self):
        for kwargs in ({"request_id": ""}, {"request_id": False}, {"request_id": " "},
                       {"rules": [{"purpose": "x", "action": "unknown", "effect": "allow"}]},
                       {"rules": "not-a-rule-list"}):
            reads, writes = len(self.ddb.reads), len(self.ddb.requests)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.writer.mutate("org_01", "GRANT", **kwargs)
            self.assertEqual((len(self.ddb.reads), len(self.ddb.requests)), (reads, writes))

    def test_corrupted_durable_event_fails_closed(self):
        self.writer.mutate("org_01", "GRANT", request_id="tampered")
        key = next(key for key in self.ddb.items if key[1].startswith("TXN#policy-"))
        payload = json.loads(self.ddb.items[key]["result_json"]["S"])
        payload["event"]["epoch"] += 1
        self.ddb.items[key]["result_json"] = {"S": json.dumps(payload)}
        with self.assertRaisesRegex(ValueError, "invalid_durable"):
            self.writer.mutate("org_01", "GRANT", request_id="tampered")

    def test_caller_rule_mutation_during_io_cannot_change_bound_event(self):
        rules = [{"purpose": "readmission", "action": action, "effect": "allow"}
                 for action in ("train", "submit_update", "aggregate")]
        get_item = self.ddb.get_item
        def changed_caller(**request):
            rules.clear()
            return get_item(**request)
        with patch.object(self.ddb, "get_item", side_effect=changed_caller):
            event = self.writer.mutate("org_01", "GRANT", rules=rules, request_id="frozen-rules")
        self.assertEqual(rules, [])
        self.assertEqual(len(event["rules"]), 3)
        self.assertEqual(self.writer.mutate("org_01", "GRANT", request_id="frozen-rules"), event)


@unittest.skipUnless(HAS_TLS, "mTLS tests use the pinned runtime")
class PolicyTlsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.identities = service_identities(self.directory.name)
        self.ddb = MemoryDynamo()
        writer = PolicyWriter(self.ddb, "pcfl-tls-state")
        writer.initialize()
        self.server = create_policy_server(writer, "127.0.0.1", 0,
            server_cert=self.identities["governance"]["cert"], server_key=self.identities["governance"]["key"],
            ca_cert=self.identities["ca"])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.endpoint = f"https://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.directory.cleanup()

    def client(self, role="policy-operator", **kwargs):
        return PolicyClient(self.endpoint, ca_cert=self.identities["ca"],
            client_cert=self.identities[role]["cert"], client_key=self.identities[role]["key"], **kwargs)

    def test_valid_operator_mutates_idempotently_over_real_mtls(self):
        client = self.client()
        first = client.mutate("org_01", "GRANT", request_id="tls-once")
        self.assertEqual(client.mutate("org_01", "GRANT", request_id="tls-once"), first)
        self.assertEqual(first["order"], 1)

    def test_signed_coordinator_certificate_cannot_impersonate_policy_operator(self):
        client = self.client("coordinator")
        with self.assertRaises(HTTPError) as denied:
            client.mutate("org_01", "GRANT", request_id="forbidden")
        self.assertEqual(denied.exception.code, 403)
        self.assertEqual(len(self.ddb.requests), 1)  # authority initialization only

    def test_missing_certificate_and_untrusted_server_ca_fail_tls(self):
        context = ssl.create_default_context(cafile=self.identities["ca"])
        request = Request(self.endpoint + "/policy-events", data=b"{}", method="POST")
        with self.assertRaises((URLError, OSError)):
            urlopen(request, context=context, timeout=2)
        with tempfile.TemporaryDirectory() as other:
            foreign = service_identities(other)
            with self.assertRaises((URLError, OSError)):
                PolicyClient(self.endpoint, ca_cert=foreign["ca"], client_cert=self.identities["policy-operator"]["cert"],
                    client_key=self.identities["policy-operator"]["key"]).mutate("org_01", "GRANT")
        self.assertEqual(len(self.ddb.requests), 1)

    def test_null_mutation_id_is_rejected_at_http_boundary(self):
        request = Request(self.endpoint + "/policy-events", data=json.dumps({"org_id": "org_01", "kind": "GRANT",
            "request_id": None}).encode(), method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as denied:
            self.client()._opener.open(request, timeout=2)
        self.assertEqual(denied.exception.code, 400)

    def test_endpoint_and_timeout_fail_closed_before_network(self):
        identity = self.identities["policy-operator"]
        for endpoint in ("http://127.0.0.1", "https:///missing", "https://user:pass@localhost", self.endpoint + "/prefix"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                PolicyClient(endpoint, ca_cert=self.identities["ca"], client_cert=identity["cert"], client_key=identity["key"])
        for timeout in (0, -1, True, float("inf"), 31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.client(timeout=timeout)

    def test_wrong_payload_or_unbounded_response_cannot_be_accepted(self):
        client = self.client()
        request_id = "response-binding"
        event = {"event_id": "policy-" + hashlib.sha256(request_id.encode()).hexdigest()[:40], "org_id": "org_02",
            "order": 1, "epoch": 1, "kind": "GRANT", "rules": []}
        class Response(io.BytesIO):
            status = 200
        bodies = [b"[]", b" " * 65537, json.dumps({"successful": True, "event": event}).encode(),
                  json.dumps({"successful": 1, "event": event}).encode()]
        for body in bodies:
            with self.subTest(size=len(body)), patch.object(client._opener, "open", return_value=Response(body)):
                with self.assertRaises(ValueError):
                    client.mutate("org_01", "GRANT", request_id=request_id)


@unittest.skipUnless(HAS_TLS and os.environ.get("PCFL_GOVERNANCE_TEST_LOCAL") == "1",
                     "Set PCFL_GOVERNANCE_TEST_LOCAL=1 for isolated DynamoDB Local tests")
class PolicyDurabilityIntegrationTests(unittest.TestCase):
    def test_real_transactions_survive_restart_and_order_concurrent_writers(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from integration_services import LocalIntegrationServices
        with tempfile.TemporaryDirectory() as directory, LocalIntegrationServices(directory) as services:
            first = PolicyWriter(services.ddb, services.table)
            first.initialize()
            grant = first.mutate("org_01", "GRANT", request_id="durable-restart")
            restarted = PolicyWriter(services.ddb, services.table)
            restarted.initialize()
            self.assertEqual(restarted.mutate("org_01", "GRANT", request_id="durable-restart"), grant)
            with self.assertRaisesRegex(ValueError, "rebound"):
                restarted.mutate("org_02", "GRANT", request_id="durable-restart")
            barrier = threading.Barrier(8)
            def mutate(index):
                writer = PolicyWriter(services.ddb, services.table, max_attempts=20)
                barrier.wait(timeout=10)
                return writer.mutate(f"org_{index:02d}", "GRANT", request_id=f"concurrent-{index}")
            with ThreadPoolExecutor(max_workers=8) as executor:
                events = list(executor.map(mutate, range(1, 9)))
            self.assertEqual(sorted(event["order"] for event in events), list(range(2, 10)))
            self.assertEqual(first.item("AUTHORITY", "SEQUENCE")["order"], 9)
            for event in events:
                current = first.item("POLICY#" + event["org_id"], "CURRENT")
                history = first.item("POLICY#" + event["org_id"], f"EVENT#{event['order']:020d}")
                self.assertEqual(json.loads(current["event_json"]), event)
                self.assertEqual(json.loads(history["event_json"]), event)
            # Exercise the actual isolated CLI actor with a private local config.
            identities = service_identities(Path(directory) / "actor-tls")
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            configuration = {"storage": services.storage, "table_name": services.table, "host": "127.0.0.1", "port": port,
                "tls": {"server_cert": identities["governance"]["cert"], "server_key": identities["governance"]["key"],
                        "ca_cert": identities["ca"]}}
            config_file = Path(directory) / "governance-config.json"
            config_file.write_text(json.dumps(configuration), encoding="utf-8")
            process = subprocess.Popen([sys.executable, str(ROOT / "scripts/serve_governance.py"), "--config", str(config_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                client = PolicyClient(f"https://127.0.0.1:{port}", ca_cert=identities["ca"],
                    client_cert=identities["policy-operator"]["cert"], client_key=identities["policy-operator"]["key"], timeout=1)
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        self.fail("governance CLI exited: " + process.stderr.read().decode(errors="replace")[:200])
                    try:
                        result = client.mutate("org_08", "REVOKE", request_id="isolated-actor")
                        break
                    except (URLError, OSError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                self.assertEqual(result["order"], 10)
                self.assertEqual(client.mutate("org_08", "REVOKE", request_id="isolated-actor"), result)
                self.assertEqual(first.item("AUTHORITY", "SEQUENCE")["order"], 10)
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()
        for container in services.names:
            inspection = subprocess.run(["docker", "inspect", container], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False, timeout=5)
            self.assertNotEqual(inspection.returncode, 0, "owned integration container remained after cleanup")
