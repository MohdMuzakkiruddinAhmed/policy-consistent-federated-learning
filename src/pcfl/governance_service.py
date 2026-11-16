"""Separate policy-writer actor with mTLS, durable idempotency and atomic history."""

from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
from urllib.parse import urlparse
import uuid

from . import aws_transactions as tx
from .contracts import ACTIONS, ORGANIZATIONS, digest
from .reference import validate_event


def _request_identity(request_id):
    request_id = uuid.uuid4().hex if request_id is None else request_id
    if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 100:
        raise ValueError("invalid_mutation_request_id")
    return request_id, "policy-" + hashlib.sha256(request_id.encode()).hexdigest()[:40]


def _mutation_rules(kind, rules):
    if rules is None:
        rules = [{"purpose": "readmission", "action": action, "effect": "allow"}
                 for action in ACTIONS] if kind == "GRANT" else []
    return deepcopy(rules)


def _decode(item):
    result = {}
    for name, value in item.items():
        if "S" in value:
            result[name] = value["S"]
        elif "N" in value:
            result[name] = int(value["N"])
    return result


class PolicyWriter:
    def __init__(self, dynamodb, table_name, *, max_attempts=5):
        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("invalid_mutation_attempt_limit")
        self.ddb, self.table = dynamodb, table_name
        self.max_attempts = max_attempts
        self.lock = threading.RLock()

    def item(self, pk, sk):
        return _decode(self.ddb.get_item(TableName=self.table,
            Key={"PK": {"S": pk}, "SK": {"S": sk}}, ConsistentRead=True).get("Item", {}))

    def initialize(self):
        with self.lock:
            if not self.item("AUTHORITY", "SEQUENCE"):
                request = tx.build_initialize_authority(self.table, txn_id="initialize-policy-authority")
                try:
                    self.ddb.transact_write_items(**request)
                except Exception:
                    if not self.item("AUTHORITY", "SEQUENCE"):
                        raise

    def mutate(self, org_id, kind, *, rules=None, request_id=None):
        from botocore.exceptions import ClientError
        if org_id not in ORGANIZATIONS or not isinstance(kind, str) or kind not in {"GRANT", "CHANGE", "REVOKE", "EXPIRE"}:
            raise ValueError("invalid_policy_transition")
        request_id, txn_id = _request_identity(request_id)
        rules = _mutation_rules(kind, rules)
        binding = digest({"org_id": org_id, "kind": kind, "rules": rules})
        # Validate the entire replacement state before consulting a durable outcome.
        tx.build_policy_mutation(self.table, expected_order=0, expected_epoch=0, txn_id=txn_id,
            event={"event_id": txn_id, "org_id": org_id, "order": 1, "epoch": 1, "kind": kind, "rules": rules})

        def recovered_event():
            old = self.item("AUTHORITY", "TXN#" + txn_id)
            if not old:
                return None
            stored = json.loads(old["result_json"])
            if stored.get("mutation_binding") != binding:
                raise ValueError("mutation_request_id_rebound")
            event = stored["event"]
            validate_event(event)
            original = tx.build_policy_mutation(self.table, expected_order=event["order"] - 1,
                expected_epoch=event["epoch"] - 1, event=event, txn_id=txn_id)
            if (event["event_id"] != txn_id or digest({key: event[key] for key in ("org_id", "kind", "rules")}) != binding
                    or old.get("order") != event["order"] or old.get("operation_kind") != "policy_mutation"
                    or old.get("record_type") != "transaction_outcome"
                    or old.get("request_digest") != tx.expected_outcome_digest(original)):
                raise ValueError("invalid_durable_mutation_outcome")
            return deepcopy(event)

        with self.lock:
            for _ in range(self.max_attempts):
                recovered = recovered_event()
                if recovered is not None:
                    return recovered
                order = self.item("AUTHORITY", "SEQUENCE")["order"]
                current = self.item(f"POLICY#{org_id}", "CURRENT")
                event = {"event_id": txn_id, "org_id": org_id, "order": order + 1,
                         "epoch": current.get("epoch", 0) + 1, "kind": kind, "rules": deepcopy(rules)}
                request = tx.build_policy_mutation(self.table, expected_order=order,
                    expected_epoch=current.get("epoch", 0), event=event, txn_id=txn_id)
                # Retain caller binding with the same atomic durable outcome.
                outcome = request["TransactItems"][-1]["Put"]["Item"]
                outcome["result_json"] = {"S": json.dumps({"event": event, "mutation_binding": binding}, sort_keys=True)}
                request["ClientRequestToken"] = digest(request["TransactItems"])[:36]
                try:
                    self.ddb.transact_write_items(**request)
                    return event
                except ClientError as error:
                    if error.response["Error"]["Code"] != "TransactionCanceledException":
                        recovered = recovered_event()
                        if recovered is not None:
                            return recovered
                        raise
                except Exception:
                    recovered = recovered_event()
                    if recovered is not None:
                        return recovered
                    raise
            raise RuntimeError("policy_mutation_retry_exhausted")


class PolicyClient:
    def __init__(self, endpoint, *, ca_cert, client_cert, client_key, timeout=5):
        parsed = urlparse(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ("", "/") or parsed.params):
            raise ValueError("governance_https_endpoint_required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ValueError("invalid_governance_timeout")
        self.endpoint, self.timeout = endpoint.rstrip("/"), timeout
        self.context = ssl.create_default_context(cafile=ca_cert)
        self.context.load_cert_chain(client_cert, client_key)
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *_):
                raise ValueError("governance_redirect_rejected")
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=self.context), NoRedirect())

    def mutate(self, org_id, kind, *, rules=None, request_id=None):
        request_id, event_id = _request_identity(request_id)
        expected_rules = _mutation_rules(kind, rules)
        data = {"org_id": org_id, "kind": kind, "request_id": request_id}
        if rules is not None:
            data["rules"] = expected_rules
        request = Request(self.endpoint + "/policy-events", data=json.dumps(data).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        with self._opener.open(request, timeout=self.timeout) as response:
            content = response.read(65537)
            if response.status != 200 or len(content) > 65536:
                raise ValueError("invalid_governance_response")
            result = json.loads(content)
        if not isinstance(result, dict) or result.get("successful") is not True or not isinstance(result.get("event"), dict):
            raise ValueError("invalid_governance_response")
        event = result["event"]
        validate_event(event)
        if (event["event_id"] != event_id or event["org_id"] != org_id
                or event["kind"] != kind or event["rules"] != expected_rules):
            raise ValueError("unbound_governance_response")
        return deepcopy(event)


def create_policy_server(writer, host, port, *, server_cert, server_key, ca_cert,
                         allowed_client_cn="pcfl-policy-operator"):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            try:
                subject = self.connection.getpeercert().get("subject", ())
                names = [value for group in subject for name, value in group if name == "commonName"]
                if names != [allowed_client_cn]:
                    self.send_error(403)
                    return
                if self.path != "/policy-events":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("invalid_request_size")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict) or set(body) - {"org_id", "kind", "rules", "request_id"}:
                    raise ValueError("invalid_mutation_fields")
                if not isinstance(body.get("request_id"), str) or not body["request_id"].strip():
                    raise ValueError("invalid_mutation_request_id")
                event = writer.mutate(body["org_id"], body["kind"], rules=body.get("rules"), request_id=body["request_id"])
                content = json.dumps({"successful": True, "event": event}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (KeyError, ValueError, TypeError):
                self.send_error(400, "Invalid policy request")
            except Exception:
                self.send_error(503, "Policy authority unavailable")
    server = ThreadingHTTPServer((host, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(server_cert, server_key)
    context.load_verify_locations(ca_cert)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
