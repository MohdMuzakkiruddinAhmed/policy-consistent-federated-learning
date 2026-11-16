"""Fail-closed REST integration with a pinned, separately running OPA evaluator.

Python checks record shape/history integrity and response binding. Rego performs
the permission and continuous-interval decision; no Python allow decision is sent.
"""

from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
import uuid

OPA_VERSION = "1.22.3"
OPA_IMAGE = "openpolicyagent/opa@sha256:a6ccb6e0cc91b2d1807b1b65a844b189249b9ab33d126e0bca30c0cf43b0ae07"
PROTOCOL_REVISION = "pcfl-interval-v1"
_ACTIONS = {"train", "submit_update", "aggregate"}
_ORGANIZATIONS = {f"org_{number:02d}" for number in range(1, 9)}


class OpaUnavailable(RuntimeError):
    """No attributable policy decision is available; publication must close."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def policy_hash(path=None):
    source = Path(path) if path is not None else Path(__file__).resolve().parents[2] / "policies/rego/pcfl.rego"
    return hashlib.sha256(source.read_bytes()).hexdigest()


def _integer(value):
    return type(value) is int and value > 0


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def validate_input(events, query):
    """Validate complete JSON history integrity without calculating permission."""
    if (not isinstance(query, dict) or not isinstance(query.get("org_id"), str) or query.get("org_id") not in _ORGANIZATIONS
            or not _text(query.get("purpose")) or not _integer(query.get("start_order"))
            or not _integer(query.get("commit_order")) or query["start_order"] > query["commit_order"]
            or not isinstance(query.get("actions"), list) or len(query["actions"]) != 3
            or not all(isinstance(action, str) for action in query["actions"])
            or set(query["actions"]) != _ACTIONS):
        raise ValueError("malformed_policy_query")
    if not isinstance(events, list):
        raise ValueError("malformed_policy_history")
    past = []
    for event in events:
        if not isinstance(event, dict) or not _integer(event.get("order")):
            raise ValueError("unknown_policy_order")
        if event["order"] > query["commit_order"]:
            continue
        if (not isinstance(event.get("org_id"), str) or event.get("org_id") not in _ORGANIZATIONS or not _text(event.get("event_id"))
                or not _integer(event.get("epoch")) or event.get("kind") not in ("GRANT", "CHANGE", "REVOKE", "EXPIRE")
                or not isinstance(event.get("rules"), list)
                or (event["kind"] in ("REVOKE", "EXPIRE") and event["rules"])):
            raise ValueError("malformed_policy_event")
        for rule in event["rules"]:
            if (not isinstance(rule, dict) or not _text(rule.get("purpose"))
                    or rule.get("action") not in ("train", "submit_update", "aggregate")
                    or rule.get("effect") not in ("allow", "deny")):
                raise ValueError("malformed_policy_rule")
        past.append(event)
    past.sort(key=lambda event: event["order"])
    identities, orders, epochs = set(), set(), {}
    for event in past:
        if event["event_id"] in identities or event["order"] in orders:
            raise ValueError("duplicate_policy_identity_or_order")
        if event["epoch"] != epochs.get(event["org_id"], 0) + 1:
            raise ValueError("incomplete_policy_history")
        identities.add(event["event_id"])
        orders.add(event["order"])
        epochs[event["org_id"]] = event["epoch"]
    return past


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise OpaUnavailable("policy_endpoint_redirect_rejected")


class OpaClient:
    def __init__(self, endpoint, *, expected_rule_hash=None, allow_loopback_http=False,
                 timeout=3.0, ca_file=None, client_cert=None, client_key=None):
        if not isinstance(endpoint, str):
            raise ValueError("invalid_opa_endpoint")
        parsed = urlsplit(endpoint)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("invalid_opa_endpoint")
        local = parsed.hostname == "localhost"
        try:
            local = local or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            pass
        if parsed.scheme != "https" and not (parsed.scheme == "http" and allow_loopback_http and local):
            raise ValueError("verified_https_required_except_explicit_loopback")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ValueError("invalid_policy_timeout")
        self.rule_hash = expected_rule_hash if expected_rule_hash is not None else policy_hash()
        if not isinstance(self.rule_hash, str) or not re.fullmatch("[0-9a-f]{64}", self.rule_hash):
            raise ValueError("invalid_expected_rule_hash")
        self.endpoint, self.timeout = endpoint.rstrip("/"), float(timeout)
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        if bool(client_cert) != bool(client_key):
            raise ValueError("opa_client_certificate_and_key_required_together")
        if client_cert:
            if parsed.scheme != "https":
                raise ValueError("opa_client_identity_requires_https")
            context.load_cert_chain(str(client_cert), str(client_key))
        # Ignore host proxy credentials/settings; decisions go only to this endpoint.
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())

    def evaluate(self, events, query):
        checked_events = deepcopy(events)
        checked_query = deepcopy(query)
        past = validate_input(checked_events, checked_query)
        binding = uuid.uuid4().hex
        history_digest = hashlib.sha256(_canonical(past)).hexdigest()
        request_hash = hashlib.sha256(_canonical({"events": checked_events, "query": checked_query})).hexdigest()
        document = {"events": checked_events, "query": checked_query, "request_binding": binding,
                    "request_hash": request_hash, "history_digest": history_digest}
        raw = _canonical({"input": document})
        if len(raw) > 4_000_000:
            raise ValueError("policy_request_size_limit")
        request = Request(self.endpoint + "/v1/data/pcfl/decision?provenance=true", data=raw,
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                content = response.read(1_000_001)
                if response.status != 200 or len(content) > 1_000_000:
                    raise OpaUnavailable("invalid_policy_response")
            envelope = json.loads(content)
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise OpaUnavailable("policy_evaluator_unavailable_or_invalid_response") from None
        if not isinstance(envelope, dict):
            raise OpaUnavailable("malformed_policy_response")
        result = envelope.get("result")
        if (not _text(envelope.get("decision_id")) or not isinstance(result, dict)
                or not isinstance(envelope.get("provenance"), dict)
                or envelope["provenance"].get("version") != OPA_VERSION
                or type(result.get("valid")) is not bool or not _text(result.get("reason"))
                or result.get("rule_hash") != self.rule_hash or result.get("protocol_revision") != PROTOCOL_REVISION
                or result.get("query") != checked_query or result.get("request_binding") != binding
                or result.get("request_hash") != request_hash or result.get("history_digest") != history_digest
                or "invalid_order" not in result
                or (result.get("invalid_order") is not None and not _integer(result["invalid_order"]))):
            raise OpaUnavailable("unbound_or_unpinned_policy_decision")
        if (result["valid"] and (result.get("invalid_order") is not None or result["reason"] != "continuous_authorization")):
            raise OpaUnavailable("incoherent_policy_decision")
        if not result["valid"] and result["reason"] not in {
                "policy_metadata_missing", "malformed_history_or_query", "missing_start_policy", "authorization_interrupted"}:
            raise OpaUnavailable("unknown_policy_denial_reason")
        return {**deepcopy(result), "decision_id": envelope["decision_id"], "opa_version": OPA_VERSION}

    __call__ = evaluate
