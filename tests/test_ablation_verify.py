"""Independent error/audit/witness fixtures, without enforcing producer imports."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pcfl.ablation_verify import assess_case


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def hashed(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fixture():
    rule_hash = hashlib.sha256((Path(__file__).resolve().parents[1] / "policies/rego/pcfl.rego").read_bytes()).hexdigest()
    grant = {"event_id": "grant-1", "org_id": "org_01", "order": 1, "epoch": 1, "kind": "GRANT",
             "rules": [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ("train", "submit_update", "aggregate")]}
    task = {"task_id": "task-1", "update_id": "update-1", "org_id": "org_01", "node_id": 1, "round_id": "round-1",
            "purpose": "readmission", "issue_order": 2, "start_order": 3, "policy_epoch": 1,
            "policy_hash": hashed(grant), "model_schema_hash": "a" * 64, "nonce_digest": "b" * 64}
    error = {key: task[key] for key in ("update_id", "task_id", "org_id", "round_id", "purpose", "start_order")}
    error.update(outcome="error", reason="synthetic_client_crash", evaluation_order=4, observed_epoch=1,
        history_digest=hashed([grant]), history_digest_scope="organization", manifest_ref=None, run_id="unit",
        rule_bundle_hash=rule_hash, authorization_status="not_evaluated_operational_error", policy_decision_id=None, policy_query=None)
    audit = {"sequence": 1, "prev_hash": "0" * 64, "payload": error}
    audit["event_hash"] = hashed(audit)
    rows = [{"PK": "RUN#unit", "SK": "TASK#task-1", **task},
        {"PK": "RUN#unit", "SK": "ISSUE#task-1", "task_json": json.dumps({"update_id": "update-1"})},
        {"PK": "RUN#unit", "SK": "ATTEMPT#task-1", "decision_json": json.dumps(error)},
        {"PK": "RUN#unit", "SK": f"AUDIT#{1:020d}", "event_json": json.dumps(audit), "event_hash": audit["event_hash"]},
        {"PK": "RUN#unit", "SK": "AUDIT_HEAD", "count": 1, "head": audit["event_hash"]},
        {"PK": "RUN#unit", "SK": "POINTER"}]
    return {"persistent_run_id": "unit", "model_schema_hash": "a" * 64, "policy_rule_hash": rule_hash, "policy_events": [grant],
        "tasks": [task], "updates": [], "decisions": {}, "attempt_failures": [error], "published_manifests": [],
        "audit": [audit], "anchor": {"count": 1, "head": audit["event_hash"]},
        "durable_evidence": {"run_records": rows, "sequence": {"order": 4}}}


class PartialVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "evidence.json"
        self.key = ec.generate_private_key(ec.SECP384R1())
        self.public = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pin = hashlib.sha256(self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def write(self, evidence):
        self.path.write_bytes(canonical(evidence) + b"\n")
        payload = {"run_id": "unit", "anchor": evidence["anchor"], "manifest_id": None, "model_digest": None,
                   "model_schema_hash": evidence["model_schema_hash"], "commit_order": 0,
                   "raw_result_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}
        return {"algorithm": "ECDSA-P384-SHA384", "payload": payload, "payload_sha256": hashed(payload),
                "public_key_sha256": self.pin, "signature_base64": base64.b64encode(self.key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))).decode()}

    def check(self, evidence):
        return assess_case(self.path, witness=self.write(evidence), public_key_pem=self.public, expected_public_key_sha256=self.pin)

    def test_final_error_is_included_in_final_audit_denominator(self):
        result = self.check(fixture())
        self.assertEqual(result["presented_update_count"], 0)
        self.assertEqual(result["final_error_count"], 1)
        self.assertEqual(result["final_audit_expected_count"], 1)
        self.assertEqual(result["final_audit_recorded_count"], 1)
        self.assertFalse(result["full_protocol_pass"])

    def test_unacknowledged_task_remains_indeterminate_not_a_fabricated_final_error(self):
        evidence = fixture()
        evidence["durable_evidence"]["run_records"].append({"PK": "RUN#unit", "SK": "ISSUE#task-2", "task_json": json.dumps({"update_id": "update-2"})})
        result = self.check(evidence)
        self.assertEqual(result["task_assignment_count"], 2)
        self.assertEqual(result["final_error_count"], 1)
        self.assertEqual(result["indeterminate_count"], 1)
        self.assertFalse(result["attempt_accounting_complete"])

    def test_missing_mandatory_error_fields_fail_even_with_a_genuine_new_signature(self):
        evidence = fixture()
        evidence["attempt_failures"][0].pop("rule_bundle_hash")
        with self.assertRaisesRegex(ValueError, "mandatory_final"):
            self.check(evidence)

    def no_audit(self):
        evidence = fixture()
        evidence["audit"] = []; evidence["anchor"] = {"count": 0, "head": "0" * 64}
        evidence["durable_evidence"]["run_records"] = [row for row in evidence["durable_evidence"]["run_records"] if not row["SK"].startswith("AUDIT#")]
        head = next(row for row in evidence["durable_evidence"]["run_records"] if row["SK"] == "AUDIT_HEAD")
        head.update(count=0, head="0" * 64)
        return evidence

    def test_error_audit_omission_is_not_treated_as_an_empty_success(self):
        with self.assertRaisesRegex(ValueError, "mandatory_final_outcome_audit_missing"):
            self.check(self.no_audit())
        evidence = self.no_audit()
        evidence.update(ablation_id="Abl-3", full_protocol=False, ablated_safeguards=["persistent_audit_chain"])
        result = self.check(evidence)
        self.assertEqual(result["final_audit_expected_count"], 1)
        self.assertEqual(result["final_audit_recorded_count"], 0)
        self.assertFalse(result["audit_complete_for_all_final_outcomes"])
        self.assertFalse(result["full_protocol_pass"])

    def test_substituting_public_key_cannot_replace_external_pin(self):
        evidence = fixture(); witness = self.write(evidence)
        attacker = ec.generate_private_key(ec.SECP384R1())
        attacker_public = attacker.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(ValueError, "external_pin"):
            assess_case(self.path, witness=witness, public_key_pem=attacker_public, expected_public_key_sha256=self.pin)


if __name__ == "__main__":
    unittest.main()
