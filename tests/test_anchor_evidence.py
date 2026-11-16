from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("anchor_cloud_export", ROOT / "scripts/anchor_evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OperatorWitnessTests(unittest.TestCase):
    def test_failed_no_model_run_is_witnessed_without_inventing_a_commit(self):
        result = {"persistent_run_id": "failed-run", "anchor": {"count": 0, "head": "0" * 64},
                  "model_schema_hash": "a" * 64, "successful": False, "published_manifests": []}
        payload = module.observed_payload(result, raw_sha256="b" * 64, cell_id="failure", campaign_id="master",
                                         application_id="app", head={}, pointer={})
        self.assertFalse(payload["execution_successful"])
        self.assertIsNone(payload["manifest_id"])
        self.assertIsNone(payload["model_digest"])
        self.assertEqual(payload["commit_order"], 0)
        with self.assertRaisesRegex(ValueError, "pointer"):
            module.observed_payload(result, raw_sha256="b" * 64, cell_id="failure", campaign_id="master",
                                    application_id="app", head={}, pointer={"manifest_id": {"S": "unexported"}})
        with self.assertRaisesRegex(ValueError, "anchor"):
            module.observed_payload(result, raw_sha256="b" * 64, cell_id="failure", campaign_id="master",
                                    application_id="app", head={"count": {"N": "1"}}, pointer={})

    def test_witness_rejects_changed_head_truncation_result_binding_signature_or_trust_key(self):
        key = ec.generate_private_key(ec.SECP384R1())
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        payload = {"run_id": "synthetic", "anchor": {"count": 2, "head": "a"*64}, "raw_result_sha256": "b"*64}
        witness = module.create_witness(payload, key)
        pin = witness["public_key_sha256"]
        self.assertTrue(module.verify_witness(witness, public, expected_public_key_sha256=pin))
        for field, changed in (("anchor", {"count": 1, "head": "a"*64}), ("raw_result_sha256", "c"*64)):
            tampered = deepcopy(witness)
            tampered["payload"][field] = changed
            tampered["payload_sha256"] = hashlib.sha256(module.canonical(tampered["payload"])).hexdigest()
            self.assertFalse(module.verify_witness(tampered, public, expected_public_key_sha256=pin))
        other = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertFalse(module.verify_witness(witness, other, expected_public_key_sha256=pin))
        self.assertFalse(module.verify_witness(witness, public, expected_public_key_sha256="d"*64))


if __name__ == "__main__":
    unittest.main()
