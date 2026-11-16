import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("process_crash_probe", ROOT/"scripts/probe_process_crash.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def custody_fixture(root):
    import numpy as np
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    root.mkdir(); (root/"s").mkdir()
    key = ec.generate_private_key(ec.SECP384R1()).public_key()
    (root/"operator-public.pem").write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pin = hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    storage = {"local_emulation": True, "region": "us-east-1", "dynamodb_endpoint": "http://127.0.0.1:8000", "s3_endpoint": "http://127.0.0.1:5000"}
    services = {"stopped": True, "aws_resources_created": False, "storage": storage, "opa_endpoint": "http://127.0.0.1:8181",
        "bucket": "pcfl-int-test-models", "table_name": "pcfl-int-test-state"}
    MOD.write(root/"s/services.json", services)
    content = io.BytesIO(); np.savez(content, np.array([5/3, 5/3], dtype=np.float32)); content = content.getvalue()
    (root/"1-crash-staged.npz").write_bytes(content); logical, _ = MOD.model_digest(content)
    cases = []
    for index, stage in enumerate(("before-publication", "after-publication"), 1):
        config = {"storage": storage, "opa_endpoint": services["opa_endpoint"], "table": services["table_name"],
            "bucket": services["bucket"], "run_id": f"crash-probe-{index}"}
        MOD.write(root/f"{index}-config.json", config)
        pointer = {"manifest_id": "a" * 64} if index == 2 else {}
        crash = {"pid": index, "phase": "after-immutable-staging-before-publication" if index == 1 else "after-durable-publication",
            "pointer": pointer, "anchor": {"count": 2 if index == 2 else 0, "head": "b" * 64}}
        if index == 1:
            crash.update(staged_parameters_digest=logical, staged_artifact={"backend": "s3", "bucket": services["bucket"],
                "key": f"models/candidates/crash-probe-1/{logical}.npz", "version_id": "version-staged", "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content), "model_digest": logical, "parameters_digest": logical, "local_path": "1-crash-staged.npz"})
        MOD.write(root/f"{index}-crash.json", crash)
        recovery = {"pid": index + 2, "idempotent_second_publish": True, "published_models": 1, "pointer_before": pointer,
            "pointer_after": {"manifest_id": "a" * 64}, "anchor": crash["anchor"]}
        MOD.write(root/f"{index}-recovery.json", recovery)
        for name in ("crash", "recovery"): (root/f"{index}-{name}.log").write_text("synthetic unit fixture\n")
        directory = root/"e"/("process-"+stage); directory.mkdir(parents=True)
        for name in ("evidence", "witness"): MOD.write(directory/(name+".json"), {"synthetic_custody_only": True})
        cases.append({"stage": stage, "crash_exit_code": 137, "crash_pid": index, "recovery_pid": index + 2, "recovery": recovery})
    report = {"kind": "actual-local-protocol-process-crash-probe", "successful": True, "aws_used": False, "clinical_rows_used": 0,
        "test_holdout_evaluated": False, "full_flower_supervisor_restart": False,
        "cases": cases, "operator_public_key_sha256": pin, "custody_receipt": MOD.write_custody(root)}
    MOD.write(root/"report.json", report)
    return root/"report.json"


class ProcessCrashProbeTests(unittest.TestCase):
    def test_offline_custody_requires_external_pin_and_exact_complete_file_set(self):
        with tempfile.TemporaryDirectory() as temp:
            report = custody_fixture(Path(temp)/"probe")
            result = MOD.verify_custody(report, expected_report_sha256=MOD.sha(report), verify_protocol=False)
            self.assertTrue(result["successful"])
            self.assertEqual(result["orphan_staged_versions_checked"], 1)
            self.assertFalse(result["protocol_replayed"])
            with self.assertRaisesRegex(ValueError, "externally_pinned"):
                MOD.verify_custody(report, expected_report_sha256="0" * 64, verify_protocol=False)
            (report.parent/"unexpected.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "file_set_or_bytes"):
                MOD.verify_custody(report, expected_report_sha256=MOD.sha(report), verify_protocol=False)

    def test_changed_or_missing_crash_log_orphan_npz_receipt_and_public_key_reject(self):
        for name in ("1-crash.json", "2-recovery.json", "1-crash.log", "1-crash-staged.npz", "operator-public.pem", "custody_receipt.json"):
            with tempfile.TemporaryDirectory() as temp:
                report = custody_fixture(Path(temp)/"probe"); pin = MOD.sha(report)
                path = report.parent/name; path.write_bytes(path.read_bytes() + b"changed")
                with self.assertRaises(ValueError): MOD.verify_custody(report, expected_report_sha256=pin, verify_protocol=False)
        with tempfile.TemporaryDirectory() as temp:
            report = custody_fixture(Path(temp)/"probe"); pin = MOD.sha(report)
            (report.parent/"2-crash.log").unlink()
            with self.assertRaises(ValueError): MOD.verify_custody(report, expected_report_sha256=pin, verify_protocol=False)

    def test_rebound_outer_custody_cannot_hide_wrong_orphan_model_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            report = custody_fixture(Path(temp)/"probe"); root = report.parent
            marker = json.loads((root/"1-crash.json").read_text())
            marker["staged_artifact"]["key"] = "models/candidates/crash-probe-2/wrong.npz"
            MOD.write(root/"1-crash.json", marker)
            body = json.loads(report.read_text()); body["custody_receipt"] = MOD.write_custody(root); MOD.write(report, body)
            with self.assertRaisesRegex(ValueError, "orphan_staged"):
                MOD.verify_custody(report, expected_report_sha256=MOD.sha(report), verify_protocol=False)

    def test_private_key_and_path_traversal_cannot_enter_custody(self):
        with tempfile.TemporaryDirectory() as temp:
            report = custody_fixture(Path(temp)/"probe"); root = report.parent
            for path in ("../outside.json", "C:/outside.json", "e/../operator-public.pem"):
                with self.assertRaises(ValueError): MOD.owned(root, path)
            (root/"private-key.pem").write_text("-----BEGIN PRIVATE KEY-----\nsynthetic\n")
            with self.assertRaisesRegex(ValueError, "private"):
                MOD.write_custody(root)

    def test_staged_candidate_uses_exact_version_and_rejects_wrong_version(self):
        import numpy as np
        content = io.BytesIO(); np.savez(content, np.array([1, 2], dtype=np.float32)); content = content.getvalue()
        logical, _ = MOD.model_digest(content); byte_sha = hashlib.sha256(content).hexdigest()
        key = f"models/candidates/crash-probe-1/{logical}.npz"
        calls = []
        def call(operation, **kwargs):
            calls.append((operation, kwargs))
            if operation == "list": return {"Versions": [{"Key": key, "IsLatest": True, "VersionId": "v1", "Size": len(content)}], "IsTruncated": False}
            if operation == "head": return {"VersionId": "v1", "ContentLength": len(content), "Metadata": {"sha256": byte_sha, "parameters-digest": logical}}
            return {"VersionId": "v1", "Body": io.BytesIO(content)}
        s3 = SimpleNamespace(list_object_versions=lambda **kw: call("list", **kw), head_object=lambda **kw: call("head", **kw), get_object=lambda **kw: call("get", **kw))
        with tempfile.TemporaryDirectory() as temp:
            result = MOD.retain_staged_candidate(s3, bucket="pcfl-int-test-models", run_id="crash-probe-1", logical_digest=logical, output=Path(temp)/"model.npz")
            self.assertEqual(result["sha256"], byte_sha)
            self.assertTrue(all(args.get("VersionId") == "v1" for op, args in calls if op != "list"))
            s3.get_object = lambda **kw: {"VersionId": "wrong", "Body": io.BytesIO(content)}
            with self.assertRaisesRegex(ValueError, "exact_version"):
                MOD.retain_staged_candidate(s3, bucket="pcfl-int-test-models", run_id="crash-probe-1", logical_digest=logical, output=Path(temp)/"bad.npz")
    def test_provider_endpoint_or_nonlocal_names_are_rejected_before_sdk_creation(self):
        config = {"storage": {"local_emulation": True, "dynamodb_endpoint": "http://127.0.0.1:8000",
            "s3_endpoint": "http://127.0.0.1:5000"}, "opa_endpoint": "http://127.0.0.1:8181",
            "table": "pcfl-int-test-state", "bucket": "pcfl-int-test-models"}
        MOD.validate_local(config)
        config["storage"]["s3_endpoint"] = "https://s3.us-east-1.amazonaws.com"
        with self.assertRaisesRegex(ValueError, "loopback"):
            MOD.validate_local(config)
        config["storage"]["s3_endpoint"] = "http://127.0.0.1:5000"
        config["table"] = "foreign-table"
        with self.assertRaisesRegex(ValueError, "owned_local"):
            MOD.validate_local(config)

    @unittest.skipUnless(os.environ.get("PCFL_LOCAL_INTEGRATION") == "1", "Set PCFL_LOCAL_INTEGRATION=1 for real local API/process crashes")
    def test_real_exit137_fresh_process_recovery_and_independent_witness_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/"probe"
            result = subprocess.run([sys.executable, str(ROOT/"scripts/probe_process_crash.py"), "--output", str(output)],
                capture_output=True, text=True, timeout=180, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[-2500:])
            report = json.loads((output/"report.json").read_text())
            self.assertTrue(report["successful"])
            self.assertFalse(report["aws_used"])
            self.assertFalse(report["full_flower_supervisor_restart"])
            self.assertEqual(len(report["cases"]), 2)
            for case in report["cases"]:
                self.assertEqual(case["crash_exit_code"], 137)
                self.assertNotEqual(case["crash_pid"], case["recovery_pid"])
                self.assertTrue(all(case["checks"].values()))
            self.assertTrue(json.loads((output/"s/services.json").read_text())["stopped"])
            replay = MOD.verify_custody(output/"report.json", expected_report_sha256=MOD.sha(output/"report.json"))
            self.assertTrue(replay["protocol_replayed"])
            self.assertGreater(replay["files_checked"], 20)
            self.assertEqual(replay["orphan_staged_versions_checked"], 1)
            # Signed raw model references retain their original absolute cache
            # paths. Replay must use only the moved, hash-bound custody tree.
            moved = Path(temp)/"moved-probe"
            self.assertEqual(output.resolve().parent, Path(temp).resolve())
            self.assertEqual(moved.resolve().parent, Path(temp).resolve())
            pin = MOD.sha(output/"report.json")
            output.rename(moved)
            self.assertTrue(MOD.verify_custody(moved/"report.json", expected_report_sha256=pin)["protocol_replayed"])


if __name__ == "__main__":
    unittest.main()
