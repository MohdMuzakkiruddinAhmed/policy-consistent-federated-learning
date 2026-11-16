from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_cloud_export", ROOT / "scripts/verify_cloud_campaign.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from pcfl import runtime_verify
from test_runtime_verify import fixture


class CloudExportVerificationTests(unittest.TestCase):
    def test_scoped_cache_reconstructs_original_manifest_without_editing_raw_paths_or_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = fixture(root)
            mapping = {}
            for artifact in [*(record["artifact"] for record in evidence["updates"]), evidence["published_manifests"][0]["artifact"]]:
                path = Path(artifact["path"])
                new = root / (artifact["file_sha256"][:16] + ".npz")
                new.write_bytes(path.read_bytes())
                path.unlink()
                mapping[artifact["file_sha256"]] = new.name
                artifact["path"] = "/runtime/original-linux-path.npz"
            manifest = evidence["published_manifests"][0]
            old_id = manifest["manifest_id"]
            manifest["manifest_id"] = hashlib.sha256(json.dumps({key:value for key,value in manifest.items() if key!='manifest_id'},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            for decision in evidence["decisions"].values():
                decision["manifest_ref"] = manifest["manifest_id"]
            previous = "0"*64
            for event in evidence["audit"]:
                event["payload"] = deepcopy(evidence["decisions"][event["payload"]["update_id"]])
                event["prev_hash"] = previous
                event["event_hash"] = hashlib.sha256(json.dumps({key:event[key] for key in ('sequence','prev_hash','payload')},sort_keys=True,separators=(',',':')).encode()).hexdigest()
                previous=event["event_hash"]
            evidence["anchor"]["head"] = previous
            result = root / "runtime_result.json"
            result.write_text(json.dumps(evidence))
            original = result.read_bytes()
            (root / "artifact_paths.json").write_text(json.dumps(mapping))
            with module.scoped_artifact_cache(root):
                summary = runtime_verify.verify_case(result)
                from pcfl import ablation_verify
                self.assertIs(ablation_verify._load_artifact, runtime_verify._load_artifact)
            self.assertTrue(summary["model_reconstruction_verified"])
            self.assertEqual(result.read_bytes(), original)
            # A cache entry cannot escape the case even if the correct bytes
            # happen to be available in another directory.
            key = next(iter(mapping))
            mapping[key] = str(root.parent / "not-owned.npz")
            (root / "artifact_paths.json").write_text(json.dumps(mapping))
            with module.scoped_artifact_cache(root), self.assertRaises(ValueError):
                runtime_verify.verify_case(result)

    def test_app_scoped_export_requires_its_exact_index_and_result_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application, cell = "master-training-iid", "cell-1"
            export = root / "r/apphash"
            case = export / hashlib.sha256(cell.encode()).hexdigest()[:8]
            case.mkdir(parents=True)
            evidence = fixture(case)
            result = case / "runtime_result.json"
            result.write_text(json.dumps(evidence))
            (case / "cell.json").write_text(json.dumps({"cell_id": cell}))
            mapping = {artifact["file_sha256"]: artifact["path"] for artifact in
                       [*(record["artifact"] for record in evidence["updates"]), evidence["published_manifests"][0]["artifact"]]}
            (case / "artifact_paths.json").write_text(json.dumps(mapping))
            index = {"campaign_id": application, "successful": True, "cases": [{"cell_id": cell, "successful": True,
                "artifacts": [{"bucket": "synthetic-bucket", "key": f"evidence/campaigns/{application}/{cell}/runtime_result.json",
                    "version_id": "exact-version", "sha256": module.file_sha(result), "size_bytes": result.stat().st_size}]}]}
            index_path = export / "campaign_result.json"
            index_path.write_text(json.dumps(index))
            inventory = {"campaign_id": "master", "account_id": "123456789012", "region": "us-east-1",
                "foundation": {"bucket_name": "synthetic-bucket"},
                "export": {"export_root": str(export), "application_campaign_id": application, "index_sha256": module.file_sha(index_path),
                    "index_key": f"evidence/campaigns/{application}/campaign_result.json", "index_version_id": "exact-index-version"}}
            path = root / "inventory.json"
            path.write_text(json.dumps(inventory))
            report = module.verify_export(path)
            self.assertFalse(report["successful"])
            self.assertEqual(report["unprotected_case_ids"], [cell])
            self.assertFalse(report["externally_protected_witnesses_verified"])
            self.assertEqual(report["application_campaign_id"], application)
            index_path.write_text(json.dumps({**index, "campaign_id": "other"}))
            with self.assertRaisesRegex(ValueError, "index_changed"):
                module.verify_export(path)


if __name__ == "__main__":
    unittest.main()
