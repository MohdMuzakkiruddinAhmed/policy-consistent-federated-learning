"""Synthetic metadata/array evidence only; no SDK, training or clinical records."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
import summarize_robustness as normalizer
from pcfl.contracts import digest
from pcfl.robustness import ADAPTER_MODULES, DEFAULTS, deployment_inputs
from pcfl.robust_host import public_documents
from test_cloud_placement import complete_fixture
from test_robustness import registry_fixture, data_fixture
from test_runtime_verify import persistent_fixture


def write(root, name, value):
    path = root/name; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, allow_nan=False))
    return normalizer.reference(path, root)


def fixture(root, *, producer_failure=False):
    registry = deepcopy(registry_fixture())
    registry_ref = write(root, "registry.json", registry)
    base, alternate, _ = data_fixture()
    spec = {"schema_version": "0.1.0", "kind": "exploratory-normalization-input", "registry": registry_ref,
        "data_manifests": [write(root, "base-data.json", base), write(root, "alternate-data.json", alternate)], "groups": []}
    if producer_failure:
        group = deployment_inputs(registry, {"baseline_id": "P1", "authority_backend": "dynamodb-s3-opa", "opa": {}, "evaluator": {}})["groups"][0]
        documents = public_documents(registry, group); application = documents["application_campaign_id"]
        campaign_ref = write(root, "campaign.json", documents["campaign"])
        source_map = {name: normalizer.sha(ROOT/"src/pcfl"/name) for name in ADAPTER_MODULES}
        manifest = {"kind": "additive-exploratory-adapter-manifest", "accepted_main_plan_digest": registry["reference_main_plan_digest"],
            "main_source_changed": False, "adapter_source_sha256": digest(source_map),
            "new_files_sha256": {"src/pcfl/"+name: sha for name, sha in source_map.items()}}
        manifest_ref = write(root, "adapter.json", manifest)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP384R1()).public_key()
        (root/"public.pem").write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        public_pin = hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        public_ref = normalizer.reference(root/"public.pem", root)
        export_root = root/"r"; export_root.mkdir()
        index = {"campaign_id": application, "successful": False, "cases": [{"cell_id": group["cases"][0]["cell_id"],
            "successful": False, "status": "failed", "artifacts": []}]}
        write(root, "r/campaign_result.json", index)
        index_ref = {"bucket": "test-models", "key": f"evidence/campaigns/{application}/campaign_result.json", "version_id": "index-v1",
            "sha256": normalizer.sha(export_root/"campaign_result.json"), "size_bytes": (export_root/"campaign_result.json").stat().st_size}
        inventory = {"campaign_id": "synthetic-deployment", "application_campaign_id": application, "foundation": {"bucket_name": "test-models"},
            "image": {"reference": group["cases"][0]["runtime"]["robustness"]["adapter_image"]},
            "uploads": [{"bucket": "test-models", "key": f"metadata/{application}/campaign.json", "version_id": "campaign-v1", "sha256": campaign_ref["sha256"]}],
            "retained_artifact_versions": [{**index_ref, "local_path": str(export_root/"campaign_result.json")}],
            "export": {"application_campaign_id": application, "export_root": str(export_root), "index_version_id": "index-v1", "index_sha256": index_ref["sha256"]}}
        inventory_ref = write(root, "inventory.json", inventory)
        spec["groups"] = [{"inventory": inventory_ref, "campaign": campaign_ref, "adapter_manifest": manifest_ref,
            "public_key": public_ref, "public_key_sha256": public_pin}]
    return write(root, "normalization-input.json", spec), registry


class ExploratoryNormalizationTests(unittest.TestCase):
    def test_all_unattempted_and_original_preparation_failure_retained_n1(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); ref, registry = fixture(root)
            report = normalizer.normalize(root/ref["path"], evidence_root=root)
            self.assertTrue(report["normalization_complete"])
            self.assertFalse(report["successful"])
            self.assertEqual(report["independent_seed_count"], 1)
            self.assertEqual(len(report["cases"]), len(registry["cases"]))
            self.assertTrue(all(row["status"] == "unattempted" and row["metrics"] is None for row in report["cases"]))
            self.assertEqual(report["excluded_preparation_attempts"], registry["excluded_preparation_attempts"])
            controls = [row for row in report["cases"] if row["factors"] == DEFAULTS]
            self.assertEqual(len(controls), 2)
            self.assertTrue(all(len(row["factor_levels"]) == 6 for row in controls))
            self.assertFalse(report["confirmatory"])
            self.assertFalse(report["final_test_accessed"])

    def test_failed_artifacts_empty_case_is_an_attempt_not_success_or_unattempted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); ref, registry = fixture(root, producer_failure=True)
            report = normalizer.normalize(root/ref["path"], evidence_root=root)
            self.assertEqual(len(report["attempts"]), 1)
            attempt = report["attempts"][0]
            self.assertEqual(attempt["status"], "failed")
            self.assertIsNone(attempt["raw_result"]); self.assertIsNone(attempt["run_id"])
            self.assertIsNone(attempt["metrics"])
            self.assertEqual(sum(row["status"] == "unattempted" for row in report["cases"]), len(registry["cases"])-1)
            self.assertFalse(report["successful"])

    def test_failed_execution_keeps_real_protected_error_audit_without_clinical_metrics(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from test_ablation_verify import fixture as error_fixture
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); ref, registry = fixture(root, producer_failure=True)
            spec = normalizer.read(root/ref["path"]); group = spec["groups"][0]
            inventory = normalizer.read(root/group["inventory"]["path"])
            campaign = normalizer.read(root/group["campaign"]["path"])
            runtime = campaign["cases"][0]["runtime"]; identity = runtime["cell_id"]; run_id = runtime["persistent_run_id"]
            def rebound(value):
                if isinstance(value, list): return [rebound(item) for item in value]
                if isinstance(value, dict): return {key: rebound(item) for key, item in value.items()}
                if value == "unit": return run_id
                if value == "RUN#unit": return "RUN#"+run_id
                if isinstance(value, str) and value.startswith("{"): return json.dumps(rebound(json.loads(value)))
                return value
            raw = rebound(error_fixture())
            audit = raw["audit"][0]; audit["event_hash"] = digest({key: audit[key] for key in ("sequence", "prev_hash", "payload")})
            raw["anchor"]["head"] = audit["event_hash"]
            for row in raw["durable_evidence"]["run_records"]:
                if row["SK"].startswith("AUDIT#"): row.update(event_hash=audit["event_hash"], event_json=json.dumps(audit))
                if row["SK"] == "AUDIT_HEAD": row["head"] = audit["event_hash"]
            raw.update(successful=False, test_holdout_evaluated=False, robustness=runtime["robustness"], distribution=runtime["distribution"],
                seed=296, cell_id=identity, cloud_campaign_id=campaign["campaign_id"], plan_digest=registry["registry_digest"])
            case_dir = root/"r"/hashlib.sha256(identity.encode()).hexdigest()[:8]; case_dir.mkdir()
            write(root, str(case_dir.relative_to(root)/"cell.json"), {"cell_id": identity})
            write(root, str(case_dir.relative_to(root)/"artifact_paths.json"), {})
            raw_file = case_dir/"runtime_result.json"; raw_file.write_text(json.dumps(raw, sort_keys=True))
            def version(path, key, version):
                return {"bucket": "test-models", "key": key, "version_id": version, "sha256": normalizer.sha(path),
                    "size_bytes": path.stat().st_size, "local_path": str(path)}
            raw_ref = version(raw_file, f"evidence/campaigns/{campaign['campaign_id']}/{identity}/runtime_result.json", "raw-v1")
            key = ec.generate_private_key(ec.SECP384R1())
            public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            (root/"public.pem").write_bytes(public); group["public_key"] = normalizer.reference(root/"public.pem", root)
            group["public_key_sha256"] = hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            payload = {"run_id": run_id, "cell_id": identity, "application_campaign_id": campaign["campaign_id"], "campaign_id": inventory["campaign_id"],
                "execution_successful": False, "raw_result_sha256": raw_ref["sha256"], "anchor": raw["anchor"], "manifest_id": None,
                "model_digest": None, "model_schema_hash": raw["model_schema_hash"], "commit_order": 0}
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            witness = {"algorithm": "ECDSA-P384-SHA384", "payload": payload, "payload_sha256": digest(payload), "public_key_sha256": group["public_key_sha256"],
                "signature_base64": base64.b64encode(key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))).decode()}
            witness_file = case_dir/"operator-witness.json"; witness_file.write_text(json.dumps(witness, sort_keys=True))
            witness_ref = version(witness_file, "anchors/synthetic-deployment/signed.json", "witness-v1")
            inventory["protected_operator_witnesses"] = [{**witness_ref, "cell_id": identity, "application_campaign_id": campaign["campaign_id"], "raw_result_sha256": raw_ref["sha256"]}]
            inventory["retained_artifact_versions"].extend([raw_ref, witness_ref])
            index_path = root/"r/campaign_result.json"; index = normalizer.read(index_path); index["cases"][0]["artifacts"] = [raw_ref]
            index_path.write_text(json.dumps(index, sort_keys=True))
            inventory["export"]["index_sha256"] = normalizer.sha(index_path)
            inventory["retained_artifact_versions"][0].update(sha256=normalizer.sha(index_path), size_bytes=index_path.stat().st_size)
            group["inventory"] = write(root, group["inventory"]["path"], inventory); write(root, ref["path"], spec)
            result = normalizer.normalize(root/ref["path"], evidence_root=root)
            attempt = result["attempts"][0]
            self.assertEqual(attempt["status"], "failed")
            self.assertTrue(attempt["verification"]["protected_witness"])
            self.assertTrue(attempt["verification"]["audit_complete"])
            self.assertFalse(attempt["verification"]["evaluation_bound"])
            self.assertIsNone(attempt["metrics"])
            self.assertIsNone(next(row for row in result["cases"] if row["case_id"] == identity)["metrics"])

    def test_changed_index_version_source_campaign_factor_and_path_fail_closed(self):
        for mode in ("index", "version", "source", "campaign", "factor", "traversal"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); ref, _ = fixture(root, producer_failure=True)
                spec_path = root/ref["path"]; spec = normalizer.read(spec_path); group = spec["groups"][0]
                if mode == "index": (root/"r/campaign_result.json").write_text("{}")
                elif mode == "traversal": group["public_key"]["path"] = "../outside.pem"
                else:
                    name = "adapter_manifest" if mode == "source" else "campaign" if mode in {"campaign", "factor"} else "inventory"
                    path = root/group[name]["path"]; value = normalizer.read(path)
                    if mode == "version": value["export"]["index_version_id"] = "null"
                    if mode == "source": value["new_files_sha256"]["src/pcfl/robust_flower_app.py"] = "a"*64
                    if mode == "campaign": value["campaign_id"] = "another-application"
                    if mode == "factor": value["cases"][0]["runtime"]["robustness"]["factors"]["artificial_latency_ms"] = 250
                    group[name] = write(root, group[name]["path"], value)
                write(root, ref["path"], spec)
                with self.assertRaises(ValueError, msg=mode): normalizer.normalize(spec_path, evidence_root=root)

    def test_deliberate_four_or_six_selected_clients_still_require_eight_physical_actors(self):
        for fraction in (.5, .75):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); inventory = complete_fixture(root)
                snapshot = inventory["learning_placement_snapshots"][0]; application = snapshot["application_campaign_id"]
                selection = normalizer.chosen(296, 1, fraction)
                registry = {str(index): org for index, org in enumerate(sorted(normalizer.ORGS), 1)}
                raw = {"node_registry": registry, "tasks": [{"node_id": int(node), "org_id": org} for node, org in registry.items() if org in selection]}
                self.assertTrue(normalizer.exploratory_placement(inventory, application, inventory["image"]["reference"], raw))
                snapshot["tasks"] = snapshot["tasks"][1:]
                snapshot["snapshot_sha256"] = normalizer.snapshot_sha({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
                with self.assertRaisesRegex(ValueError, "physical_actor"):
                    normalizer.exploratory_placement(inventory, application, inventory["image"]["reference"], raw)

    def test_selected_subset_and_actual_full_budget_reports_are_independent(self):
        case = deepcopy(next(row for row in registry_fixture()["cases"] if row["robustness"]["factors"]["participation_fraction"] == .5))
        data = data_fixture()[0]; settings = case["shared_config"]["training"]
        raw = {"tasks": [], "updates": [], "decisions": {}, "rounds": [], "client_training": []}
        for number in range(1, 6):
            organizations = normalizer.chosen(296, number, .5); round_id = f"round-{number}"
            raw["rounds"].append({"round_id": round_id, "selected_clients": 4, "received_updates": 4, "accepted_updates": 4})
            for org in organizations:
                uid = f"{round_id}-{org}"
                raw["tasks"].append({"round_id": round_id, "org_id": org})
                raw["updates"].append({"round_id": round_id, "org_id": org, "sample_count": 100})
                raw["decisions"][uid] = {"round_id": round_id, "outcome": "accepted"}
                raw["client_training"].append({"round_id": round_id, "org_id": org, "sample_count": 100, "epochs": settings["local_epochs"],
                    "optimizer": settings["optimizer"], "example_exposures": 100*settings["local_epochs"],
                    "batches": 2*settings["local_epochs"], "seed": 296+100*number+sorted(normalizer.ORGS).index(org),
                    "artificial_application_reply_delay_ms": 0, "client_reported_clock_offset_ms": 0})
        self.assertEqual(len(normalizer.selected_proof(raw, case, data)), 5)
        for field, value in (("epochs", 2), ("sample_count", 10), ("client_reported_clock_offset_ms", 60000)):
            changed = deepcopy(raw); changed["client_training"][0][field] = value
            with self.assertRaises(ValueError): normalizer.selected_proof(changed, case, data)
        raw["tasks"][0]["org_id"] = "org_99"
        with self.assertRaisesRegex(ValueError, "selected_subset"): normalizer.selected_proof(raw, case, data)

    def test_actual_policy_event_identity_order_and_lifecycle_brackets_required(self):
        case = deepcopy(registry_fixture()["cases"][0]); expected = normalizer.intended_schedule(296, 5, case["robustness"]["factors"])
        self.assertEqual(expected, case["schedule"])
        raw = {"persistent_run_id": "synthetic-robust-run", "policy_events": [], "tasks": [], "decisions": {}, "published_manifests": []}
        for index, item in enumerate(expected):
            number = 0 if item["round_id"] == "initial" else int(item["round_id"].removeprefix("round-"))
            order = index+1 if number == 0 else number*100+(1 if item["phase"] == "before_round" else 50)
            request = "robust-policy-"+digest([normalizer.PROTOCOL, raw["persistent_run_id"], item])[:40]
            raw["policy_events"].append({"event_id": "policy-"+hashlib.sha256(request.encode()).hexdigest()[:40], "order": order,
                "org_id": item["org_id"], "kind": item["kind"]})
        for number in range(1, 6):
            for org in normalizer.chosen(296, number, case["robustness"]["factors"]["participation_fraction"]):
                raw["tasks"].append({"round_id": f"round-{number}", "org_id": org, "issue_order": number*100+10, "start_order": number*100+11})
                raw["decisions"][f"{number}-{org}"] = {"round_id": f"round-{number}", "evaluation_order": number*100+60}
        normalizer.schedule_proof(raw, case)
        changed = deepcopy(raw); changed["policy_events"][-1]["event_id"] = "forged"
        with self.assertRaisesRegex(ValueError, "event_missing"): normalizer.schedule_proof(changed, case)
        changed = deepcopy(raw); changed["policy_events"].append({"event_id": "unregistered", "order": 59, "org_id": "org_01", "kind": "GRANT"})
        with self.assertRaisesRegex(ValueError, "unregistered_policy"): normalizer.schedule_proof(changed, case)

    def test_protocol_wrapper_uses_real_independent_signature_weighted_and_eval_checks(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        for mode in ("valid", "wrong-pin", "audit", "evaluation", "model"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); raw = persistent_fixture(directory)
                # Full-runtime fixture intentionally omits run_id on final
                # updates; the partial-protocol checker requires it explicitly.
                for decision in raw["decisions"].values(): decision["run_id"] = raw["persistent_run_id"]
                previous = "0"*64
                for audit in raw["audit"]:
                    audit["payload"] = raw["decisions"][audit["payload"]["update_id"]]
                    audit["prev_hash"] = previous
                    previous = digest({name: audit[name] for name in ("sequence", "prev_hash", "payload")})
                    audit["event_hash"] = previous
                raw["anchor"]["head"] = previous
                for row in raw["durable_evidence"]["run_records"]:
                    if row["SK"].startswith("UPDATE#"): row["decision_json"] = json.dumps(raw["decisions"][row["update_id"]])
                    if row["SK"].startswith("AUDIT#"):
                        audit = raw["audit"][int(row["SK"].split("#")[1])-1]
                        row.update(event_json=json.dumps(audit), event_hash=audit["event_hash"])
                    if row["SK"] == "AUDIT_HEAD": row["head"] = previous
                    if row["SK"].startswith("TXN#") and row.get("operation_kind") == "publication":
                        outcome = json.loads(row["result_json"]); outcome["audit_head"] = previous; row["result_json"] = json.dumps(outcome)
                robust = {"adapter_image": "example.invalid@sha256:"+"c"*64, "adapter_source_sha256": "f"*64, "factors": deepcopy(DEFAULTS)}
                case = {"case_id": "synthetic-case", "seed": 296, "distribution": "iid", "robustness": robust, "equivalence_hash": "b"*64, "schedule": [],
                    "architecture": {"model_metadata": {"metadata_digest": "e"*64}, "float32_parameter_bytes": 12},
                    "shared_config": {"model_schema_hash": raw["model_schema_hash"], "validation_sha256": "f"*64, "training": {"max_validation_examples": 4}}}
                raw.update(kind="exploratory_robustness_validation", registered_primary_case=False, aws_used=True, robustness=robust, seed=296,
                    distribution="iid", cloud_campaign_id="synthetic-app", cell_id="synthetic-case", equivalence_hash="b"*64, plan_digest="d"*64,
                    experiment_binding={"plan_digest": "d"*64, "cell_id": "synthetic-case", "equivalence_hash": "b"*64, "family": "exploratory",
                        "policy_schedule_hash": digest([]), "source_sha256": "f"*64}, rounds=[{"duration_seconds": .1}], client_training=[])
                if mode == "audit": raw["audit"].pop()
                if mode == "evaluation": raw["evaluation_service_response"]["model_sha256"] = "0"*64
                if mode == "model":
                    model_path = Path(raw["published_manifests"][0]["artifact"]["local_export"]["path"])
                    model_path.write_bytes(model_path.read_bytes()+b"changed")
                cache = {record["artifact"]["sha256"]: str(Path(record["artifact"]["local_export"]["path"]).relative_to(directory))
                    for record in [*raw["updates"], *raw["published_manifests"]]}
                write(directory, "artifact_paths.json", cache); write(directory, "runtime_result.json", raw)
                key = ec.generate_private_key(ec.SECP384R1()); public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                pin = hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
                last = raw["published_manifests"][-1]
                payload = {"run_id": raw["persistent_run_id"], "cell_id": case["case_id"], "application_campaign_id": "synthetic-app", "campaign_id": "synthetic-deployment",
                    "execution_successful": True, "raw_result_sha256": normalizer.sha(directory/"runtime_result.json"), "anchor": raw["anchor"],
                    "manifest_id": last["manifest_id"], "model_digest": last["model_digest"], "model_schema_hash": raw["model_schema_hash"], "commit_order": last["commit_order"]}
                canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                witness = {"algorithm": "ECDSA-P384-SHA384", "payload": payload, "payload_sha256": digest(payload), "public_key_sha256": pin,
                    "signature_base64": base64.b64encode(key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))).decode()}
                # These three unrelated orchestration obligations are tested
                # independently above; the cryptographic/protocol verifier is real.
                with patch.object(normalizer, "schedule_proof"), patch.object(normalizer, "selected_proof", return_value=[]), patch.object(normalizer, "exploratory_placement"):
                    call = lambda: normalizer.assess_runtime(directory/"runtime_result.json", directory, raw, case,
                        {"splits": {"validation": {"encounters": 4}}}, {"campaign_id": "synthetic-deployment"}, "synthetic-app", witness, public,
                        "0"*64 if mode == "wrong-pin" else pin)
                    if mode == "valid": self.assertEqual(call()["published_models"], 1)
                    else:
                        with self.assertRaises(ValueError, msg=mode): call()


if __name__ == "__main__": unittest.main()
