"""Synthetic owned-backend ingestion boundaries; no clinical/AWS/real gates."""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file())
MODULES = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "cloud_assessment.py").is_file() else ROOT / "scripts"
sys.path[:0] = [str(MODULES), str(ROOT / "src"), str(ROOT / "scripts"), str(ROOT / "tests")]
def load_host(name, filename):
    spec = importlib.util.spec_from_file_location(name, MODULES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


assessment_host = load_host("cloud_assessment", "cloud_assessment.py")
export_verifier = load_host("verify_cloud_campaign", "verify_cloud_campaign.py")
ingestion = load_host("partial_ingestion_under_test", "ingest_experiments.py")
from cloud_assessment import derive_partial_metrics, verify_retained_witness
from anchor_evidence import create_witness, observed_payload
from pcfl.ablation_verify import assess_case
from pcfl.analysis import analyze_registry, write_analysis
from pcfl.evaluation import build_model_metadata
from pcfl.experiments import COUNT_METRICS, append_attempt, digest, file_digest, freeze_plan, load_attempts
from pcfl.flower_app import run_server
from pcfl.governance_service import PolicyWriter
from pcfl.opa import policy_hash
from pcfl.scenarios import ScenarioSignal, ScenarioWatcher
from integration_services import LocalIntegrationServices
from test_ablation_verify import fixture as error_fixture
from test_cloud_placement import complete_fixture
from test_evaluation import preprocessor
from test_experiments import example_plan, synthetic_gate_refs
from test_integrated_runtime import EightNodeGrid
from test_runtime_verify import persistent_fixture
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def signing_key():
    key = ec.generate_private_key(ec.SECP384R1())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return key, public, pin


def add_witness(inventory, raw_path, cell, key, public, pin, *, s3=None):
    raw = json.loads(raw_path.read_bytes())
    head = {"count": {"N": str(raw["anchor"]["count"])}, "head": {"S": raw["anchor"]["head"]}}
    last = raw["published_manifests"][-1] if raw["published_manifests"] else None
    pointer = {"manifest_id": {"S": last["manifest_id"]}} if last else {}
    payload = observed_payload(raw, raw_sha256=file_digest(raw_path), cell_id=cell,
        campaign_id=inventory["campaign_id"], application_id=inventory["application_campaign_id"], head=head, pointer=pointer)
    witness = create_witness(payload, key)
    path = raw_path.parent / "operator_witness.json"
    write(path, witness)
    sha = file_digest(path)
    record = {"cell_id": cell, "application_campaign_id": inventory["application_campaign_id"], "raw_result_sha256": file_digest(raw_path),
        "key": f"anchors/{inventory['campaign_id']}/{hashlib.sha256(cell.encode()).hexdigest()[:24]}/{sha}.json",
        "version_id": "synthetic-immutable-witness-version", "sha256": sha, "public_key_sha256": pin, "local_path": str(path)}
    if s3 is not None:
        record["version_id"] = s3.put_object(Bucket=inventory["foundation"]["bucket_name"], Key=record["key"],
            Body=path.read_bytes(), IfNoneMatch="*", ServerSideEncryption="AES256")["VersionId"]
        response = s3.get_object(Bucket=inventory["foundation"]["bucket_name"], Key=record["key"], VersionId=record["version_id"])
        try: assert response["Body"].read() == path.read_bytes()
        finally: response["Body"].close()
    inventory["protected_operator_witnesses"] = [record]
    public_path = raw_path.parent.parent / "external-operator-public.pem"
    public_path.write_bytes(public)
    return public_path, record


def export_case(root, raw, cell, *, source_bucket="independent-model-bucket", download=None):
    export = root / "r/application"
    case = export / hashlib.sha256(cell.encode()).hexdigest()[:8]
    case.mkdir(parents=True)
    mapping = {}
    for row in raw["updates"] + raw["published_manifests"]:
        artifact = row["artifact"]
        if artifact["sha256"] in mapping:
            continue
        content = download(artifact) if download else Path(artifact["local_export"]["path"]).read_bytes()
        destination = case / "cache" / (artifact["sha256"][:24] + ".npz")
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(content)
        assert file_digest(destination) == artifact["sha256"]
        mapping[artifact["sha256"]] = str(destination.relative_to(case))
    # A cache annotates a copy on read; source raw/candidate hashes never change.
    for row in raw["updates"] + raw["published_manifests"]:
        row["artifact"].pop("local_export", None)
    raw_path = case / "runtime_result.json"
    write(raw_path, raw)
    write(case / "cell.json", {"cell_id": cell})
    write(case / "artifact_paths.json", mapping)
    return export, case, raw_path


class WitnessAndFailedAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key, self.public, self.pin = signing_key()

    def full(self):
        source = self.root / "source"; source.mkdir()
        raw = persistent_fixture(source)
        raw.update(cell_id="cell-1", cloud_campaign_id="application-one")
        export, case, path = export_case(self.root, raw, "cell-1")
        raw_ref = {"bucket": "independent-model-bucket", "key": "evidence/campaigns/application-one/cell-1/runtime_result.json",
            "version_id": "actual-synthetic-source-version", "sha256": file_digest(path), "size_bytes": path.stat().st_size}
        index = {"campaign_id": "application-one", "successful": True, "cases": [{"cell_id": "cell-1", "successful": True, "artifacts": [raw_ref]}]}
        write(export / "campaign_result.json", index)
        inv = {"campaign_id": "master", "application_campaign_id": "application-one", "account_id": "123456789012", "region": "us-east-1",
            "foundation": {"bucket_name": "independent-model-bucket"}, "export": {"export_root": str(export),
                "application_campaign_id": "application-one", "index_key": "evidence/campaigns/application-one/campaign_result.json",
                "index_version_id": "actual-synthetic-index-version", "index_sha256": file_digest(export / "campaign_result.json")}}
        public, record = add_witness(inv, path, "cell-1", self.key, self.public, self.pin)
        inventory_path = self.root / "inventory.json"; write(inventory_path, inv)
        return inv, inventory_path, path, public, record

    def test_successful_full_export_checks_external_pin_and_never_silently_ignores_it(self):
        inv, path, raw, public, _ = self.full()
        report = export_verifier.verify_export(path, witness_public_key=public, witness_public_key_sha256=self.pin)
        self.assertTrue(report["successful"])
        self.assertTrue(report["externally_protected_witnesses_verified"])
        self.assertTrue(report["verified_cases"][0]["protected_operator_witness"]["protected_witness_verified"])
        without = export_verifier.verify_export(path)
        self.assertFalse(without["successful"])
        self.assertEqual(without["unprotected_case_ids"], ["cell-1"])
        with self.assertRaisesRegex(ValueError, "pin_mismatch"):
            export_verifier.verify_export(path, witness_public_key=public, witness_public_key_sha256="0" * 64)
        _, attacker_public, _ = signing_key()
        public.write_bytes(attacker_public)
        with self.assertRaisesRegex(ValueError, "signature_or_external_pin"):
            export_verifier.verify_export(path, witness_public_key=public, witness_public_key_sha256=self.pin)

    def test_witness_version_path_body_and_run_custody_fail_closed(self):
        inv, path, raw, public, record = self.full()
        for field, value in (("version_id", "null"), ("key", "evidence/writable.json"), ("raw_result_sha256", "0" * 64), ("local_path", str(self.root / "outside.json"))):
            changed = deepcopy(inv); changed["protected_operator_witnesses"][0][field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                verify_retained_witness(changed, application="application-one", cell_id="cell-1", raw_path=raw,
                    public_key_path=public, public_key_pin=self.pin)
        witness = json.loads(Path(record["local_path"]).read_bytes())
        witness["payload"]["run_id"] = "different-run"
        witness = create_witness(witness["payload"], self.key)
        write(Path(record["local_path"]), witness)
        record["sha256"] = file_digest(record["local_path"])
        record["key"] = f"anchors/master/{hashlib.sha256(b'cell-1').hexdigest()[:24]}/{record['sha256']}.json"
        with self.assertRaisesRegex(ValueError, "case_run_pointer"):
            verify_retained_witness(inv, application="application-one", cell_id="cell-1", raw_path=raw,
                public_key_path=public, public_key_pin=self.pin)

    def test_failed_partial_keeps_real_error_indeterminate_and_zero_missing_audit_counts(self):
        raw = error_fixture()
        raw.update(successful=False, baseline_id="P1", scenario_id="transport_fault", ablation_id="Abl-3", full_protocol=False,
            ablated_safeguards=["persistent_audit_chain"], test_holdout_evaluated=False,
            measurement_manifest={"schema_version": "0.1.0", "tamper_scope": "this-runtime-invocation", "tamper_mode": "none_declared", "tamper_results": []})
        raw["audit"] = []; raw["anchor"] = {"count": 0, "head": "0" * 64}
        rows = raw["durable_evidence"]["run_records"]
        rows[:] = [row for row in rows if not row["SK"].startswith("AUDIT#")]
        next(row for row in rows if row["SK"] == "AUDIT_HEAD").update(raw["anchor"])
        issued = {key: value for key, value in raw["tasks"][0].items() if key != "nonce_digest"}; issued["start_order"] = None
        next(row for row in rows if row["SK"].startswith("ISSUE#"))["task_json"] = json.dumps(issued)
        second = {**issued, "task_id": "task-2", "update_id": "update-2", "org_id": "org_02", "node_id": 2, "issue_order": 6}
        rows.append({"PK": "RUN#unit", "SK": "ISSUE#task-2", "task_json": json.dumps(second)})
        raw["durable_evidence"]["sequence"]["order"] = 6
        path = self.root / "runtime_result.json"; write(path, raw)
        inv = {"campaign_id": "master", "application_campaign_id": "app", "foundation": {"bucket_name": "test-bucket"}}
        public, _ = add_witness(inv, path, "failed-cell", self.key, self.public, self.pin)
        witness, pem, _ = verify_retained_witness(inv, application="app", cell_id="failed-cell", raw_path=path, public_key_path=public, public_key_pin=self.pin)
        assessment = assess_case(path, witness=witness, public_key_pem=pem, expected_public_key_sha256=self.pin)
        metrics, sources, timing = derive_partial_metrics(raw, assessment)
        self.assertEqual(assessment["final_error_count"], 1)
        self.assertEqual(assessment["indeterminate_count"], 1)
        self.assertEqual(metrics["final_decisions"], 1)
        self.assertEqual(metrics["audit_complete_decisions"], 0)
        self.assertEqual(metrics["audit_record_sets_verified"], 0)
        self.assertEqual(metrics["selected_eligible_clients"], 2)
        self.assertFalse(timing["runtime_observations_verified"])
        self.assertIsNone(metrics.get("auroc"))
        self.assertEqual(COUNT_METRICS - set(metrics), set())


@unittest.skipUnless(os.environ.get("PCFL_LOCAL_INTEGRATION") == "1", "explicit owned local SDK/OPA integration")
class ActualPartialIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.services = LocalIntegrationServices(cls.root / "services")
        cls.services.__enter__()
        cls.key, cls.public, cls.pin = signing_key()
        cls.fixtures = {}

    @classmethod
    def tearDownClass(cls):
        cls.services.__exit__(None, None, None)
        cls.temp.cleanup()

    def make_fixture(self, variant=None, *, fault=None):
        identity = (variant or "P1") + ("-failed" if fault == "opa_transport_unavailable" else "")
        if identity in self.fixtures:
            return self.fixtures[identity]
        root = self.root / identity; root.mkdir()
        fake = root / "fake-project"; (fake / "src").mkdir(parents=True)
        (fake / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
        candidate = example_plan(frozen_training=True)
        plan = freeze_plan(candidate, synthetic_gate_refs(candidate, fake), fake)
        cell = next(row for row in plan["ablation_cells" if variant else "primary_cells"]
            if row["variant"] == variant and row["baseline_id"] == "P1" and row["distribution"] == "iid" and row["seed"] == 296
            and (variant is not None or row["scenario_id"] == "S0"))
        shared = cell["shared_config"]
        metadata = build_model_metadata(preprocessor(), seed=296)
        runtime = {"node_registry": {str(i): f"org_{i:02d}" for i in range(1, 9)}, "baseline_id": "P1",
            "scenario_id": cell["scenario_id"], "scenario_target_org": shared["policy_schedule"]["target_org"],
            "scenario_control": True, "rounds": 5, "seed": 296, "max_examples_per_client": shared["training"]["max_examples_per_client"],
            "validation_max_examples": shared["training"]["max_validation_examples"], "training": shared["training"],
            "validation_source_sha256": shared["validation_sha256"], "model_metadata": metadata,
            "authority_backend": "dynamodb-s3-ablation" if variant else "dynamodb-s3-opa", "storage": {"local_emulation": True},
            "table_name": self.services.table, "bucket": self.services.bucket, "persistent_run_id": "native-" + identity,
            "output_dir": str(root / "runtime"), "message_timeout_seconds": 2,
            "opa": {"endpoint": self.services.opa_endpoint, "allow_loopback_http": True, "expected_rule_hash": policy_hash()},
            "evaluator": {"endpoint": "https://synthetic.invalid"},
            "plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"], "match_id": cell["match_id"],
            "equivalence_hash": cell["equivalence_hash"], "distribution": "iid", "experiment_binding": {
                "plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"], "equivalence_hash": cell["equivalence_hash"],
                "family": cell["family"], "policy_schedule_hash": shared["policy_schedule_hash"], "source_sha256": plan["provenance"]["source_sha256"]}}
        if variant: runtime.update(ablation_id=variant, full_protocol=False)
        if cell["scenario_id"] == "S8": runtime["scripted_fault"] = fault or "audit_transport_unavailable"
        writer = PolicyWriter(self.services.ddb, self.services.table); writer.initialize()
        watcher = ScenarioWatcher(writer, {"runs": [{"run_id": runtime["persistent_run_id"], "scenario_id": cell["scenario_id"], "rounds": 5,
            "target_org": runtime["scenario_target_org"]}]}).start()
        def evaluate(request):
            metrics = {"count": 4, "positive_count": 2, "prevalence": .5, "auroc": .5, "auprc": .5,
                       "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7}
            return {"schema_version": "0.1.0", "request_id": "synthetic-evaluation", **{key: request[key] for key in
                ("run_id", "manifest_id", "round_id", "model_schema_hash", "parameters_digest")},
                "model_sha256": request["artifact"]["sha256"], "metadata_digest": metadata["metadata_digest"],
                "validation_sha256": shared["validation_sha256"], "validation_sample_digest": "e" * 64,
                "dataset_role": "validation", "final_test_evaluated": False, "manifest_verified": True, "metrics": metrics}
        try:
            with redirect_stdout(io.StringIO()), patch("pcfl.service_io.sdk_clients", return_value=(self.services.ddb, self.services.s3)), \
                    patch("pcfl.evaluation.EvaluationClient", return_value=SimpleNamespace(evaluate=evaluate)):
                ScenarioSignal(self.services.ddb, self.services.table, runtime["persistent_run_id"], cell["scenario_id"],
                    target_org=runtime["scenario_target_org"]).reach("before_run")
                try: run_server(EightNodeGrid(), runtime)
                except Exception:
                    if fault != "opa_transport_unavailable": raise
        finally:
            watcher.stop()
        raw = json.loads((root / "runtime/runtime_result.json").read_bytes())
        raw.update(cloud_campaign_id="campaign-one", cell_id=cell["cell_id"], model_metadata_digest=metadata["metadata_digest"],
            validation_source_sha256=shared["validation_sha256"], case_started_at_utc="2026-01-01T00:00:00Z",
            case_finished_at_utc="2026-01-01T00:01:00Z", elapsed_seconds=60)
        def download(ref):
            response = self.services.s3.get_object(Bucket=ref["bucket"], Key=ref["key"], VersionId=ref["version_id"])
            try: return response["Body"].read()
            finally: response["Body"].close()
        export, directory, raw_path = export_case(root, raw, cell["cell_id"], download=download)
        (root / "placement").mkdir()
        inventory = complete_fixture(root / "placement")
        reference = plan["provenance"]["image_digests"]["runtime"]
        inventory.update(application_campaign_id="campaign-one", image={"reference": reference}, observed_tasks=[])
        inventory["foundation"].update(bucket_name=self.services.bucket, state_table_name=self.services.table,
            image_repositories={"runtime": reference.split("@")[0]})
        snap = inventory["learning_placement_snapshots"][0]
        snap["image_relations"] = {"leaf": {"pinned_reference": reference, "verified": True}}
        for task in snap["tasks"]: task["definition_image"] = reference
        from validate_cloud_placement import sha
        snap["snapshot_sha256"] = sha({key: value for key, value in snap.items() if key != "snapshot_sha256"})
        for template in [*inventory["runtime_plan"]["client_access_probe_templates"], inventory["runtime_plan"]["coordinator_access_probe_template"]]:
            env = template["overrides"]["containerOverrides"][0]["environment"][0]
            value = json.loads(env["value"]); value["bucket"] = self.services.bucket; value["table_name"] = self.services.table; env["value"] = json.dumps(value)
        inventory["uploads"] = [{"sha256": value, "version_id": "synthetic-frozen-upload-version"} for value in shared["partition_hashes"].values()]
        key = f"evidence/campaigns/campaign-one/{cell['cell_id']}/runtime_result.json"
        version = self.services.s3.put_object(Bucket=self.services.bucket, Key=key, Body=raw_path.read_bytes())["VersionId"]
        raw_ref = {"bucket": self.services.bucket, "key": key, "version_id": version, "sha256": file_digest(raw_path), "size_bytes": raw_path.stat().st_size}
        index = {"campaign_id": "campaign-one", "successful": raw["successful"], "started_at_utc": raw["case_started_at_utc"],
            "finished_at_utc": raw["case_finished_at_utc"], "node_registry": runtime["node_registry"],
            "cases": [{"cell_id": cell["cell_id"], "successful": raw["successful"], "artifacts": [raw_ref]}]}
        write(export / "campaign_result.json", index)
        index_version = self.services.s3.put_object(Bucket=self.services.bucket, Key="evidence/campaigns/campaign-one/campaign_result.json",
            Body=(export / "campaign_result.json").read_bytes())["VersionId"]
        inventory["export"] = {"application_campaign_id": "campaign-one", "export_root": str(export),
            "index_key": "evidence/campaigns/campaign-one/campaign_result.json", "index_version_id": index_version,
            "index_sha256": file_digest(export / "campaign_result.json"), "cases": 1, "case_directories": {cell["cell_id"]: str(directory)}}
        public, witness_record = add_witness(inventory, raw_path, cell["cell_id"], self.key, self.public, self.pin, s3=self.services.s3)
        inventory_path, campaign_path = root / "inventory.json", root / "campaign.json"
        write(inventory_path, inventory)
        write(campaign_path, {"campaign_id": "campaign-one", "cases": [{"cell_id": cell["cell_id"], "runtime": runtime}]})
        value = SimpleNamespace(root=root, plan=plan, cell=cell, raw=raw, raw_path=raw_path, inventory=inventory,
            inventory_path=inventory_path, campaign_path=campaign_path, public=public, witness_record=witness_record)
        self.fixtures[identity] = value
        return value

    def ingest(self, fixture, suffix="result", **options):
        output, ledger = fixture.root / suffix, fixture.root / (suffix + ".jsonl")
        result = ingestion.ingest_cloud(fixture.plan, fixture.inventory_path, fixture.campaign_path, ledger, output,
            witness_public_key=fixture.public, witness_public_key_sha256=self.pin, **options)
        row = load_attempts(ledger, fixture.plan)[0]
        assessment = json.loads(next(output.glob("cloud-*.json")).read_bytes())
        assessment["test_placement_checks"] = json.loads((output / "placement.json").read_bytes())["checks"]
        return result, row, assessment

    def test_all_four_real_five_round_partial_variants_ingest_numeric_qualified_scope(self):
        for variant in ("Abl-1", "Abl-2", "Abl-3", "Abl-4"):
            with self.subTest(variant=variant):
                fixture = self.make_fixture(variant)
                original = fixture.raw_path.read_bytes()
                _, row, assessment = self.ingest(fixture)
                self.assertEqual(row["status"], "successful", {"reasons": assessment["exclusion_reasons"], "placement": assessment["test_placement_checks"]})
                self.assertEqual(row["reason_code"], "partial-qualified-ablation")
                self.assertTrue(assessment["partial_qualified"])
                self.assertFalse(assessment["full_protocol_pass"])
                self.assertTrue(assessment["summary"]["protected_witness_verified"])
                self.assertEqual(COUNT_METRICS - set(row["metrics"]), set())
                self.assertEqual(row["metrics"]["evaluation_split"], "validation")
                self.assertEqual(row["metrics"]["auroc"], .5)
                self.assertEqual(row["metrics"]["published_models"], 5)
                expected = {"Abl-1": (36, 35, 1, 0), "Abl-2": (36, 35, 1, 0),
                            "Abl-3": (40, 40, 0, 0), "Abl-4": (40, 40, 1, 1)}[variant]
                self.assertEqual(tuple(row["metrics"][name] for name in ("unique_presented_updates", "accepted_updates",
                    "oracle_invalid_presented", "oracle_invalid_incorporations")), expected)
                self.assertEqual(fixture.raw_path.read_bytes(), original)
                if variant == "Abl-3":
                    self.assertEqual(row["metrics"]["final_decisions"], 40)
                    self.assertEqual(row["metrics"]["audit_complete_decisions"], 0)
                    self.assertEqual(row["metrics"]["audit_record_sets_verified"], 0)
                    self.assertEqual(len(assessment["summary"]["missing_final_audit_update_ids"]), 40)
                if variant == "Abl-4":
                    self.assertGreater(row["metrics"]["oracle_invalid_incorporations"], 0)
                analysis = analyze_registry(fixture.plan, [row])
                self.assertFalse(analysis["confirmatory_verdict_permitted"])
                self.assertEqual(next(x for x in analysis["tables"]["audit"] if x["baseline_id"] == "P1")["attempts"], 0)

    def test_failed_S8_is_failed_with_preserved_partial_counts_and_no_fabricated_utility(self):
        fixture = self.make_fixture("Abl-3", fault="opa_transport_unavailable")
        _, row, assessment = self.ingest(fixture)
        self.assertFalse(fixture.raw["successful"])
        self.assertEqual(row["status"], "failed")
        self.assertIn("runtime-reported-failure", assessment["exclusion_reasons"])
        self.assertFalse(assessment["partial_qualified"])
        self.assertFalse(assessment["full_protocol_pass"])
        self.assertGreater(row["metrics"]["final_decisions"], 0)
        self.assertEqual(row["metrics"]["audit_complete_decisions"], 0)
        self.assertEqual(row["metrics"]["evaluation_split"], "none")
        self.assertNotIn("auroc", row["metrics"])
        self.assertIn("indeterminate_count", assessment["summary"])
        self.assertEqual(row["metrics"]["unique_presented_updates"], 16)
        self.assertEqual(row["metrics"]["accepted_updates"], 8)
        self.assertEqual(assessment["summary"]["final_deny_count"], 8)

    def test_actual_full_protocol_requires_external_witness_but_primary_verifier_is_unchanged(self):
        fixture = self.make_fixture()
        _, row, assessment = self.ingest(fixture)
        self.assertEqual(row["status"], "successful", {"reasons": assessment["exclusion_reasons"], "placement": assessment["test_placement_checks"]})
        self.assertFalse(assessment["partial_qualified"])
        self.assertTrue(assessment["summary"]["persistent_protocol_verified"])
        self.assertTrue(assessment["protected_operator_witness"]["protected_witness_verified"])
        ledger, output = fixture.root / "unprotected.jsonl", fixture.root / "unprotected"
        ingestion.ingest_cloud(fixture.plan, fixture.inventory_path, fixture.campaign_path, ledger, output)
        row = load_attempts(ledger, fixture.plan)[0]
        self.assertEqual(row["status"], "excluded")
        self.assertEqual(row["metrics"]["audit_record_sets_verified"], 0)
        self.assertIn("external-protected-operator-witness-unverified", row["observation"]["exclusion_reasons"])

    def test_partial_cannot_be_relabelled_primary_or_variant_rebound_even_with_new_signed_raw(self):
        fixture = self.make_fixture("Abl-4")
        campaign = json.loads(fixture.campaign_path.read_bytes())
        campaign["cases"][0]["runtime"]["ablation_id"] = "Abl-1"
        write(fixture.campaign_path, campaign)
        _, row, assessment = self.ingest(fixture, "wrong-variant")
        self.assertEqual(row["status"], "excluded")
        self.assertFalse(assessment["partial_qualified"])
        self.assertIn("partial-evidence-not-qualified-registered-ablation", assessment["exclusion_reasons"])


if __name__ == "__main__":
    unittest.main()
