"""Temporary signed synthetic witnesses and fake S3; no actual AWS calls."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
import anchor_evidence as anchor
import witness_retention as retention
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class WitnessRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.directory = self.root / "results/aws/synthetic-campaign"; self.directory.mkdir(parents=True)
        (self.root / "reports").mkdir()
        self.path = self.directory / "inventory.json"
        self.key = ec.generate_private_key(ec.SECP384R1())
        self.public = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_path = self.directory / "operator-witness-public.pem"; self.public_path.write_bytes(self.public)
        (self.directory / "operator-witness.key").write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.pin = hashlib.sha256(self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.account, self.campaign, self.cell = "111111111111", "synthetic-campaign", "synthetic-P1-S0-296"
        self.bucket = "pcfl-synthetic-111111111111-us-east-1"
        self.raw = {"persistent_run_id":"synthetic-run", "anchor":{"count":2,"head":"a"*64}, "model_schema_hash":"b"*64,
            "successful":True,"published_manifests":[{"manifest_id":"c"*64,"model_digest":"d"*64,"commit_order":10}]}
        self.case = self.directory / "r" / hashlib.sha256(self.cell.encode()).hexdigest()[:8]; self.case.mkdir(parents=True)
        self.raw_body = anchor.canonical(self.raw); self.raw_sha = hashlib.sha256(self.raw_body).hexdigest()
        self.raw_path = self.case / "runtime_result.json"; self.raw_path.write_bytes(self.raw_body)
        raw_ref = {"bucket":self.bucket,"key":f"evidence/campaigns/{self.campaign}/{self.cell}/runtime_result.json",
            "version_id":"raw-version","sha256":self.raw_sha,"size_bytes":len(self.raw_body),"local_path":str(self.raw_path)}
        self.payload = {"schema_version":"0.1.0","campaign_id":self.campaign,"application_campaign_id":self.campaign,"cell_id":self.cell,
            "run_id":"synthetic-run","raw_result_sha256":self.raw_sha,"anchor":self.raw["anchor"],"manifest_id":"c"*64,
            "model_digest":"d"*64,"model_schema_hash":"b"*64,"commit_order":10,"execution_successful":True,
            "operator_observed_at_utc":"2026-11-13T00:00:00Z"}
        self.inventory = {"account_id":self.account,"region":"us-east-1","project_id":"pcfl-synthetic","campaign_id":self.campaign,
            "foundation":{"bucket_name":self.bucket,"state_table_name":"synthetic-table"},"retained_artifact_versions":[raw_ref],
            "protected_operator_witnesses":[]}
        self.objects = {}; self.s3 = Mock()
        self.s3.get_bucket_versioning.return_value = {"Status":"Enabled"}
        self.s3.get_object.side_effect = self.get
        self.s3.put_object.side_effect = self.put
        self.sts = Mock(); self.sts.get_caller_identity.return_value={"Account":self.account}
        self.ddb = Mock(); self.ddb.get_item.side_effect = lambda **kw: {"Item":
            {"count":{"N":"2"},"head":{"S":"a"*64}} if kw["Key"]["SK"] == {"S":"AUDIT_HEAD"} else {"manifest_id":{"S":"c"*64}}}
        self.add_witness(); self.save()

    def add_witness(self, *, legacy=False):
        payload=deepcopy(self.payload)
        if legacy:
            payload.pop("application_campaign_id"); payload.pop("execution_successful")
        body=anchor.canonical(anchor.create_witness(payload,self.key)); sha=hashlib.sha256(body).hexdigest()
        key=f"anchors/{self.campaign}/{hashlib.sha256(self.cell.encode()).hexdigest()[:24]}/{sha}.json"
        local=self.case/("operator_witness-"+sha[:8]+".json");local.write_bytes(body)
        record={"cell_id":self.cell,"key":key,"version_id":"witness-version","sha256":sha,"public_key_sha256":self.pin,"local_path":str(local)}
        if not legacy: record.update(application_campaign_id=self.campaign,raw_result_sha256=self.raw_sha)
        self.inventory["protected_operator_witnesses"]=[record];self.objects[(key,"witness-version")]=body
        return record

    def get(self,**kw):
        self.assertEqual(kw["Bucket"],self.bucket);self.assertEqual(kw["ExpectedBucketOwner"],self.account)
        body=self.objects[(kw["Key"],kw["VersionId"])]
        return {"Body":io.BytesIO(body),"VersionId":kw["VersionId"],"ContentLength":len(body),"ServerSideEncryption":"AES256"}

    def put(self,**kw):
        self.assertEqual(kw["ExpectedBucketOwner"],self.account);self.assertEqual(kw["ServerSideEncryption"],"AES256");self.assertEqual(kw["IfNoneMatch"],"*")
        self.objects[(kw["Key"],"new-witness-version")]=kw["Body"]
        return {"VersionId":"new-witness-version"}

    def save(self): self.path.write_text(json.dumps(self.inventory,sort_keys=True))

    def retain(self,inventory=None):
        return retention.retain_recorded_witnesses(inventory or self.inventory,self.s3,directory=self.directory,
            public_key_pem=self.public,expected_public_key_sha256=self.pin)

    def backfill(self,**kwargs):
        with patch.object(retention,"ROOT",self.root):
            return retention.backfill_inventory(self.path,public_key_path=self.public_path,expected_public_key_sha256=self.pin,
                expected_inventory_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),apply=True,
                clients={"sts":self.sts,"s3":self.s3},**kwargs)

    def test_exact_GET_owner_version_SSE_signature_raw_binding_and_legacy_metadata(self):
        record=self.add_witness(legacy=True);before=deepcopy(self.inventory);body=Path(record["local_path"]).read_bytes()
        updated,receipt,result=self.retain()
        self.assertEqual(result["versions_added"],1);self.assertEqual(len(updated["retained_artifact_versions"]),2)
        normalized=updated["protected_operator_witnesses"][0]
        self.assertEqual(normalized["raw_result_sha256"],self.raw_sha);self.assertEqual(normalized["application_campaign_id"],self.campaign)
        self.assertEqual(normalized["size_bytes"],len(body));self.assertEqual(receipt["verified_references"][0]["server_side_encryption"],"AES256")
        self.assertEqual(before,self.inventory);self.assertEqual(body,Path(record["local_path"]).read_bytes())
        self.s3.list_object_versions.assert_not_called();self.s3.put_object.assert_not_called();self.s3.delete_objects.assert_not_called()

    def test_backfill_is_idempotent_without_signing_or_changing_raw_or_pointer_fields(self):
        raw=self.raw_path.read_bytes();protected=Path(self.inventory["protected_operator_witnesses"][0]["local_path"]).read_bytes()
        with patch.object(anchor,"create_witness",side_effect=AssertionError("no_resigning")):
            first=self.backfill();before=self.path.read_bytes();second=self.backfill()
        self.assertEqual(first["versions_added"],1);self.assertEqual(second["versions_added"],0);self.assertEqual(before,self.path.read_bytes())
        self.assertEqual(len(json.loads(before)["operator_witness_retention_receipts"]),1)
        self.assertEqual(self.raw_path.read_bytes(),raw);self.assertEqual(Path(self.inventory["protected_operator_witnesses"][0]["local_path"]).read_bytes(),protected)

    def test_version_SSE_length_digest_and_unversioned_bucket_fail_closed(self):
        for name,value in (("VersionId","wrong"),("ServerSideEncryption",None),("ContentLength",1),("body",b"changed")):
            response=self.get(Bucket=self.bucket,ExpectedBucketOwner=self.account,Key=self.inventory["protected_operator_witnesses"][0]["key"],VersionId="witness-version")
            if name=="body":response["Body"]=io.BytesIO(value)
            else:response[name]=value
            self.s3.get_object.side_effect=None;self.s3.get_object.return_value=response
            with self.assertRaises(ValueError):self.retain()
            self.assertTrue(response["Body"].closed)
        self.s3.get_bucket_versioning.return_value={}
        with self.assertRaisesRegex(ValueError,"versioned"):self.retain()

    def test_wrong_external_key_or_rebound_signed_payload_cannot_enter_retention(self):
        with self.assertRaisesRegex(ValueError,"signature"):
            retention.retain_recorded_witnesses(self.inventory,self.s3,directory=self.directory,public_key_pem=self.public,expected_public_key_sha256="e"*64)
        witness=json.loads(Path(self.inventory["protected_operator_witnesses"][0]["local_path"]).read_text());witness["payload"]["cell_id"]="another-cell"
        witness["payload_sha256"]=hashlib.sha256(anchor.canonical(witness["payload"])).hexdigest()
        body=anchor.canonical(witness);sha=hashlib.sha256(body).hexdigest();record=self.inventory["protected_operator_witnesses"][0]
        record["sha256"]=sha;record["key"]=f"anchors/{self.campaign}/{hashlib.sha256(self.cell.encode()).hexdigest()[:24]}/{sha}.json"
        Path(record["local_path"]).write_bytes(body);self.objects[(record["key"],record["version_id"])]=body
        with self.assertRaisesRegex(ValueError,"signature"):self.retain()

    def test_signed_wrong_scope_or_original_raw_model_mismatch_reject(self):
        for field,value in (("campaign_id","foreign-campaign"),("raw_result_sha256","f"*64),("manifest_id","e"*64)):
            payload=deepcopy(self.payload);payload[field]=value;body=anchor.canonical(anchor.create_witness(payload,self.key));sha=hashlib.sha256(body).hexdigest()
            inventory=deepcopy(self.inventory);record=inventory["protected_operator_witnesses"][0];record["sha256"]=sha
            record["key"]=f"anchors/{self.campaign}/{hashlib.sha256(self.cell.encode()).hexdigest()[:24]}/{sha}.json"
            local=self.case/("changed-"+field+".json");local.write_bytes(body);record["local_path"]=str(local)
            self.objects[(record["key"],record["version_id"])]=body
            with self.assertRaises(ValueError):self.retain(inventory)

    def test_missing_retained_raw_corrupt_cache_and_outside_paths_are_not_repaired(self):
        missing=deepcopy(self.inventory);missing["retained_artifact_versions"]=[]
        with self.assertRaisesRegex(ValueError,"raw_result_not"):self.retain(missing)
        updated,_,_=self.retain();cached=updated["retained_artifact_versions"][-1]
        bad=self.directory/"bad-cache.json";bad.write_bytes(b"bad");cached["local_path"]=str(bad)
        with self.assertRaisesRegex(ValueError,"corruption"):self.retain(updated)
        outside=self.root/"outside.json";outside.write_bytes(Path(self.inventory["protected_operator_witnesses"][0]["local_path"]).read_bytes())
        wrong=deepcopy(self.inventory);wrong["protected_operator_witnesses"][0]["local_path"]=str(outside)
        with self.assertRaisesRegex(ValueError,"outside"):self.retain(wrong)

    def test_duplicate_or_unrecorded_versions_are_never_discovered_or_adopted(self):
        unknown=next(iter(self.objects));self.objects[(unknown[0],"unknown-version")]=b"unknown"
        updated,_,_=self.retain()
        self.assertNotIn("unknown-version",[row["version_id"] for row in updated["retained_artifact_versions"]])
        self.s3.list_object_versions.assert_not_called()
        duplicate=deepcopy(self.inventory);duplicate["protected_operator_witnesses"]*=2
        with self.assertRaisesRegex(ValueError,"duplicate"):self.retain(duplicate)

    def test_wrong_STS_or_stale_inventory_SHA_reject_before_S3(self):
        before=self.path.read_bytes();self.sts.get_caller_identity.return_value={"Account":"222222222222"}
        with self.assertRaisesRegex(ValueError,"STS"):self.backfill()
        self.s3.get_object.assert_not_called();self.assertEqual(before,self.path.read_bytes())
        with self.assertRaisesRegex(ValueError,"expected_inventory_SHA"):
            retention.backfill_inventory(self.path,public_key_path=self.public_path,expected_public_key_sha256=self.pin,
                expected_inventory_sha256="f"*64,apply=True,clients={"sts":self.sts,"s3":self.s3})

    def test_inventory_change_during_read_preserves_newer_bytes_and_cannot_authorize_purge(self):
        original_get=self.get;changed=b'{"newer_independent_writer":true}'
        def collide(**kwargs):
            response=original_get(**kwargs);self.path.write_bytes(changed);return response
        self.s3.get_object.side_effect=collide
        with self.assertRaisesRegex(ValueError,"CAS"):self.backfill()
        self.assertEqual(self.path.read_bytes(),changed);self.s3.delete_objects.assert_not_called()

    def test_preview_performs_no_AWS_or_local_changes(self):
        before=self.path.read_bytes()
        with patch("boto3.client",side_effect=AssertionError("no_AWS")):
            result=retention.backfill_inventory(self.path,public_key_path=self.public_path,expected_public_key_sha256=self.pin)
        self.assertFalse(result["aws_calls"]);self.assertEqual(before,self.path.read_bytes())

    def _fresh_anchor_setup(self):
        self.inventory["protected_operator_witnesses"]=[]
        index={"campaign_id":self.campaign,"cases":[{"cell_id":self.cell,"artifacts":[self.inventory["retained_artifact_versions"][0]]}]}
        index_body=anchor.canonical(index);root=self.case.parent;(root/"campaign_result.json").write_bytes(index_body)
        self.inventory["export"]={"export_root":str(root),"index_sha256":hashlib.sha256(index_body).hexdigest(),"application_campaign_id":self.campaign}
        self.save()

    def _run_anchor(self):
        clients={"sts":self.sts,"s3":self.s3,"dynamodb":self.ddb}
        with patch("boto3.client",side_effect=lambda name,**kwargs:clients[name]),patch.object(anchor,"ROOT",self.root):
            return anchor.anchor_inventory(self.path,apply=True)

    def test_future_anchor_immediately_retains_new_version_and_rerun_does_not_resign(self):
        self._fresh_anchor_setup();first=self._run_anchor()
        self.assertEqual(first["protected_witnesses_created"],1);self.assertEqual(first["protected_witness_versions_newly_retained"],1)
        before=self.path.read_bytes()
        with patch.object(anchor,"create_witness",side_effect=AssertionError("do_not_resign")):second=self._run_anchor()
        self.assertEqual(second["protected_witnesses_created"],0);self.assertEqual(before,self.path.read_bytes());self.assertEqual(self.s3.put_object.call_count,1)

    def test_future_GET_failure_preserves_recorded_version_for_backfill_without_new_signature(self):
        self._fresh_anchor_setup();self.s3.get_object.side_effect=RuntimeError("synthetic_read_transport_failure")
        with self.assertRaises(RuntimeError):self._run_anchor()
        partial=json.loads(self.path.read_text());self.assertEqual(len(partial["protected_operator_witnesses"]),1)
        self.assertEqual(len(partial["retained_artifact_versions"]),1)
        self.s3.get_object.side_effect=self.get
        with patch.object(anchor,"create_witness",side_effect=AssertionError("do_not_resign")):result=self._run_anchor()
        self.assertEqual(result["protected_witnesses_created"],0);self.assertEqual(result["protected_witness_versions_newly_retained"],1)
        self.assertEqual(self.s3.put_object.call_count,1)
