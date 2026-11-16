"""Staged public-bundle security fixtures, never clinical results or private data."""
from copy import deepcopy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(parent for parent in STAGE.parents if (parent / "pyproject.toml").is_file())
MODULE = STAGE / "public_release.py" if (STAGE / "public_release.py").is_file() else ROOT / "scripts/public_release.py"
SPEC = importlib.util.spec_from_file_location("staged_public_release", MODULE)
PUBLIC = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PUBLIC)


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def json_bytes(value): return json.dumps(value, sort_keys=True, allow_nan=False).encode()


def reference(path, root):
    return {"path": path.resolve().relative_to(root.resolve()).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def claims_csv(rows):
    stream = io.StringIO(newline=""); writer = csv.DictWriter(stream, fieldnames=sorted({name for row in rows for name in row}))
    writer.writeheader()
    for row in rows:
        writer.writerow({name: json.dumps(value, sort_keys=True, allow_nan=False) if isinstance(value, (list, dict)) else value for name,value in row.items()})
    return stream.getvalue().encode()


def fixture(root, *, tree_name="report-tree"):
    tree = root/tree_name
    plan = {"plan_digest": "a"*64, "provenance": {"source_files_sha256": {"scripts/report_final_artifacts.py": "b"*64}}}
    attempts = []; attempt_digest = PUBLIC.digest(attempts); analysis = {"scope": "synthetic-test-only", "attempt_count": 0}
    claims = [{"RQ": f"RQ{number}", "plan_digest": plan["plan_digest"], "attempts_digest": attempt_digest,
        "figure_links": [{"path": "figures/plot.svg", "sha256": "replaced-below"}], "table_links": [{"path": "claim_evidence_matrix.csv"}]} for number in range(1,5)]
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>'
    svg_sha = hashlib.sha256(svg).hexdigest()
    for row in claims: row["figure_links"][0]["sha256"] = svg_sha
    files = {"reports/"+name+".md": b"Synthetic aggregate reporting fixture. No scientific claim.\n" for name in
             ("results","limitations","design_principles","validation_findings","final_validation")}
    files.update({"claim_evidence_matrix.json": json_bytes(claims), "claim_evidence_matrix.csv": claims_csv(claims),
        "evidence_references.json": b"[]", "tables/analysis.json": json_bytes(analysis), "figures/plot.svg": svg})
    for name, body in files.items(): write(tree/name, body)
    inputs = {"accepted_plan": {"sha256": "c"*64}, "figure_attempts": {"sha256": "d"*64}, "analysis": {"sha256": hashlib.sha256(files["tables/analysis.json"]).hexdigest()}}
    manifest = {"kind": "bound-final-reporting-drafts", "successful": True, "assessment_scope": "reporting-input-integrity-only",
        "all_phases_complete": False, "plan_digest": plan["plan_digest"], "attempts_digest": attempt_digest, "source_sha256": "b"*64,
        "files_sha256": {name: hashlib.sha256(body).hexdigest() for name,body in files.items()}, "inputs": inputs,
        "figures": [{"path": "plot.svg", "sha256": svg_sha, "figure_id": "plot"}]}
    manifest_path = tree/"reporting_manifest.json"; write(manifest_path, json_bytes(manifest))
    figure_manifest = {"kind": "reproducible-descriptive-research-figures", "plan_digest": plan["plan_digest"], "all_attempts_retained": 0,
        "input_sha256": {"plan": inputs["accepted_plan"]["sha256"], "attempts": inputs["figure_attempts"]["sha256"], "analysis": inputs["analysis"]["sha256"]},
        "files": [{"path": "plot.svg", "sha256": svg_sha}]}
    figure_path = root/"figure-source.json"; write(figure_path, json_bytes(figure_manifest))
    spec = {"schema_version": "0.1.0", "kind": "reviewed-public-release-attachments", "artifact_version": "synthetic-v1",
        "plan_digest": plan["plan_digest"], "attempts_digest": attempt_digest, "reporting_manifest": reference(manifest_path,root),
        "files": [{"source": reference(tree/name,root), "destination": "reporting/"+name, "category": "reporting"} for name in files]}
    spec["files"].extend([{"source": spec["reporting_manifest"], "destination": "reporting/reporting_manifest.json", "category": "reporting"},
        {"source": reference(figure_path,root), "destination": "reporting/figures/figures_manifest.json", "category": "figure_manifest"}])
    return spec, plan, attempts, analysis, tree


def rebind(root, spec, tree, name, body):
    write(tree/name, body)
    for row in spec["files"]:
        if row["destination"] == "reporting/"+name: row["source"] = reference(tree/name, root)
    manifest_path = tree/"reporting_manifest.json"; manifest = json.loads(manifest_path.read_bytes())
    manifest["files_sha256"][name] = hashlib.sha256(body).hexdigest()
    write(manifest_path,json_bytes(manifest)); spec["reporting_manifest"] = reference(manifest_path,root)
    for row in spec["files"]:
        if row["destination"] == "reporting/reporting_manifest.json": row["source"] = spec["reporting_manifest"]


class PublicAttachmentSecurityTests(unittest.TestCase):
    def invoke(self, root, values, *, output=None):
        spec, plan, attempts, analysis, _ = values
        with patch("pcfl.analysis.analyze_registry", return_value=analysis):
            return PUBLIC.public_attachments(spec,plan,attempts,output or root/"bundle",root=root)

    def test_explicit_complete_public_tree_copies_exact_bytes_and_no_completion_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); values=fixture(root); result=self.invoke(root,values)
            self.assertTrue(result["successful"])
            self.assertEqual(result["public_file_count"],12)
            self.assertFalse(result["clinical_records_included"]); self.assertFalse(result["study_completion_inferred"])
            for row in values[0]["files"]:
                self.assertEqual((root/row["source"]["path"]).read_bytes(),(root/"bundle"/row["destination"]).read_bytes())

    def test_path_traversal_absolute_backslash_and_casefold_collision_rejected(self):
        for destination in ("reporting/../escape.md","C:/escape.md","/escape.md",r"reporting\escape.md"):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve(); values=fixture(root); values[0]["files"][0]["destination"]=destination
                with self.assertRaises(ValueError): self.invoke(root,values)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); values=fixture(root)
            duplicate=deepcopy(values[0]["files"][0]);duplicate["destination"]="reporting/REPORTS/results.md";values[0]["files"].append(duplicate)
            with self.assertRaisesRegex(ValueError,"collision"):self.invoke(root,values)

    def test_source_hash_drift_and_missing_required_report_or_figure_fail_closed(self):
        for mode in ("hash","report","figure-manifest","figure-target"):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();values=fixture(root);spec,_,_,_,tree=values
                if mode=="hash":(tree/"reports/results.md").write_bytes(b"unbound edit")
                else:
                    target={"report":"reporting/reports/final_validation.md","figure-manifest":"reporting/figures/figures_manifest.json","figure-target":"reporting/figures/plot.svg"}[mode]
                    spec["files"]=[row for row in spec["files"] if row["destination"]!=target]
                with self.assertRaises(ValueError,msg=mode):self.invoke(root,values)

    def test_rebound_secret_key_material_local_paths_and_private_json_are_rejected(self):
        bodies=[b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n",b"Synthetic marker " + b"AKIA" + b"ABCDEFGHIJKLMNOP\n",b"See file:///home/user/private.json\n",
            b"See https://example.invalid/?X-Amz-Credential=synthetic\n"]
        for body in bodies:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();values=fixture(root);rebind(root,values[0],values[4],"reports/results.md",body)
                with self.assertRaises(ValueError):self.invoke(root,values)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();values=fixture(root);rebind(root,values[0],values[4],"evidence_references.json",b'{"private_key":"synthetic"}')
            with self.assertRaises(ValueError):self.invoke(root,values)

    def test_rebound_patient_csv_and_csv_json_disagreement_are_rejected(self):
        for body in (b"patient_id,outcome\nsynthetic-person,1\n",b"patient_nbr,age\n1,50\n",b"RQ,comment\nRQ1,unbound-clinical-claim\n"):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();values=fixture(root);rebind(root,values[0],values[4],"claim_evidence_matrix.csv",body)
                with self.assertRaises(ValueError):self.invoke(root,values)

    def test_private_source_roots_and_source_output_overlap_are_rejected(self):
        for tree in ("data/reports","private/reports","raw/reports","secrets/reports",".terraform/reports"):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();values=fixture(root,tree_name=tree)
                with self.assertRaisesRegex(ValueError,"private_source"):self.invoke(root,values)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();values=fixture(root)
            with self.assertRaisesRegex(ValueError,"overlap"):self.invoke(root,values,output=values[4])

    def test_active_svg_and_false_scientific_input_manifest_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();values=fixture(root);rebind(root,values[0],values[4],"figures/plot.svg",b'<svg><script>synthetic()</script></svg>')
            with self.assertRaisesRegex(ValueError,"svg"):self.invoke(root,values)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();values=fixture(root);spec=values[0];row=next(row for row in spec["files"] if row["category"]=="figure_manifest")
            path=root/row["source"]["path"];body=json.loads(path.read_bytes());body["input_sha256"]["plan"]="f"*64
            write(path,json_bytes(body));row["source"]=reference(path,root)
            with self.assertRaisesRegex(ValueError,"input_binding"):self.invoke(root,values)

    def test_linked_destination_cannot_escape_intended_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();values=fixture(root);output=root/"bundle";output.mkdir();escape=root/"unselected-target";escape.mkdir();link=output/"reporting"
            self.assertTrue(link.resolve().is_relative_to(root));self.assertTrue(escape.resolve().is_relative_to(root))
            try:os.symlink(escape,link,target_is_directory=True)
            except OSError:
                if os.name!="nt":raise
                result=subprocess.run(["cmd","/c","mklink","/J",str(link),str(escape)],capture_output=True,text=True,check=False)
                self.assertEqual(result.returncode,0,result.stderr)
            with self.assertRaisesRegex(ValueError,"linked_public_output"):self.invoke(root,values,output=output)
            self.assertEqual(list(escape.iterdir()),[])


if __name__=="__main__":unittest.main()
