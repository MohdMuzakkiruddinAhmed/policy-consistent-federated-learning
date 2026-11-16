"""Metadata-only future-image packaging tests; no image build or AWS calls."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from pcfl.experiments import build_plan, digest, file_digest, freeze_plan
from pcfl.robustness import ADAPTER_MODULES
from test_experiments import synthetic_gate_refs
from test_robustness import data_fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from package_robustness_adapter import package


class RobustPackagingTests(unittest.TestCase):
    def fixture(self, root):
        names = ["src/pcfl/" + name for name in ADAPTER_MODULES]
        names += ["containers/robustness/entrypoint.py", "containers/entrypoint.py", "containers/robustness/Dockerfile"]
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# synthetic packaging fixture; never executable research evidence\n")
        sources = {name: file_digest(root / name) for name in names}
        repository = Path(__file__).resolve().parents[1]
        config = json.loads((repository / "configs/experiments.json").read_bytes())
        training = json.loads((repository / "configs/experiments_training.json").read_bytes())
        training["pilot_only"] = False
        provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "git_commit": None,
            "image_digests": {"runtime": "example.invalid/frozen@sha256:" + "b" * 64}}
        candidate = build_plan(config, training, data_fixture()[0], provenance)
        return freeze_plan(candidate, synthetic_gate_refs(candidate, root), root)

    def test_owned_repository_mirror_same_digest_packages_without_mutating_main_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.fixture(root)
            before = (root / "containers/entrypoint.py").read_bytes()
            result = package(plan, "owned.example/mirror@sha256:" + "b" * 64, source_root=root)
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(result["image_built"])
            self.assertEqual(result["accepted_main_plan_digest"], plan["plan_digest"])
            self.assertIn("containers/entrypoint.py", result["unchanged_frozen_files_sha256"])
            self.assertEqual((root / "containers/entrypoint.py").read_bytes(), before)

    def test_mutable_foreign_or_changed_adapter_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.fixture(root)
            for image in ("example.invalid/latest:latest", "example.invalid/frozen@sha256:" + "c" * 64):
                with self.subTest(image=image), self.assertRaisesRegex(ValueError, "immutable_accepted"):
                    package(plan, image, source_root=root)
            (root / "src/pcfl/robust_flower_app.py").write_bytes(b"changed\n")
            with self.assertRaisesRegex(ValueError, "source_changed"):
                package(plan, plan["provenance"]["image_digests"]["runtime"], source_root=root)


if __name__ == "__main__":
    unittest.main()
