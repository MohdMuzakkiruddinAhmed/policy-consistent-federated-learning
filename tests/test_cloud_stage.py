import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloud_stage_guard", ROOT / "scripts/run_cloud_stage.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrivateSupervisorDeadlineTests(unittest.TestCase):
    def test_missing_or_short_private_deadline_cannot_launch_long_public_batch(self):
        public = {"task_deadline_seconds": 43200}
        module.verify_private_deadline(public, {"task_deadline_seconds": 43200})
        for private in ({}, {"task_deadline_seconds": 3600}, {"task_deadline_seconds": "43200"}):
            with self.subTest(private=private), self.assertRaises(ValueError):
                module.verify_private_deadline(public, private)


if __name__ == "__main__":
    unittest.main()
