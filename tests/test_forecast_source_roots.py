"""Pinned ROOT-relative cost sources replay from nested input folders."""
import importlib.util
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

STAGE = Path(__file__).resolve().parent
ROOT = next(path for path in STAGE.parents if (path / "pyproject.toml").is_file())
sys.path.insert(0, str(ROOT / "scripts")); sys.path.insert(0, str(ROOT / "tests"))
import test_remaining_campaign_forecast as model_fixture
SOURCE = STAGE / "forecast_remaining_campaign.py" if (STAGE / "forecast_remaining_campaign.py").is_file() else ROOT / "scripts/forecast_remaining_campaign.py"
spec = importlib.util.spec_from_file_location("rooted_forecast", SOURCE)
forecast = importlib.util.module_from_spec(spec); spec.loader.exec_module(forecast)


class ForecastSourceRootTests(unittest.TestCase):
    def setUp(self):
        self.fixture = model_fixture.ForecastTests(); self.fixture.setUp()
        f = self.fixture; f.batch("iid"); f.batch("non_iid")
        f.cost["source_inputs"] = deepcopy(f.cost["source_inputs"])
        for ref in f.cost["source_inputs"]:
            path = Path(ref["path"])
            if path.name.endswith("inventory.json"):
                ref["path"] = path.resolve().relative_to(f.root.resolve()).as_posix()
        from test_remaining_campaign_forecast import write
        f.doc["priced_usage"] = write(f.root / "cost.json", f.cost)
        self.nested = f.root / "deep/nested/input"; self.nested.mkdir(parents=True)

    def tearDown(self): self.fixture.tearDown()

    def test_nested_manifest_uses_explicit_project_root_for_report_source_refs(self):
        f = self.fixture
        value = forecast.generate(f.doc, base=self.nested, project_root=f.root)
        self.assertTrue(value["all_historical_inventory_task_coverage"])
        self.assertTrue(value["forecast_ready"])
        self.assertEqual(value["total_remaining_work"], 292)

    def test_different_cwd_does_not_rebase_root_relative_report_sources(self):
        previous = Path.cwd()
        try:
            os.chdir(self.nested)
            value = forecast.generate(self.fixture.doc, base=self.nested, project_root=self.fixture.root)
        finally:
            os.chdir(previous)
        self.assertTrue(value["forecast_ready"])

    def test_bad_source_pin_still_withholds_projection(self):
        f = self.fixture
        next(ref for ref in f.cost["source_inputs"] if ref["path"].endswith("inventory.json"))["sha256"] = "0" * 64
        from test_remaining_campaign_forecast import write
        f.doc["priced_usage"] = write(f.root / "cost.json", f.cost)
        value = forecast.generate(f.doc, base=self.nested, project_root=f.root)
        self.assertFalse(value["all_historical_inventory_task_coverage"])
        self.assertIsNone(value["priced_comparison"])


if __name__ == "__main__": unittest.main()
