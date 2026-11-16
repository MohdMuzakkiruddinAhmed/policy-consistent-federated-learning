"""Synthetic whole-protocol tests for the actual Flower S1 scenario label."""
from copy import deepcopy
import unittest

from assess_pilots import ORGS, full_cloud_case
from pcfl.experiments import digest
from test_assess_pilots import model_fixture


def cloud_fixture():
    plan, dataset, local = model_fixture()
    attempt = local["attempts"][0]
    runtime = {"distribution": "iid", "training": plan["training_candidate"], "rounds": 5,
        "max_examples_per_client": 100000, "validation_max_examples": 100000,
        "validation_source_sha256": dataset["private_artifacts_sha256"]["validation.csv"],
        "baseline_id": "P1", "scenario_id": "S1", "seed": 296, "persistent_run_id": "synthetic-run",
        "model_metadata": {"metadata_digest": digest("synthetic-metadata"),
            "model_schema_hash": digest("synthetic-schema"), "hidden_dims": [64, 32]}}
    raw = {"baseline_id": "P1", "scenario_id": "between_round", "seed": 296,
        "persistent_run_id": "synthetic-run", "cloud_campaign_id": "synthetic-application",
        "client_training": [{**row, "round_id": "round-" + str(round_["round"])}
            for round_ in attempt["rounds"] for row in round_["clients"]],
        "updates": [{"round_id": "round-" + str(round_["round"]), "org_id": row["org_id"],
            "sample_count": row["sample_count"]} for round_ in attempt["rounds"] for row in round_["clients"]],
        "validation_metrics": {"count": 16, "threshold": .5}, "test_holdout_evaluated": False,
        "model_metadata_digest": digest("synthetic-metadata"), "model_schema_hash": digest("synthetic-schema")}
    inventory = {"campaign_id": "synthetic-deployment", "export": {"application_campaign_id": "synthetic-application"},
        "image": {"reference": next(iter(plan["provenance"]["image_digests"].values()))},
        "uploads": [{"sha256": value, "version_id": "synthetic-version"}
            for key, value in dataset["private_artifacts_sha256"].items()
            if key.startswith("iid/") or key == "preprocessor.json"]}
    return runtime, raw, dataset, plan, inventory


class PilotScenarioAliasTests(unittest.TestCase):
    def test_real_producer_S1_name_binds_full_training_and_model_protocol(self):
        facts = full_cloud_case(*cloud_fixture())
        self.assertTrue(all(facts[name] for name in
            ("protocol", "partitions", "full", "seed", "validation_full", "validation_only")))
        self.assertEqual(facts["trained_client_rounds"], 40)

    def test_legacy_S1_label_and_canonical_S1_remain_compatible(self):
        for name in ("before_dispatch", "S1"):
            values = cloud_fixture()
            values[1]["scenario_id"] = name
            with self.subTest(name=name):
                self.assertTrue(full_cloud_case(*values)["protocol"])

    def test_wrong_and_unknown_raw_scenarios_do_not_bind_to_prepared_S1(self):
        for name in ("stable", "mid_round", "S0", "S2", "between_rounds", "unknown", None):
            values = cloud_fixture()
            values[1]["scenario_id"] = name
            with self.subTest(name=name):
                facts = full_cloud_case(*values)
                self.assertFalse(facts["protocol"])
                self.assertTrue(facts["full"] and facts["seed"] and facts["validation_full"])

    def test_actual_S1_label_does_not_allow_other_prepared_scenario(self):
        for scenario in ("S0", "S2", "S3", "unknown", None):
            values = cloud_fixture()
            values[0]["scenario_id"] = scenario
            with self.subTest(scenario=scenario):
                self.assertFalse(full_cloud_case(*values)["protocol"])

    def test_alias_acceptance_preserves_identity_model_and_budget_bindings(self):
        for field, value in (("seed", 593), ("persistent_run_id", "other-run"), ("baseline_id", "B1"),
                ("cloud_campaign_id", "other-application"), ("model_schema_hash", "f" * 64),
                ("model_metadata_digest", "e" * 64)):
            values = cloud_fixture()
            values[1][field] = value
            with self.subTest(field=field):
                self.assertFalse(full_cloud_case(*values)["protocol"])
        values = cloud_fixture()
        values[0]["rounds"] = 1
        self.assertFalse(full_cloud_case(*values)["protocol"])

    def test_other_actual_primary_wire_names_keep_whole_protocol_binding(self):
        for scenario, wire in (("S0", "stable"), ("S2", "mid_round"), ("S3", "delayed")):
            values = cloud_fixture()
            values[0]["scenario_id"], values[1]["scenario_id"] = scenario, wire
            with self.subTest(scenario=scenario):
                self.assertTrue(full_cloud_case(*values)["protocol"])


if __name__ == "__main__": unittest.main()
