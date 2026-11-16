"""Operational logging boundary tests; free-text content is not classified here."""

import json
import math
import unittest

from pcfl.logging_guard import ALLOWED_FIELDS, encode_log, validate_log_record


class LoggingGuardTests(unittest.TestCase):
    def test_permitted_scalar_metadata_round_trips(self):
        record = {
            "event": "update_rejected", "org_id": "org_01", "update_id": "u-1",
            "task_id": "t-1", "round_id": "r-1", "run_id": "synthetic-run",
            "reason": "authorization_interrupted", "outcome": "rejected",
            "order": 12, "epoch": 3, "digest": "a" * 64, "scenario_id": "S4",
            "seed": 7, "count": 1, "schema_version": "0.1.0",
            "duration_ms": 1.25, "correlation_id": None,
        }
        self.assertEqual(set(record), set(ALLOWED_FIELDS))
        self.assertEqual(json.loads(encode_log(record)), record)

    def test_unknown_and_clinical_fields_are_rejected(self):
        fields = (
            "patient_nbr", "encounter_id", "readmitted", "diagnosis", "diag_1",
            "race", "gender", "age", "weight", "medical_specialty", "patient_name",
            "email", "date_of_birth", "rows", "features", "unexpected_metadata",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    validate_log_record({"event": "synthetic", field: "synthetic-value"})

    def test_nested_payloads_are_rejected_under_allowlisted_fields(self):
        for value in ({"patient_nbr": "synthetic-id"}, ["synthetic-row"],
                      ("synthetic-row",), {"synthetic-row"}, b"synthetic-row"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    validate_log_record({"event": "synthetic", "reason": value})

    def test_nonfinite_numbers_cannot_be_serialized(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    encode_log({"event": "synthetic", "duration_ms": value})

    def test_non_records_and_missing_event_are_rejected(self):
        for record in (None, [], "synthetic", {}, {"event": ""}, {"event": 1}):
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    validate_log_record(record)

    def test_scalar_subclasses_cannot_smuggle_nested_serialization(self):
        class CustomString(str):
            pass

        with self.assertRaises(ValueError):
            validate_log_record({"event": "synthetic", "reason": CustomString("value")})


if __name__ == "__main__":
    unittest.main()
