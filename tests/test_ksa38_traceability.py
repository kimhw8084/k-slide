from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/ksa38"))

from traceability import (  # noqa: E402
    EXPECTED_FAMILIES,
    EXPECTED_KSA_CLOSURE,
    TraceabilityError,
    load_json,
    render_report,
    validate_matrix,
)


MATRIX_PATH = ROOT / "traceability/ksa38/traceability.v1.json"
SCHEMA_PATH = ROOT / "traceability/ksa38/schema.v1.json"


class KSA38TraceabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = load_json(MATRIX_PATH)
        cls.schema = load_json(SCHEMA_PATH)

    def check(self, matrix: dict) -> dict:
        return validate_matrix(ROOT, matrix, self.schema)

    def test_complete_matrix_binds_exact_product_subject_and_change_span(self) -> None:
        summary = self.check(copy.deepcopy(self.matrix))
        self.assertEqual(self.matrix["product_subject"]["commit_sha"], "23669bacb0392aecc009ae19c7b8c645f1d8c7dd")
        self.assertEqual(self.matrix["change_span"]["change_base_sha"], "af5836540304b424289bedbe57a87dbb5d02763f")
        self.assertEqual(summary["trace_rows"], 35)
        self.assertEqual(summary["changed_path_coverage"]["expected_paths"], 229)
        self.assertEqual(summary["changed_path_coverage"]["unexplained_paths"], 0)

    def test_canonical_clause_and_ksa_coverage_is_complete(self) -> None:
        actual = {
            item["family_id"]: item["canonical_clause_ids"]
            for item in self.matrix["canonical_contract_families"]
        }
        self.assertEqual(actual, {key: list(value) for key, value in EXPECTED_FAMILIES.items()})
        linked = {ksa for row in self.matrix["trace_rows"] for ksa in row["linked_ksa_items"]}
        self.assertEqual(linked, set(EXPECTED_KSA_CLOSURE))

    def test_queued_item_can_have_implementation_without_closure_promotion(self) -> None:
        row = next(row for row in self.matrix["trace_rows"] if "KSA-04" in row["linked_ksa_items"])
        self.assertEqual(row["implementation_state"], "IMPLEMENTED")
        closure = next(link for link in row["project_os_closure"] if link["ksa_id"] == "KSA-04")
        self.assertEqual(closure["state"], "QUEUED")
        self.check(copy.deepcopy(self.matrix))

    def test_schema_rejects_open_enums_and_unrecognized_fields(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"][0]["ownership"] = "SOMEWHAT_REPOSITORY_OWNED"
        self.assertFalse(Draft202012Validator(self.schema).is_valid(invalid))
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"][0]["invented_field"] = "not permitted"
        self.assertFalse(Draft202012Validator(self.schema).is_valid(invalid))

    def test_all_dedicated_ksa38_schemas_are_draft_2020_12(self) -> None:
        paths = (
            SCHEMA_PATH,
            ROOT / "traceability/ksa38/candidate-evidence.schema.v1.json",
            ROOT / "traceability/ksa38/qualification.schema.v1.json",
        )
        for path in paths:
            with self.subTest(path=path.name):
                Draft202012Validator.check_schema(load_json(path))

    def test_duplicate_trace_id_fails(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"][1]["trace_id"] = invalid["trace_rows"][0]["trace_id"]
        with self.assertRaisesRegex(TraceabilityError, "trace IDs are not unique"):
            self.check(invalid)

    def test_missing_canonical_clause_fails(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"] = [
            row for row in invalid["trace_rows"]
            if "employee_workflow_host_parity_native_invocation" not in row["clause_ids"]
        ]
        with self.assertRaisesRegex(TraceabilityError, "coverage is incomplete"):
            self.check(invalid)

    def test_project_os_snapshot_cannot_be_changed_by_code_presence(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["project_os_closure_snapshot"]["items"][3]["state"] = "DONE_INTEGRATED"
        with self.assertRaisesRegex(TraceabilityError, "differs from the supplied authoritative state"):
            self.check(invalid)
        invalid = copy.deepcopy(self.matrix)
        row = next(row for row in invalid["trace_rows"] if "KSA-04" in row["linked_ksa_items"])
        closure = next(link for link in row["project_os_closure"] if link["ksa_id"] == "KSA-04")
        closure["state"] = "DONE_INTEGRATED"
        with self.assertRaisesRegex(TraceabilityError, "silently changes KSA-04"):
            self.check(invalid)

    def test_changed_path_coverage_must_match_the_exact_rederived_span(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["change_span"]["changed_path_coverage"].pop()
        with self.assertRaisesRegex(TraceabilityError, "changed-path coverage mismatch"):
            self.check(invalid)

    def test_rederivable_commit_anchor_must_match_its_declared_role(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["repository_anchors"][0]["commit_sha"] = invalid["change_span"]["change_base_sha"]
        invalid["repository_anchors"][0]["tree_oid"] = invalid["change_span"]["change_base_tree_oid"]
        with self.assertRaisesRegex(TraceabilityError, "anchors do not match"):
            self.check(invalid)

    def test_deleted_subject_path_must_be_explicitly_historical(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        deleted = next(
            item for item in invalid["change_span"]["changed_path_coverage"]
            if item["path"] == ".opencode/commands/k-slide-safe.md"
        )
        deleted["historical"] = False
        with self.assertRaisesRegex(TraceabilityError, "changed path is absent"):
            self.check(invalid)

    def test_test_locator_must_resolve_to_a_real_subject_test(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"][0]["decisive_test_locators"][0]["symbol"] = "test_does_not_exist"
        with self.assertRaisesRegex(TraceabilityError, "test locator does not resolve"):
            self.check(invalid)

    def test_external_gate_cannot_be_labeled_repository_proven(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        row = next(row for row in invalid["trace_rows"] if row["ownership"] == "EXTERNAL_PRODUCTION_GATE")
        row["repository_evidence_availability"] = "REPOSITORY_TESTED_ONLY"
        with self.assertRaisesRegex(TraceabilityError, "labeled repository-proven"):
            self.check(invalid)

    def test_open_gap_requires_a_next_owner(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        queued = next(row for row in invalid["trace_rows"] if "OPEN_PROJECT_OS_RECONCILIATION" in row["gap_classification"])
        queued["next_owner"] = None
        with self.assertRaisesRegex(TraceabilityError, "open gap without a next owner"):
            self.check(invalid)

    def test_changed_repository_locators_are_concrete(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        invalid["trace_rows"][0]["implementation_locators"][0]["path"] = "src/k_slide/**"
        with self.assertRaisesRegex(TraceabilityError, "schema validation"):
            self.check(invalid)

    def test_report_has_open_and_external_sections(self) -> None:
        report = render_report(self.matrix)
        self.assertIn("## Open repository and reconciliation work", report)
        self.assertIn("## External production gates", report)
        self.assertIn("ACTIVE_VERIFY_REQUIRED", report)
        self.assertIn("QUEUED", report)


if __name__ == "__main__":
    unittest.main()
