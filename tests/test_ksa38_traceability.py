from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/ksa38"))

import build_candidate_evidence as candidate_evidence  # noqa: E402
from traceability import (  # noqa: E402
    EXPECTED_FAMILIES,
    EXPECTED_KSA_CLAUSES,
    EXPECTED_KSA_CLOSURE,
    EXPECTED_OPEN_REPOSITORY_KSAS,
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
        actual_crosswalk = {
            item["ksa_id"]: tuple((link["family_id"], link["clause_id"]) for link in item["mappings"])
            for item in self.matrix["ksa_scope_registry"]
        }
        self.assertEqual(actual_crosswalk, EXPECTED_KSA_CLAUSES)
        self.check(copy.deepcopy(self.matrix))

    def test_queued_item_with_open_repository_scope_is_not_fully_implemented(self) -> None:
        row = next(row for row in self.matrix["trace_rows"] if "KSA-04" in row["linked_ksa_items"])
        self.assertEqual(row["implementation_state"], "PARTIAL")
        self.assertIn("OPEN_REPOSITORY_REQUIREMENT", row["gap_classification"])
        scope = next(item for item in self.matrix["ksa_scope_registry"] if item["ksa_id"] == "KSA-04")
        self.assertTrue(scope["repository_requirement_open"])
        self.assertEqual(scope["mappings"][0]["implementation_state"], "PARTIAL")
        closure = next(link for link in row["project_os_closure"] if link["ksa_id"] == "KSA-04")
        self.assertEqual(closure["state"], "QUEUED")
        self.check(copy.deepcopy(self.matrix))

    def _row(self, matrix: dict, clause: str) -> dict:
        return next(row for row in matrix["trace_rows"] if clause in row["clause_ids"])

    def _set_row_ksas(self, matrix: dict, row: dict, ksa_ids: set[str]) -> None:
        row["linked_ksa_items"] = sorted(ksa_ids)
        row["project_os_closure"] = [
            {"ksa_id": ksa, "state": EXPECTED_KSA_CLOSURE[ksa]}
            for ksa in sorted(ksa_ids)
        ]

    def test_ksa04_cannot_be_satisfied_by_immutable_source_clause(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        host = self._row(invalid, "employee_workflow_host_parity_native_invocation")
        source = self._row(invalid, "immutable_source_multifile_evidence_boundaries")
        self._set_row_ksas(invalid, host, set(host["linked_ksa_items"]) - {"KSA-04"})
        self._set_row_ksas(invalid, source, set(source["linked_ksa_items"]) | {"KSA-04"})
        with self.assertRaisesRegex(TraceabilityError, "semantic KSA crosswalk mismatch"):
            self.check(invalid)

    def test_ksa05_is_required_on_decision_view_clause(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        decision = self._row(invalid, "decision_view_reconstruction_review_disclosure_evidence_drilldown")
        source = self._row(invalid, "immutable_source_multifile_evidence_boundaries")
        self._set_row_ksas(invalid, decision, {"KSA-19"})
        self._set_row_ksas(invalid, source, set(source["linked_ksa_items"]) | {"KSA-05"})
        with self.assertRaisesRegex(TraceabilityError, "semantic KSA crosswalk mismatch"):
            self.check(invalid)

    def test_unrelated_ksa_cannot_be_inserted_to_keep_id_set_coverage_green(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        host = self._row(invalid, "employee_workflow_host_parity_native_invocation")
        self._set_row_ksas(invalid, host, set(host["linked_ksa_items"]) | {"KSA-19"})
        with self.assertRaisesRegex(TraceabilityError, "semantic KSA crosswalk mismatch"):
            self.check(invalid)

    def test_correct_closure_snapshot_does_not_substitute_for_a_required_clause_link(self) -> None:
        invalid = copy.deepcopy(self.matrix)
        host = self._row(invalid, "employee_workflow_host_parity_native_invocation")
        self._set_row_ksas(invalid, host, set(host["linked_ksa_items"]) - {"KSA-04"})
        self.assertEqual(
            next(item["state"] for item in invalid["project_os_closure_snapshot"]["items"] if item["ksa_id"] == "KSA-04"),
            "QUEUED",
        )
        with self.assertRaisesRegex(TraceabilityError, "semantic KSA crosswalk mismatch"):
            self.check(invalid)

    def test_open_queued_scope_cannot_be_marked_fully_implemented(self) -> None:
        self.assertIn("KSA-04", EXPECTED_OPEN_REPOSITORY_KSAS)
        invalid = copy.deepcopy(self.matrix)
        row = self._row(invalid, "employee_workflow_host_parity_native_invocation")
        row["implementation_state"] = "IMPLEMENTED"
        with self.assertRaisesRegex(TraceabilityError, "falsely marked fully implemented"):
            self.check(invalid)

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
        with self.assertRaisesRegex(TraceabilityError, "differs from the binding-time Project OS state"):
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
        self.assertIn("## Closed KSA semantic crosswalk", report)
        self.assertIn("KSA-04` | first-class Cloud VS Code adapter", report)
        self.assertIn("KSA-05` | Decision View", report)
        self.assertIn("OPEN_REPOSITORY_REQUIREMENT", report)
        self.assertIn("OPEN_EXTERNAL_PRODUCTION_GATE", report)
        self.assertIn("Project OS KSA-04 owner", report)
        self.assertIn("`KSA-02` | canonical host-adapter contract and one normal employee workflow | `ROUND_1/employee_workflow_host_parity_native_invocation` (KSA38-TR-001): KSA-02 requires the canonical host adapter to expose one normal employee workflow. | `IMPLEMENTED` | `DONE_INTEGRATED` | None recorded", report)
        self.assertIn("ACTIVE_VERIFY_REQUIRED", report)
        self.assertIn("QUEUED", report)

    def test_full_suite_workflows_checkout_history_for_traceability(self) -> None:
        workflow_jobs = (
            (ROOT / ".github/workflows/k-slide.yml", "test"),
            (ROOT / ".github/workflows/k-slide-phase32.yml", "fast"),
        )
        for workflow_path, job_name in workflow_jobs:
            with self.subTest(workflow=workflow_path.name, job=job_name):
                workflow = workflow_path.read_text(encoding="utf-8")
                job_header = re.search(
                    rf"(?m)^  {re.escape(job_name)}:\s*$", workflow
                )
                self.assertIsNotNone(job_header, f"missing {job_name} job")
                assert job_header is not None
                next_job = re.search(
                    r"(?m)^  [A-Za-z0-9_-]+:\s*$",
                    workflow[job_header.end() :],
                )
                job = workflow[
                    job_header.end() :
                    job_header.end() + next_job.start()
                    if next_job
                    else len(workflow)
                ]
                self.assertIn("python -m unittest discover -s tests", job)

                lines = job.splitlines()
                checkout_indexes = [
                    index
                    for index, line in enumerate(lines)
                    if line.startswith("      - uses: actions/checkout@")
                ]
                self.assertEqual(len(checkout_indexes), 1)
                checkout_index = checkout_indexes[0]
                next_step = next(
                    (
                        index
                        for index in range(checkout_index + 1, len(lines))
                        if lines[index].startswith("      - ")
                    ),
                    len(lines),
                )
                checkout_step = lines[checkout_index:next_step]
                self.assertIn("fetch-depth: 0", [line.strip() for line in checkout_step])


class KSA38CandidateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = load_json(ROOT / "traceability/ksa38/candidate-context.v1.json")
        cls.qualification = load_json(ROOT / "traceability/ksa38/qualification.v1.json")

    def test_candidate_context_preserves_native_predecessor_chain(self) -> None:
        candidate_evidence._validate_context(self.context)
        self.assertEqual(self.context["request"], "chg16-requirement-traceability-01-fix04")
        self.assertEqual(self.context["work_branch"], "codex/k-slide-chg16-requirement-traceability-01-fix04")
        self.assertEqual(self.context["candidate_parent_sha"], "8fc9d6c9f87e9dec0c0a75075e7137bb9698f86d")
        self.assertNotEqual(self.context["candidate_parent_sha"], self.context["predecessor_lineage"]["work_head"])
        self.assertEqual(self.context["predecessor_lineage"]["request"], "chg16-requirement-traceability-01-fix03")
        self.assertEqual(self.context["predecessor_lineage"]["work_head"], "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2")
        self.assertEqual(self.context["predecessor_lineage"]["native_evidence_commit"], "defcf1eda11038fad75f825b678f50795eff485c")
        self.assertEqual(self.context["predecessor_lineage"]["native_build_job_id"], "CF-5138c2009554585799d1357c")
        self.assertEqual(self.context["integration_lineage"]["pull_request_number"], 40)
        self.assertTrue(candidate_evidence._is_ancestor(
            self.context["integration_lineage"]["accepted_head_sha"],
            self.context["integration_lineage"]["merge_commit_sha"],
        ))
        self.assertTrue(candidate_evidence._same_tree(
            self.context["integration_lineage"]["accepted_head_sha"],
            self.context["integration_lineage"]["merge_commit_sha"],
        ))
        self.assertEqual(self.context["historical_lineage"][0]["request"], "chg16-requirement-traceability-01-fix02")
        self.assertEqual(self.context["historical_lineage"][1]["disposition"], "REJECTED")
        self.assertEqual(self.context["historical_lineage"][2]["disposition"], "BUILD_PREDECESSOR")

    def test_stale_request_work_branch_and_predecessor_are_rejected(self) -> None:
        invalid = copy.deepcopy(self.qualification)
        invalid["request"] = "chg16-requirement-traceability-01-fix03"
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "qualification request"):
            candidate_evidence.validate_qualification_identity(invalid, self.context)

        invalid = copy.deepcopy(self.qualification)
        invalid["work_branch"] = "codex/k-slide-chg16-requirement-traceability-01-fix03"
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "qualification work_branch"):
            candidate_evidence.validate_qualification_identity(invalid, self.context)

        invalid = copy.deepcopy(self.qualification)
        invalid["predecessor_lineage"]["work_head"] = "6c15efcff2352e43050391c78ea164fa8a5edf8e"
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "qualification predecessor_lineage"):
            candidate_evidence.validate_qualification_identity(invalid, self.context)

        invalid = copy.deepcopy(self.qualification)
        invalid["execution_base_sha"] = self.context["predecessor_lineage"]["work_head"]
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "qualification execution_base_sha"):
            candidate_evidence.validate_qualification_identity(invalid, self.context)

        invalid = copy.deepcopy(self.qualification)
        invalid["integration_lineage"]["merge_commit_sha"] = "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "qualification integration_lineage"):
            candidate_evidence.validate_qualification_identity(invalid, self.context)

    def test_candidate_parent_must_match_bound_execution_base(self) -> None:
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "candidate parent"):
            candidate_evidence.validate_bound_candidate_identity(
                self.context["request"],
                self.context["work_branch"],
                self.context["predecessor_lineage"]["work_head"],
                self.context,
            )

    def test_altered_stored_context_identities_fail_closed(self) -> None:
        mutations = (
            ("request", "chg16-requirement-traceability-01-fix03"),
            ("work_branch", "codex/k-slide-chg16-requirement-traceability-01-fix03"),
            ("candidate_parent_sha", self.context["predecessor_lineage"]["work_head"]),
            ("predecessor_lineage", {**self.context["predecessor_lineage"], "native_build_job_id": "CF-959e82d5a93c6227f3e861fb"}),
            ("integration_lineage", {**self.context["integration_lineage"], "merge_commit_sha": "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"}),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                invalid = copy.deepcopy(self.context)
                invalid[key] = value
                with self.assertRaises(candidate_evidence.CandidateEvidenceError):
                    candidate_evidence._validate_context(invalid)

    def _candidate_documents(self) -> tuple[dict, dict, dict]:
        evidence = load_json(ROOT / ".codex-fabric/ksa38/candidate-evidence.json")
        audit = load_json(ROOT / ".codex-fabric/audit.json")
        qualification = load_json(ROOT / "traceability/ksa38/qualification.v1.json")
        return evidence, audit, qualification

    def _branch_override(self, branch_name: str):
        original_git = candidate_evidence.git

        def git_with_branch(*args: str) -> str:
            if args == ("branch", "--show-current"):
                return branch_name
            return original_git(*args)

        return patch.object(candidate_evidence, "git", side_effect=git_with_branch)

    def test_generation_succeeds_for_bound_branch_and_rejects_wrong_branch(self) -> None:
        evidence, _, qualification = self._candidate_documents()
        candidate_sha = evidence["candidate_binding"]["commit_sha"]
        with self._branch_override(self.context["work_branch"]), patch.object(
            candidate_evidence, "_status_paths", return_value=set()
        ):
            generated, bound_qualification = candidate_evidence.build_candidate_artifacts(candidate_sha)
        self.assertEqual(generated["candidate_binding"], evidence["candidate_binding"])
        self.assertEqual(bound_qualification["candidate_binding"], qualification["candidate_binding"])
        with self._branch_override("main"):
            with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "requires the bound FIX04 work branch"):
                candidate_evidence.build_candidate_artifacts(candidate_sha)

    def test_generation_rejects_wrong_request_base_and_forged_predecessor(self) -> None:
        evidence, _, _ = self._candidate_documents()
        candidate_sha = evidence["candidate_binding"]["commit_sha"]
        with self._branch_override(self.context["work_branch"]):
            original_load = candidate_evidence.load_json

            def wrong_request_context(path):
                value = original_load(path)
                if Path(path).resolve() == (ROOT / "traceability/ksa38/candidate-context.v1.json").resolve():
                    value = copy.deepcopy(value)
                    value["request"] = "chg16-requirement-traceability-01-fix03"
                return value

            with patch.object(candidate_evidence, "load_json", side_effect=wrong_request_context):
                with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "request is not the bound FIX04"):
                    candidate_evidence.build_candidate_artifacts(candidate_sha)

            for key, value, message in (
                ("candidate_parent_sha", self.context["predecessor_lineage"]["work_head"], "execution base is not the fresh FIX04 base"),
                ("predecessor_lineage", {**self.context["predecessor_lineage"], "work_head": "6c15efcff2352e43050391c78ea164fa8a5edf8e"}, "accepted FIX03 predecessor lineage"),
            ):
                original_load = candidate_evidence.load_json

                def altered_context(path, *, _key=key, _value=value):
                    result = original_load(path)
                    if Path(path).resolve() == (ROOT / "traceability/ksa38/candidate-context.v1.json").resolve():
                        result = copy.deepcopy(result)
                        result[_key] = _value
                    return result

                with patch.object(candidate_evidence, "load_json", side_effect=altered_context):
                    with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, message):
                        candidate_evidence.build_candidate_artifacts(candidate_sha)

            with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "candidate parent"):
                candidate_evidence.build_candidate_artifacts(self.context["candidate_parent_sha"])

            with patch.object(candidate_evidence, "_status_paths", return_value={"unexpected.txt"}):
                with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "outside the evidence sidecars"):
                    candidate_evidence.build_candidate_artifacts(candidate_sha)

    def test_read_only_validation_is_checkout_portable_and_preserves_binding(self) -> None:
        evidence, audit, qualification = self._candidate_documents()
        sidecar_bytes = (ROOT / ".codex-fabric/ksa38/candidate-evidence.json").read_bytes()
        audit_bytes = (ROOT / ".codex-fabric/audit.json").read_bytes()
        self.assertEqual(sidecar_bytes, audit_bytes)
        self.assertEqual(evidence, audit)
        self.assertEqual(qualification["candidate_binding"], evidence["candidate_binding"])
        self.assertEqual(evidence["candidate_binding"]["work_branch"], self.context["work_branch"])
        self.assertEqual(evidence["candidate_binding"]["parent_sha"], self.context["candidate_parent_sha"])
        self.assertEqual(evidence["execution_base_sha"], self.context["candidate_parent_sha"])
        self.assertEqual(evidence["integration_lineage"], self.context["integration_lineage"])
        self.assertEqual(evidence["predecessor_lineage"], self.context["predecessor_lineage"])
        self.assertEqual(evidence["candidate_binding"]["commit_sha"], qualification["candidate_binding"]["commit_sha"])
        self.assertEqual(
            evidence["candidate_binding"]["tree_oid"],
            candidate_evidence.git("rev-parse", f"{evidence['candidate_binding']['commit_sha']}^{{tree}}"),
        )
        self.assertEqual(
            evidence["candidate_binding"]["parent_sha"],
            candidate_evidence.git("rev-parse", f"{evidence['candidate_binding']['commit_sha']}^"),
        )
        self.assertIsNone(evidence["current_execution_identity"])
        self.assertIsNone(evidence["fabric_execution_identity"]["fabric_job_id"])

        for checkout_branch in ("", "main"):
            with (
                self.subTest(checkout_branch=checkout_branch),
                self._branch_override(checkout_branch),
                patch.object(candidate_evidence, "_status_paths", return_value={"editable-install.egg-info"}),
            ):
                candidate_evidence.validate_evidence(evidence, audit, qualification)

    def test_altered_stored_candidate_sha_tree_parent_or_lineage_fails_read_only_validation(self) -> None:
        evidence, audit, qualification = self._candidate_documents()
        corruptions = (
            ("candidate_binding", "commit_sha", "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"),
            ("candidate_binding", "tree_oid", "12684be7aa76895dceb572306ede944be56576ac"),
            ("candidate_binding", "parent_sha", "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"),
            ("predecessor_lineage", "native_build_job_id", "CF-959e82d5a93c6227f3e861fb"),
            ("integration_lineage", "merge_commit_sha", "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"),
        )
        for section, key, value in corruptions:
            with self.subTest(section=section, key=key):
                invalid = copy.deepcopy(evidence)
                invalid[section][key] = value
                with self.assertRaises(candidate_evidence.CandidateEvidenceError):
                    candidate_evidence.validate_evidence(invalid, invalid, qualification)

    def test_conventional_audit_must_match_candidate_sidecar_binding(self) -> None:
        sidecar, _, _ = self._candidate_documents()
        audit = copy.deepcopy(sidecar)
        audit["candidate_binding"]["commit_sha"] = "5d48a1ad189e108e2f9fda5fb4fe59805ca944a2"
        with self.assertRaisesRegex(candidate_evidence.CandidateEvidenceError, "audit.json differs"):
            candidate_evidence.validate_audit_match(sidecar, audit)


if __name__ == "__main__":
    unittest.main()
