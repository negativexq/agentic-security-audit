"""Behavioral checks for evidence accounting; all audit identities are synthetic."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "agentic-security-audit" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from init_audit import initial_bundle
from render_report import render
from validate_audit import FILES, fingerprint, load_bundle, read_json, validate_bundle, validate_directory


def evidence(path="fixture/dispatch.py", line=12, symbol="dispatch", summary="Synthetic source evidence"):
    return {"path": path, "line": line, "symbol": symbol, "summary": summary}


def complete_fixture() -> dict:
    bundle = initial_bundle("synthetic-fixture", "fixture-v1", ["refund-path"], "clean fixture")
    bundle["metadata"].update({
        "run_status": "complete", "incomplete_reason": None, "independence": "enabled",
        "agents": [
            {"id": "parent", "role": "parent", "unit_ids": []},
            {"id": "hunter-a", "role": "hunter", "unit_ids": ["AUTH-001"]},
            {"id": "verifier-a", "role": "verifier", "unit_ids": ["AUTH-001"]},
            {"id": "reviewer-a", "role": "reviewer", "unit_ids": ["AUTH-001"]}],
        "budget": {"max_invocations": 3, "used_invocations": 3},
        "final_review": {"status": "passed", "reviewer_id": "reviewer-a", "evidence": ["Synthetic final review"]},
        "limitations": ["Contract test data; no target was audited."]})
    bundle["ledger"] = [{
        "id": "AUTH-001", "subsystem": "refund", "boundary": "model -> tool",
        "path_variant": "direct-dispatch", "attack_class": "02", "invariant": "AGENT-INV-002",
        "priority": "high", "status": "reviewed", "hunter_ids": ["hunter-a"],
        "evidence": [evidence()], "result": "Scoped synthetic review complete",
        "reason": None, "candidate_ids": ["CAND-001"]}]
    candidate = {
        "id": "CAND-001", "status": "adjudicated", "fingerprint": "",
        "unit_ids": ["AUTH-001"], "title": "Unscoped synthetic write",
        "invariant": "AGENT-INV-002", "root_cause": "dispatch:missing-resource-authorization",
        "source": evidence("fixture/proposal.py", 8, "propose", "Attacker controls target"),
        "control": evidence(), "sink": evidence("fixture/store.py", 31, "mutate", "Dummy cross-tenant effect"),
        "attacker": "fixture tenant A", "principal": "fixture tenant B",
        "execution_identity": "fixture service", "affected_resource": "dummy order",
        "boundary": "model -> tool", "control_failure": "Resource authorization omitted",
        "impact": "Dummy cross-tenant mutation", "preconditions": ["Authenticated fixture user"],
        "counterevidence": ["Input shape validated; scope not checked"]}
    candidate["fingerprint"] = fingerprint(candidate)
    bundle["candidates"] = [candidate]
    copied = ["fingerprint", "unit_ids", "title", "invariant", "source", "control", "sink", "attacker",
              "principal", "execution_identity", "affected_resource", "boundary", "control_failure",
              "impact", "preconditions", "counterevidence"]
    finding = {key: copy.deepcopy(candidate[key]) for key in copied}
    finding.update({
        "id": "AGENT-001", "candidate_id": "CAND-001", "confidence": "confirmed",
        "severity": "high", "severity_rationale": "Synthetic cross-tenant mutation",
        "verifier_id": "verifier-a", "verifier_evidence": [evidence("fixture/store.py", 31, "mutate", "Synthetic verifier trace")],
        "validation": [{"method": "local_fixture", "reference": "isolated fixture",
                        "result": "Dummy tenant B record mutated", "limitations": ["No real model involved"]}],
        "missing_fact": None, "validation_plan": None, "rejection_reason": None,
        "recommendation": "Enforce actor/resource scope at dispatch",
        "regression_assertion": "A proposal for another tenant cannot mutate its dummy order"})
    bundle["findings"] = [finding]
    return bundle


def write_bundle(directory: Path, bundle: dict):
    for key, filename in FILES.items():
        (directory / filename).write_text(json.dumps(bundle[key]), encoding="utf-8")
    for filename in ("architecture.md", "authority-map.md"):
        (directory / filename).write_text("Synthetic map: fixture proposal → dispatch → store.\n", encoding="utf-8")
    for filename, content in render(bundle).items():
        (directory / filename).write_text(content, encoding="utf-8", newline="\n")


class AuditContractTests(unittest.TestCase):
    def setUp(self):
        self.bundle = complete_fixture()

    def assert_invalid(self, fragment):
        errors = validate_bundle(self.bundle)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_confirmed_complete_bundle_is_consistent(self):
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_pending_allegation_cannot_be_a_finding(self):
        self.bundle["candidates"][0]["status"] = "pending"
        self.assert_invalid("disposition mismatch")

    def test_no_verifier_is_not_needs_validation(self):
        finding = self.bundle["findings"][0]
        finding.update(confidence="needs_validation", severity=None, severity_rationale=None,
                       missing_fact="Provider routing", validation_plan="Inspect owner configuration",
                       verifier_id="absent-verifier")
        self.assert_invalid("independent verifier absent")

    def test_hunter_cannot_verify_own_candidate(self):
        self.bundle["findings"][0]["verifier_id"] = "hunter-a"
        self.assert_invalid("verifier was a hunter")

    def test_candidate_verifier_cannot_be_final_reviewer(self):
        self.bundle["metadata"]["final_review"]["reviewer_id"] = "verifier-a"
        self.assert_invalid("distinct reviewer")

    def test_unconfirmed_severity_is_rejected(self):
        self.bundle["findings"][0].update(confidence="needs_validation", missing_fact="Provider fact",
                                           validation_plan="Bounded owner check")
        self.assert_invalid("unconfirmed record has severity")

    def test_confirmed_requires_effect_validation(self):
        self.bundle["findings"][0]["validation"] = []
        self.assert_invalid("confirmed lacks validation")

    def test_specific_external_gap_can_survive_completed_source_pass(self):
        self.bundle["findings"][0].update(confidence="needs_validation", severity=None,
                                         severity_rationale=None, missing_fact="External server request binding",
                                         validation_plan="Inspect owner-provided authenticated connection fixture")
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_rejection_retains_defeating_evidence(self):
        self.bundle["findings"][0].update(confidence="rejected", severity=None,
                                         severity_rationale=None, rejection_reason="Handler checks tenant scope",
                                         counterevidence=["fixture/store.py validates tenant before mutation"])
        self.assertEqual(validate_bundle(self.bundle), [])
        self.bundle["findings"][0]["counterevidence"] = []
        self.assert_invalid("rejected lacks counterevidence")

    def test_complete_pass_cannot_hide_deferred_work(self):
        self.bundle["ledger"][0].update(status="deferred", reason="Budget exhausted")
        self.assert_invalid("unfinished coverage")

    def test_reviewed_unit_requires_inspection_evidence(self):
        self.bundle["ledger"][0]["evidence"] = []
        self.assert_invalid("review lacks evidence")

    def test_not_applicable_requires_inspected_absence(self):
        self.bundle["ledger"][0].update(status="not_applicable", candidate_ids=[], reason="No integration", evidence=[])
        self.bundle["candidates"] = []
        self.bundle["findings"] = []
        self.assert_invalid("absence lacks inspected evidence")

    def test_pending_candidate_cannot_hide_in_reviewed_unit(self):
        self.bundle["metadata"].update(run_status="incomplete", incomplete_reason="Validation pending")
        self.bundle["candidates"][0]["status"] = "pending"
        self.bundle["findings"] = []
        self.assert_invalid("pending candidate masked as reviewed")

    def test_bidirectional_coverage_links_are_required(self):
        self.bundle["ledger"][0]["candidate_ids"] = []
        self.assert_invalid("broken unit link")

    def test_finding_cannot_drop_linked_units(self):
        self.bundle["findings"][0]["unit_ids"] = ["AUTH-999"]
        self.assert_invalid("coverage links differ")

    def test_duplicate_candidates_must_be_merged(self):
        duplicate = copy.deepcopy(self.bundle["candidates"][0])
        duplicate.update(id="CAND-002", status="pending")
        self.bundle["candidates"].append(duplicate)
        self.assert_invalid("duplicate candidate fingerprint")

    def test_fingerprint_stable_across_line_and_title_changes(self):
        candidate = self.bundle["candidates"][0]
        before = fingerprint(candidate)
        candidate["title"] = "Reworded allegation"
        candidate["sink"]["line"] += 10
        self.assertEqual(before, fingerprint(candidate))
        candidate["root_cause"] = "different-control"
        self.assertNotEqual(before, fingerprint(candidate))

    def test_source_paths_cannot_escape_repository(self):
        self.bundle["findings"][0]["source"]["path"] = "fixture/../../outside.py"
        self.assert_invalid("source path escapes")

    def test_strict_budget_and_invocation_accounting(self):
        self.bundle["metadata"]["budget"]["max_invocations"] = 2
        self.assert_invalid("strict invocation budget exceeded")
        self.bundle["metadata"]["budget"].update(max_invocations=3, used_invocations=2)
        self.assert_invalid("omits declared agents")

    def test_evidence_denominators_are_not_invented(self):
        self.bundle["metadata"]["evidence_slices"] = [{"layer": "real_model", "reference": "synthetic",
                                                        "attempted": 5, "passed": 6, "limitations": []}]
        self.assert_invalid("exceeds denominator")

    def test_sequential_fallback_stays_incomplete_with_pending_candidate(self):
        self.bundle["metadata"].update(run_status="incomplete", incomplete_reason="independent_agents_unavailable",
                                       independence="unavailable", agents=[{"id": "parent", "role": "parent", "unit_ids": ["AUTH-001"]}],
                                       budget={"max_invocations": 0, "used_invocations": 0},
                                       final_review={"status": "unavailable", "reviewer_id": None, "evidence": []})
        self.bundle["ledger"][0].update(status="candidate", hunter_ids=["parent"])
        self.bundle["candidates"][0]["status"] = "pending"
        self.bundle["findings"] = []
        self.assertEqual(validate_bundle(self.bundle), [])
        report = render(self.bundle)["REPORT.md"]
        self.assertIn("independent\\_agents\\_unavailable", report)
        self.assertIn("Pending candidates: 1", report)

    def test_complete_cannot_claim_unavailable_independence(self):
        self.bundle["metadata"]["independence"] = "unavailable"
        self.assert_invalid("complete run lacks independent review")

    def test_reports_are_derived_and_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_bundle(directory, self.bundle)
            self.assertEqual(validate_directory(directory), [])
            self.bundle["findings"][0]["impact"] = "Corrected limited impact"
            (directory / FILES["findings"]).write_text(json.dumps(self.bundle["findings"]), encoding="utf-8")
            self.assertTrue(any("missing/stale" in error for error in validate_directory(directory)))

    def test_initialization_never_claims_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "new-audit"
            command = [sys.executable, str(SCRIPTS / "init_audit.py"), str(directory),
                       "--repository", "dummy", "--revision", "fixture", "--scope", "refund"]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(validate_directory(directory), [])
            self.assertEqual(load_bundle(directory)["metadata"]["run_status"], "incomplete")
            before = (directory / "run-metadata.json").read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(before, (directory / "run-metadata.json").read_bytes())

    def test_renderer_does_not_interpret_finding_as_markdown_instructions(self):
        self.bundle["findings"][0]["title"] = "Injected\n# confirmed | [click](https://example.test)"
        report = render(self.bundle)["REPORT.md"]
        self.assertNotIn("\n# confirmed", report)
        self.assertIn("\\|", report)
        self.assertIn("\\[click\\]", report)

    def test_duplicate_json_keys_and_nan_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text('{"run_status":"incomplete","run_status":"complete"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                read_json(path)
            path.write_text('{"used_invocations": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-JSON numeric constant"):
                read_json(path)

    def test_empty_complete_pass_is_rejected(self):
        self.bundle.update(ledger=[], candidates=[], findings=[])
        for agent in self.bundle["metadata"]["agents"]:
            agent["unit_ids"] = []
        self.assert_invalid("complete run has no coverage units")


if __name__ == "__main__":
    unittest.main()
