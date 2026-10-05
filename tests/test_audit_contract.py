"""Behavioral checks for evidence accounting; all audit identities are synthetic."""

from __future__ import annotations

import copy
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "agentic-security-audit" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from init_audit import initial_bundle, main as initialize_audit
from audit_integrity import (ALLEGATION_FIELDS, ATTACK_CLASS_INVARIANTS, candidate_hash,
                             canonical_hash, capture_source, check_output, verify_source)
from render_report import render
from validate_audit import FILES, fingerprint, load_bundle, read_json, validate_bundle, validate_directory


def evidence(path="fixture/dispatch.py", line=12, symbol="dispatch", summary="Synthetic source evidence"):
    return {"path": path, "line": line, "symbol": symbol, "summary": summary}


def complete_fixture() -> dict:
    bundle = initial_bundle("synthetic-fixture", ["refund-path"], "clean fixture")
    manifest = bundle["source_manifest"]
    manifest["files"] = {p: {"sha256": "a" * 64, "size": 80} for p in
                         ("fixture/proposal.py", "fixture/dispatch.py", "fixture/store.py")}
    digest = canonical_hash(manifest)
    bundle["metadata"].update(source_manifest_hash=digest, revision=digest)
    bundle["metadata"].update({
        "run_status": "complete", "incomplete_reason": None, "independence": "enabled",
        "agents": [
            {"id": "parent", "role": "parent", "unit_ids": []},
            {"id": "hunter-a", "role": "hunter", "unit_ids": ["AUTH-001"]},
            {"id": "verifier-a", "role": "verifier", "unit_ids": ["AUTH-001"]},
            {"id": "reviewer-a", "role": "reviewer", "unit_ids": ["AUTH-001"]}],
        "budget": {"max_invocations": 5, "used_invocations": 5},
        "final_review": {"status": "passed", "reviewer_id": "reviewer-a", "evidence": ["Synthetic final review"]},
        "limitations": ["Contract test data; no target was audited."]})
    for agent in bundle["metadata"]["agents"]:
        agent["source_manifest_hash"] = digest
    for cid in ("critic-planning", "critic-final"):
        bundle["metadata"]["agents"].append({"id": cid, "role": "coverage_critic", "unit_ids": [], "source_manifest_hash": digest})
    bundle["metadata"]["final_review"]["source_manifest_hash"] = digest
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
    candidate["source_manifest_hash"] = digest
    candidate["fingerprint"] = fingerprint(candidate)
    bundle["candidates"] = [candidate]
    copied = ["fingerprint", "unit_ids", "title", "invariant", "source", "control", "sink", "attacker",
              "principal", "execution_identity", "affected_resource", "boundary", "control_failure",
              "impact", "preconditions", "counterevidence", "source_manifest_hash"]
    finding = {key: copy.deepcopy(candidate[key]) for key in copied}
    finding.update({
        "id": "AGENT-001", "candidate_id": "CAND-001", "confidence": "confirmed",
        "verified_candidate_hash": candidate_hash(candidate),
        "severity": "high", "severity_rationale": "Synthetic cross-tenant mutation",
        "verifier_id": "verifier-a", "verifier_evidence": [evidence("fixture/store.py", 31, "mutate", "Synthetic verifier trace")],
        "validation": [{"method": "static_trace", "reference": "synthetic source trace", "execution_id": None,
                        "result": "Dummy tenant B record mutated", "limitations": ["No real model involved"]}],
        "missing_fact": None, "validation_plan": None, "rejection_reason": None,
        "recommendation": "Enforce actor/resource scope at dispatch",
        "regression_assertion": "A proposal for another tenant cannot mutate its dummy order"})
    bundle["findings"] = [finding]
    for stage in ("planning", "final"):
        ledger = copy.deepcopy(bundle["ledger"])
        bundle["metadata"]["coverage_reviews"].append({
            "stage": stage, "status": "passed", "critic_id": "critic-" + stage,
            "source_manifest_hash": digest, "ledger_snapshot": ledger,
            "ledger_hash": canonical_hash(ledger), "evidence": [evidence()], "missing_units": []})
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
                                       independence="unavailable", agents=[{"id": "parent", "role": "parent", "unit_ids": ["AUTH-001"], "source_manifest_hash": self.bundle["metadata"]["source_manifest_hash"]}],
                                       budget={"max_invocations": 0, "used_invocations": 0},
                                       coverage_reviews=[], final_review={"status": "unavailable", "reviewer_id": None, "evidence": [], "source_manifest_hash": None})
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
            self.assertEqual(validate_directory(directory, check_source=False), [])
            self.bundle["findings"][0]["recommendation"] = "Corrected repair guidance"
            (directory / FILES["findings"]).write_text(json.dumps(self.bundle["findings"]), encoding="utf-8")
            self.assertTrue(any("missing/stale" in error for error in validate_directory(directory, check_source=False)))

    def test_initialization_never_claims_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "new-audit"
            source = Path(temporary) / "source"
            source.mkdir()
            (source / "agent.py").write_text("pass\n")
            command = [sys.executable, str(SCRIPTS / "init_audit.py"), str(directory),
                       "--repository", str(source), "--scope", "refund"]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(validate_directory(directory, check_source=False), [])
            self.assertEqual(load_bundle(directory)["metadata"]["run_status"], "incomplete")
            before = (directory / "run-metadata.json").read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(before, (directory / "run-metadata.json").read_bytes())

    def test_renderer_does_not_interpret_finding_as_markdown_instructions(self):
        self.bundle["findings"][0]["title"] = "Injected\n# confirmed | [click](https://example.test)"
        self.bundle["candidates"][0]["title"] = self.bundle["findings"][0]["title"]
        self.bundle["findings"][0]["verified_candidate_hash"] = candidate_hash(self.bundle["candidates"][0])
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

    def test_every_finding_allegation_field_is_bound(self):
        for field in ALLEGATION_FIELDS:
            with self.subTest(field=field):
                bundle = complete_fixture()
                value = bundle["findings"][0][field]
                if isinstance(value, dict):
                    value["summary"] = "Different claimed control/effect"
                elif isinstance(value, list):
                    value.append("Additional exploitation condition")
                else:
                    bundle["findings"][0][field] = ("b" * 64 if field == "source_manifest_hash" else
                        "AGENT-INV-001" if field == "invariant" else "Altered allegation")
                self.assertTrue(any("allegation field changed: " + field in error
                                    for error in validate_bundle(bundle)))

    def test_candidate_change_invalidates_verifier_receipt(self):
        self.bundle["candidates"][0]["impact"] = "Escalated cross-tenant takeover"
        self.bundle["findings"][0]["impact"] = "Escalated cross-tenant takeover"
        self.assert_invalid("verified candidate snapshot differs")

    def test_candidate_hash_ignores_only_disposition_bookkeeping(self):
        candidate = self.bundle["candidates"][0]
        before = candidate_hash(candidate)
        candidate["status"] = "pending"
        self.assertEqual(before, candidate_hash(candidate))
        self.assertEqual(before, candidate_hash(dict(reversed(list(candidate.items())))))
        candidate["counterevidence"].append("New downstream control")
        self.assertNotEqual(before, candidate_hash(candidate))

    def test_new_independent_receipt_accepts_corrected_candidate(self):
        candidate = self.bundle["candidates"][0]
        candidate["impact"] = "Corrected narrower effect"
        self.bundle["findings"][0]["impact"] = candidate["impact"]
        self.bundle["findings"][0]["verified_candidate_hash"] = candidate_hash(candidate)
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_complete_requires_both_coverage_critics(self):
        for stage in ("planning", "final"):
            with self.subTest(stage=stage):
                bundle = complete_fixture()
                bundle["metadata"]["coverage_reviews"] = [r for r in bundle["metadata"]["coverage_reviews"] if r["stage"] != stage]
                self.assertTrue(any(f"passed {stage} coverage critique" in e for e in validate_bundle(bundle)))

    def test_hunter_cannot_impersonate_coverage_critic(self):
        self.bundle["metadata"]["coverage_reviews"][0]["critic_id"] = "hunter-a"
        self.assert_invalid("coverage critique lacks independent critic")

    def test_planning_and_final_critics_cannot_share_context(self):
        self.bundle["metadata"]["coverage_reviews"][1]["critic_id"] = "critic-planning"
        self.assert_invalid("must use distinct contexts")

    def test_final_critic_receipt_invalidated_by_new_ledger_unit(self):
        unit = copy.deepcopy(self.bundle["ledger"][0])
        unit.update(id="AUTH-002", path_variant="recovery-worker", status="unreviewed",
                    hunter_ids=[], candidate_ids=[], evidence=[], result=None)
        self.bundle["ledger"].append(unit)
        self.assert_invalid("final coverage critique is stale")

    def test_missing_coverage_discovery_cannot_be_discarded(self):
        unit = self.bundle["ledger"][0]
        gap = {key: unit[key] for key in ("subsystem", "boundary", "path_variant", "attack_class", "invariant")}
        gap.update(unit_id=None, evidence=[evidence()])
        self.bundle["metadata"]["coverage_reviews"][0]["missing_units"] = [gap]
        self.assert_invalid("unresolved missing coverage")
        gap["unit_id"] = "AUTH-999"
        self.assert_invalid("missing coverage was not integrated")
        gap["unit_id"] = "AUTH-001"
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_critique_snapshot_cannot_lose_or_relabel_units(self):
        self.bundle["ledger"][0]["path_variant"] = "limited-admin-only"
        self.assert_invalid("critiqued unit removed or materially changed")

    def test_prior_changes_required_discovery_cannot_disappear_at_completion(self):
        planning = self.bundle["metadata"]["coverage_reviews"][0]
        unit = self.bundle["ledger"][0]
        gap = {key: unit[key] for key in ("subsystem", "boundary", "path_variant", "attack_class", "invariant")}
        gap.update(unit_id=None, path_variant="forgotten-cron-worker", evidence=[evidence()])
        planning.update(status="changes_required", missing_units=[gap])
        # Add a later passed planning review that claims no gaps. The earlier gap
        # must still be integrated, even if final criticism claims a clean ledger.
        later = copy.deepcopy(planning)
        later.update(status="passed", critic_id="critic-planning-2", missing_units=[])
        self.bundle["metadata"]["coverage_reviews"].insert(1, later)
        self.bundle["metadata"]["agents"].append({"id": "critic-planning-2", "role": "coverage_critic", "unit_ids": [], "source_manifest_hash": planning["source_manifest_hash"]})
        self.bundle["metadata"]["budget"].update(max_invocations=6, used_invocations=6)
        self.assert_invalid("unresolved missing coverage")

    def test_critic_and_reviewer_source_receipts_cannot_drift(self):
        self.bundle["metadata"]["coverage_reviews"][1]["source_manifest_hash"] = "b" * 64
        self.assert_invalid("critic source snapshot differs")
        self.bundle["metadata"]["final_review"]["source_manifest_hash"] = "b" * 64
        self.assert_invalid("final review source snapshot differs")

    def test_manifest_paths_cannot_escape_source(self):
        self.bundle["source_manifest"]["files"]["../outside.py"] = {"sha256": "a" * 64, "size": 1}
        self.assert_invalid("source manifest path escapes")

    def test_attack_class_invariant_pairs_enforced_for_every_class(self):
        for attack, allowed in ATTACK_CLASS_INVARIANTS.items():
            with self.subTest(attack=attack):
                bundle = complete_fixture()
                bundle["ledger"][0].update(attack_class=attack,
                    invariant=next(f"AGENT-INV-{n:03}" for n in range(1, 13) if f"AGENT-INV-{n:03}" not in allowed))
                self.assertTrue(any("attack-class/invariant mismatch" in e for e in validate_bundle(bundle)))

    def test_complete_full_audit_cannot_be_only_not_applicable(self):
        self.bundle.update(candidates=[], findings=[])
        self.bundle["ledger"][0].update(status="not_applicable", reason="Inspected absence", candidate_ids=[])
        for critique in self.bundle["metadata"]["coverage_reviews"]:
            critique.update(ledger_snapshot=copy.deepcopy(self.bundle["ledger"]), ledger_hash=canonical_hash(self.bundle["ledger"]))
        self.assert_invalid("full audit has no reviewed unit")
        self.bundle["metadata"]["audit_mode"] = "focused"
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_source_manifest_cannot_drift_or_omit_evidence(self):
        self.bundle["source_manifest"]["files"].pop("fixture/store.py")
        self.assert_invalid("source manifest hash mismatch")
        self.assert_invalid("source evidence absent from snapshot")

    def test_all_independent_agents_bind_same_source(self):
        self.bundle["metadata"]["agents"][1]["source_manifest_hash"] = "b" * 64
        self.assert_invalid("agent hunter-a: source snapshot differs")

    def test_runtime_evidence_requires_complete_sandbox_record(self):
        entry = self.bundle["findings"][0]["validation"][0]
        entry.update(method="existing_test", execution_id="exec-1")
        self.assert_invalid("executed validation lacks sandbox record")
        execution = {
            "id": "exec-1", "command": "offline synthetic check", "source_manifest_hash": self.bundle["metadata"]["source_manifest_hash"],
            "enforcement": "Synthetic host sandbox receipt", "evidence": ["Synthetic denied-access receipt"],
            "controls": {k: True for k in ("network_disabled", "source_read_only", "scratch_only_writes", "credentials_absent", "artifacts_inaccessible", "dependency_installation_disabled", "synthetic_data_only")},
            "limits": {"cpu_seconds": 2, "wall_seconds": 4, "memory_bytes": 1000000,
                       "processes": 2, "open_files": 20, "disk_bytes": 1000000}}
        execution["controls"]["environment_allowlist"] = []
        self.bundle["metadata"].update(execution_policy="sandboxed", execution_runs=[execution])
        self.assertEqual(validate_bundle(self.bundle), [])
        execution["controls"]["network_disabled"] = False
        self.assert_invalid("network_disabled")
        execution["controls"]["network_disabled"] = True
        execution["limits"]["wall_seconds"] = 0
        self.assert_invalid("wall_seconds")

    def test_static_policy_cannot_contain_execution(self):
        self.bundle["findings"][0]["validation"][0].update(method="local_fixture", execution_id="missing")
        self.assert_invalid("executed validation lacks sandbox record")

    def test_snapshot_detects_byte_changes_additions_and_deletions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agent.py").write_text("original\n")
            manifest = capture_source(root)
            self.assertEqual(verify_source(manifest, root), [])
            (root / "agent.py").write_text("mutated\n")
            self.assertTrue(verify_source(manifest, root))
            (root / "agent.py").write_text("original\n")
            (root / "worker.py").write_text("untracked\n")
            self.assertTrue(verify_source(manifest, root))
            (root / "worker.py").unlink()
            (root / "agent.py").unlink()
            self.assertTrue(verify_source(manifest, root))

    def test_snapshot_rejects_links_without_reading_outside_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agent.py").write_text("pass\n")
            # Windows symlink creation can require privileges. Mock the detected
            # reparse flag to exercise fail-closed behavior portably.
            with patch("audit_integrity.is_link", side_effect=lambda p: p.name == "agent.py"):
                with self.assertRaisesRegex(ValueError, "Non-regular source"):
                    capture_source(root)

    def test_output_inside_target_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / ".audit" / "run"
            with self.assertRaisesRegex(ValueError, "inside target"):
                check_output(root, output)
            check_output(root, output, True)
            with self.assertRaisesRegex(ValueError, "contain or replace"):
                check_output(root, root, True)

    def test_initialization_and_default_validation_detect_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "agent.py").write_text("pass\n")
            output = Path(temporary) / "output"
            command = [sys.executable, str(SCRIPTS / "init_audit.py"), str(output),
                       "--repository", str(root), "--scope", "agent"]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(validate_directory(output), [])
            (root / "agent.py").write_text("changed\n")
            self.assertTrue(any("source snapshot drift" in e for e in validate_directory(output)))
            self.assertEqual(validate_directory(output, check_source=False), [])

    def test_in_target_opt_in_excludes_only_its_run_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agent.py").write_text("pass\n")
            output = root / ".audit" / "run"
            command = [sys.executable, str(SCRIPTS / "init_audit.py"), str(output),
                       "--repository", str(root), "--scope", "agent", "--allow-in-target-output"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(validate_directory(output), [])
            (root / ".audit" / "other.py").write_text("new source\n")
            self.assertTrue(any("source snapshot drift" in e for e in validate_directory(output)))

    def test_initializer_default_is_outside_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "agent.py").write_text("pass\n")
            host_output = Path(temporary) / "isolated-host-output"
            with patch("init_audit.Path.home", return_value=host_output), patch(
                    "sys.argv", ["init_audit.py", "--repository", str(root), "--scope", "agent"]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(initialize_audit(), 0)
            runs = list((host_output / "agentic-security-audit" / "source").glob("run-*"))
            self.assertEqual(len(runs), 1)
            self.assertFalse(runs[0].is_relative_to(root))
            self.assertEqual(validate_directory(runs[0]), [])

    def test_relocated_snapshot_can_be_checked_without_changing_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, relocated = Path(temporary) / "source", Path(temporary) / "copy"
            root.mkdir()
            relocated.mkdir()
            (root / "agent.py").write_text("pass\n")
            (relocated / "agent.py").write_bytes((root / "agent.py").read_bytes())
            manifest = capture_source(root)
            self.assertEqual(verify_source(manifest, relocated), [])
            (relocated / "agent.py").write_text("changed\n")
            self.assertTrue(verify_source(manifest, relocated))

    def test_git_snapshot_covers_dirty_untracked_and_ignored_bytes_without_filters(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args):
                subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
            git("init")
            git("config", "user.name", "Synthetic Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "core.autocrlf", "false")
            (root / "agent.py").write_text("original\n")
            (root / ".gitignore").write_text("ignored.txt\n")
            git("add", "agent.py", ".gitignore")
            git("commit", "-m", "Synthetic fixture")
            clean = capture_source(root)
            self.assertFalse(clean["dirty"])
            git("config", "core.fsmonitor", "never-run-target-fsmonitor")
            git("config", "diff.external", "never-run-target-diff")
            git("config", "diff.hostile.textconv", "never-run-target-textconv")
            git("config", "filter.hostile.clean", "never-run-target-clean-filter")
            git("config", "filter.hostile.required", "true")
            (root / ".gitattributes").write_text("*.py diff=hostile filter=hostile\n")
            (root / "agent.py").write_text("dirty\n")
            (root / "untracked.txt").write_text("untracked\n")
            (root / "ignored.txt").write_text("ignored\n")
            dirty = capture_source(root)
            self.assertTrue(dirty["dirty"])
            self.assertNotEqual(clean["diff_sha256"], dirty["diff_sha256"])
            self.assertIn("untracked.txt", dirty["files"])
            self.assertIn("ignored.txt", dirty["files"])
            self.assertEqual(verify_source(dirty, root), [])


if __name__ == "__main__":
    unittest.main()
