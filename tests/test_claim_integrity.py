"""Adversarial contract tests; these are not vulnerability-detection benchmarks."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from test_audit_contract import complete_fixture, evidence, write_bundle
from audit_integrity import ALLEGATION_FIELDS, candidate_hash, canonical_hash
from audit_claims import FEATURE_REQUIREMENTS, attested_bundle_hash, load_trusted_keys
from render_report import render
from validate_audit import fingerprint, validate_bundle, validate_directory


def refresh_allegation(bundle):
    candidate, finding = bundle["candidates"][0], bundle["findings"][0]
    candidate["fingerprint"] = fingerprint(candidate)
    for field in ALLEGATION_FIELDS:
        finding[field] = copy.deepcopy(candidate[field])
    finding["fingerprint"] = candidate["fingerprint"]
    finding["unit_ids"] = copy.deepcopy(candidate["unit_ids"])
    finding["verified_candidate_hash"] = candidate_hash(candidate)


def refresh_threat(bundle):
    digest = canonical_hash(bundle["threat_model"])
    bundle["metadata"]["threat_model_hash"] = digest
    for record in bundle["metadata"]["agents"] + bundle["metadata"]["coverage_reviews"]:
        record["threat_model_hash"] = digest
    bundle["metadata"]["final_review"]["threat_model_hash"] = digest
    bundle["candidates"][0]["threat_model_hash"] = digest
    refresh_allegation(bundle)


def add_requirement(bundle, claim, rid="REQ-SPECIAL"):
    for feature, requirement_claim in FEATURE_REQUIREMENTS.items():
        if requirement_claim == claim:
            bundle["candidates"][0]["claim_features"][feature] = True
    bundle["candidates"][0]["minimum_evidence"].append({
        "id": rid, "claim": claim, "description": "Bounded synthetic claim", "step_id": None, "assumption_ids": []})
    finding = bundle["findings"][0]
    finding["requirement_results"].append({"requirement_id": rid, "status": "satisfied",
        "evidence_ids": ["EVID-1"], "rationale": "Synthetic evidence", "missing_facts": []})
    finding["validation"][0]["proves"].append(rid)
    refresh_allegation(bundle)


def composite_fixture():
    bundle = complete_fixture()
    candidate, finding = bundle["candidates"][0], bundle["findings"][0]
    unit = copy.deepcopy(bundle["ledger"][0])
    unit.update(id="AUTH-002", attack_class="05", invariant="AGENT-INV-005", boundary="approval -> write")
    bundle["ledger"].append(unit)
    candidate["unit_ids"].append("AUTH-002")
    candidate["contributing_invariants"] = ["AGENT-INV-005"]
    approval = evidence("fixture/store.py", 20, "approve", "Mutable action bypasses exact approval")
    candidate["exploit_chain"] = [
        {"id": "STEP-1", "unit_id": "AUTH-001", "invariant": "AGENT-INV-002", "root_cause": candidate["root_cause"],
         "source": copy.deepcopy(candidate["source"]), "control": copy.deepcopy(candidate["control"]),
         "sink": copy.deepcopy(candidate["control"]), "input_state": "untrusted proposal",
         "output_state": "unscoped pending action", "boundary": candidate["boundary"], "control_failure": candidate["control_failure"]},
        {"id": "STEP-2", "unit_id": "AUTH-002", "invariant": "AGENT-INV-005", "root_cause": "approval:mutable-action",
         "source": copy.deepcopy(candidate["control"]), "control": approval, "sink": copy.deepcopy(candidate["sink"]),
         "input_state": "unscoped pending action", "output_state": "unauthorized write",
         "boundary": "approval -> write", "control_failure": "Approval does not bind arguments"}]
    candidate["minimum_evidence"][1]["step_id"] = "STEP-1"
    add_requirement(bundle, "source_control", "REQ-SECOND")
    candidate["minimum_evidence"][-1]["step_id"] = "STEP-2"
    finding["validation"][0]["source_locations"].append(copy.deepcopy(approval))
    for agent in bundle["metadata"]["agents"]:
        if agent["unit_ids"]:
            agent["unit_ids"].append("AUTH-002")
    for critic in bundle["metadata"]["coverage_reviews"]:
        critic.update(ledger_snapshot=copy.deepcopy(bundle["ledger"]), ledger_hash=canonical_hash(bundle["ledger"]))
    refresh_allegation(bundle)
    return bundle


class ClaimIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.bundle = complete_fixture()

    def invalid(self, fragment):
        errors = validate_bundle(self.bundle)
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_source_completion_preserves_unassessed_runtime_deployment_external(self):
        self.assertEqual(validate_bundle(self.bundle), [])
        report = render(self.bundle)["REPORT.md"]
        self.assertIn("| runtime | not_assessed", report)
        self.assertIn("| deployment | not_assessed", report)
        self.assertIn("| external | not_assessed", report)

    def test_decisive_capability_requires_ingress_evidence(self):
        self.bundle["threat_model"]["attacker_capabilities"][0]["evidence"] = []
        refresh_threat(self.bundle)
        self.invalid("decisive capability lacks ingress evidence")

    def test_unknown_capability_blocks_confirmation_and_established_entry(self):
        cap = self.bundle["threat_model"]["attacker_capabilities"][0]
        cap.update(status="unknown", evidence=[])
        refresh_threat(self.bundle)
        self.invalid("confirmed uses unestablished attacker capability")
        self.invalid("attacker reachability uses unestablished capability")
        finding = self.bundle["findings"][0]
        finding.update(confidence="needs_validation", severity=None, severity_rationale=None,
                       missing_fact="Ingress access unknown", validation_plan="Inspect owner routing")
        finding["attacker_reachability"].update(status="unresolved", evidence_ids=[], missing_facts=["Ingress access"])
        self.invalid("satisfied requirement relies on unresolved assumption/capability")
        finding["requirement_results"][0].update(status="unresolved", evidence_ids=[], missing_facts=["Ingress access"])
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_source_ingress_does_not_prove_production_endpoint_exposure(self):
        cap = self.bundle["threat_model"]["attacker_capabilities"][0]
        cap["deployment_dependent"] = True
        refresh_threat(self.bundle)
        self.invalid("decisive deployment capability lacks deployment assumption")
        self.invalid("decisive deployment capability lacks config evidence")
        self.bundle["threat_model"]["assumptions"] = [{"id": "public-route", "statement": "Fixture ingress accessible in named environment",
            "status": "established", "dimension": "deployment", "anchor_ids": ["user-input"], "evidence": [], "reference": "Frozen synthetic routing config"}]
        cap["assumption_ids"] = ["public-route"]
        cap["deployment_evidence"] = [{"method": "deployment_configuration", "reference": "Owner-frozen synthetic routes",
            "sha256": "c" * 64, "environment": "isolated synthetic environment", "result": "Route available to fixture caller", "limitations": ["Not a real deployment"]}]
        self.bundle["metadata"]["assurance"]["deployment"] = {"status": "partial", "basis": ["Frozen fixture routes"], "limitations": ["Synthetic only"]}
        refresh_threat(self.bundle)
        self.invalid("capability hides necessary assumption")
        self.bundle["candidates"][0]["assumption_ids"] = ["public-route"]
        refresh_allegation(self.bundle)
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_every_feature_derives_a_mandatory_requirement(self):
        for feature, claim in FEATURE_REQUIREMENTS.items():
            with self.subTest(feature=feature):
                bundle = complete_fixture()
                bundle["candidates"][0]["claim_features"][feature] = True
                refresh_allegation(bundle)
                self.assertTrue(any("mandatory evidence requirements missing: " + claim in e for e in validate_bundle(bundle)))

    def test_feature_declaration_is_required_and_receipt_bound(self):
        self.bundle["candidates"][0].pop("claim_features")
        self.invalid("'claim_features' is a required property")
        self.bundle = complete_fixture()
        self.bundle["candidates"][0]["claim_features"]["network_dependent"] = True
        self.bundle["findings"][0]["claim_features"]["network_dependent"] = True
        self.invalid("verified candidate snapshot differs")

    def test_requirements_cannot_hide_a_known_feature(self):
        add_requirement(self.bundle, "network_route")
        self.bundle["candidates"][0]["claim_features"]["network_dependent"] = False
        refresh_allegation(self.bundle)
        self.invalid("evidence claim has disabled feature: network_dependent")

    def test_model_and_delegation_flags_must_match_structured_paths(self):
        self.bundle["candidates"][0]["attacker_route"] = "model_mediated"
        refresh_allegation(self.bundle)
        self.invalid("model feature differs from attacker route")
        self.bundle["candidates"][0]["claim_features"]["delegated"] = True
        refresh_allegation(self.bundle)
        self.invalid("delegated feature differs from provenance")

    def refuted_assumption(self):
        self.bundle["threat_model"]["assumptions"] = [{"id": "required-source-fact", "statement": "Necessary route enabled",
            "status": "refuted", "dimension": "source", "anchor_ids": ["user-input"], "evidence": [evidence()], "reference": None}]
        self.bundle["candidates"][0]["assumption_ids"] = ["required-source-fact"]
        refresh_threat(self.bundle)

    def reject(self):
        self.bundle["findings"][0].update(confidence="rejected", severity=None, severity_rationale=None,
            missing_fact=None, validation_plan=None, rejection_reason="Necessary precondition refuted", counterevidence=["Synthetic necessary source fact is false"])

    def test_refuted_necessary_assumption_requires_rejection_even_with_unknown_axis(self):
        self.refuted_assumption()
        self.invalid("refuted necessary dependency requires rejection")
        finding = self.bundle["findings"][0]
        finding.update(confidence="needs_validation", severity=None, severity_rationale=None, missing_fact="Other unknown", validation_plan="Inspect other route")
        finding["effect_reachability"].update(status="unresolved", missing_facts=["Other unknown"])
        self.invalid("refuted necessary dependency requires rejection")
        self.reject()
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_requirement_dependency_refutation_propagates_without_invented_evidence(self):
        self.refuted_assumption()
        self.bundle["candidates"][0]["minimum_evidence"][1]["assumption_ids"] = ["required-source-fact"]
        refresh_allegation(self.bundle)
        self.reject()
        self.invalid("refuted dependency requires refuted requirement")
        self.bundle["findings"][0]["requirement_results"][1].update(status="refuted", evidence_ids=[], rationale="Necessary source assumption refuted by threat-model evidence")
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_refuted_capability_can_defeat_entry_without_fabricated_requirement_evidence(self):
        self.bundle["threat_model"]["attacker_capabilities"][0]["status"] = "refuted"
        refresh_threat(self.bundle)
        self.reject()
        finding = self.bundle["findings"][0]
        finding["attacker_reachability"]["status"] = "refuted"
        finding["requirement_results"][0].update(status="refuted", evidence_ids=[], rationale="Capability refuted by ingress evidence")
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_human_persuasion_cannot_be_proved_by_static_trace_or_software_test(self):
        add_requirement(self.bundle, "human_action_binding", "REQ-HUMAN-BINDING")
        add_requirement(self.bundle, "human_persuasion", "REQ-HUMAN-PERSUASION")
        self.invalid("minimum evidence not met for human_persuasion")
        finding = self.bundle["findings"][0]
        finding["validation"].append({"id": "EVID-HUMAN", "method": "controlled_human_observation",
            "reference": "Frozen synthetic controlled participant observation", "result": "Observed bounded human approval under misleading evidence",
            "limitations": ["Synthetic receipt, no actual participants; no general persuasion claim"], "execution_id": None,
            "proves": ["REQ-HUMAN-PERSUASION"], "source_locations": []})
        finding["requirement_results"][-1]["evidence_ids"] = ["EVID-HUMAN"]
        self.bundle["metadata"]["assurance"]["runtime"] = {"status": "partial", "basis": ["Controlled receipt inspected"], "limitations": ["Synthetic contract example"]}
        self.assertEqual(validate_bundle(self.bundle), [])
        finding["validation"][-1]["method"] = "owner_observation"
        self.bundle["metadata"]["assurance"]["deployment"] = {"status": "partial", "basis": ["Owner observation receipt"], "limitations": ["Synthetic only"]}
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_persuasion_cannot_disable_human_action_binding_dependency(self):
        add_requirement(self.bundle, "human_persuasion")
        self.invalid("persuasion hides human dependency")
        self.bundle["candidates"][0]["claim_features"]["human_dependent"] = True
        refresh_allegation(self.bundle)
        self.invalid("mandatory evidence requirements missing: human_action_binding")

    def test_source_complete_needs_source_assurance_and_trust_map(self):
        self.bundle["metadata"]["assurance"]["source"]["status"] = "partial"
        self.invalid("complete source pass lacks source assurance")
        self.bundle["threat_model"]["anchors"] = []
        self.invalid("complete run lacks reconstructed trust anchors")

    def test_threat_mutation_invalidates_all_receipts(self):
        self.bundle["threat_model"]["anchors"][0]["trust"] = "trusted"
        self.invalid("threat model hash mismatch")
        self.invalid("agent hunter-a: threat model differs")
        self.invalid("coverage critic threat model differs")
        self.invalid("final review threat model differs")

    def test_unknown_anchor_and_capability_are_rejected(self):
        self.bundle["candidates"][0]["capability_ids"] = ["invented-access"]
        self.invalid("attacker capability missing/unknown")
        self.bundle["threat_model"]["attacker_capabilities"][0]["anchor_ids"] = ["absent"]
        self.invalid("unknown anchor")

    def test_confirmed_cannot_depend_on_assumed_provider_fact(self):
        self.bundle["threat_model"]["assumptions"] = [{"id": "provider-atomicity", "statement": "Remote writes are atomic",
            "status": "assumed", "dimension": "external", "anchor_ids": [], "evidence": [], "reference": None}]
        self.bundle["candidates"][0]["assumption_ids"] = ["provider-atomicity"]
        refresh_threat(self.bundle)
        self.invalid("confirmed depends on unresolved threat assumption")
        self.bundle["metadata"]["assurance"]["external"] = {"status": "assessed", "basis": ["Assertion only"], "limitations": []}
        self.invalid("external assurance hides unresolved assumption")
        self.bundle["metadata"]["assurance"]["external"]["status"] = "not_applicable"
        self.invalid("external assurance masks relevant assumption as absent")

    def test_effect_proof_does_not_establish_attacker_reachability(self):
        finding = self.bundle["findings"][0]
        finding["attacker_reachability"].update(status="unresolved", evidence_ids=[], missing_facts=["Can attacker supply input?"])
        self.invalid("confirmed lacks established attacker reachability")
        finding.update(confidence="needs_validation", severity=None, severity_rationale=None,
                       missing_fact="Attacker route", validation_plan="Inspect caller ingress")
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_reachability_proof_must_reference_the_right_axis_and_endpoint(self):
        finding = self.bundle["findings"][0]
        finding["validation"][0]["proves"].remove("axis:attacker")
        self.invalid("evidence not bound to attacker reachability")
        finding["validation"][0]["source_locations"] = [finding["control"]]
        self.invalid("attacker evidence omits endpoint")
        self.invalid("effect evidence omits endpoint")

    def test_model_mediated_entry_needs_observed_inducement(self):
        self.bundle["candidates"][0]["attacker_route"] = "model_mediated"
        refresh_allegation(self.bundle)
        self.invalid("model-mediated entry lacks inducement requirement")
        add_requirement(self.bundle, "model_inducement")
        self.invalid("minimum evidence not met for model_inducement")

    def test_owner_frozen_model_sample_can_support_only_the_bounded_route(self):
        self.bundle["candidates"][0]["attacker_route"] = "model_mediated"
        add_requirement(self.bundle, "model_inducement")
        finding = self.bundle["findings"][0]
        finding["validation"].append({"id": "EVID-MODEL", "method": "real_model_sample",
            "reference": "Synthetic owner-frozen model/version/input/output sample", "result": "One bounded induced proposal",
            "limitations": ["Synthetic example, no detection measurement or general success rate"], "execution_id": None,
            "proves": ["REQ-SPECIAL", "axis:attacker"], "source_locations": []})
        finding["requirement_results"][-1]["evidence_ids"] = ["EVID-MODEL"]
        finding["attacker_reachability"]["evidence_ids"] = ["EVID-MODEL"]
        self.bundle["metadata"]["assurance"]["runtime"] = {"status": "partial", "basis": ["One owner-frozen sample"], "limitations": ["No broad model measurement"]}
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_distributed_sequence_cannot_be_confirmed_by_ordinary_trace(self):
        add_requirement(self.bundle, "failure_propagation")
        self.invalid("minimum evidence not met for failure_propagation")

    def test_human_binding_requires_a_bound_claim_disposition(self):
        add_requirement(self.bundle, "human_action_binding")
        self.assertEqual(validate_bundle(self.bundle), [])
        self.bundle["findings"][0]["requirement_results"][-1].update(status="unresolved", missing_facts=["Operator action preview unknown"])
        self.invalid("confirmed has unmet evidence requirement")

    def test_requirement_results_cannot_omit_or_invent_requirements(self):
        self.bundle["findings"][0]["requirement_results"].pop()
        self.invalid("evidence requirement dispositions differ")

    def test_confirmed_chain_cannot_skip_unresolved_step(self):
        self.bundle = composite_fixture()
        self.assertEqual(validate_bundle(self.bundle), [])
        self.bundle["findings"][0]["requirement_results"][-1].update(status="unresolved", evidence_ids=[], missing_facts=["Approval binding unknown"])
        self.invalid("confirmed has unmet evidence requirement")

    def test_composite_needs_connected_states_endpoints_and_matching_units(self):
        self.bundle = composite_fixture()
        self.bundle["candidates"][0]["exploit_chain"][1]["input_state"] = "unrelated state"
        refresh_allegation(self.bundle)
        self.invalid("disconnected exploit chain")
        self.bundle["candidates"][0]["exploit_chain"][1]["unit_id"] = "AUTH-001"
        refresh_allegation(self.bundle)
        self.invalid("chain step lacks matching coverage")

    def test_composite_primary_cause_cannot_be_invented_outside_chain(self):
        self.bundle = composite_fixture()
        self.bundle["candidates"][0]["root_cause"] = "invented-primary-cause"
        refresh_allegation(self.bundle)
        self.invalid("primary cause is absent from exploit chain")

    def test_composite_step_requires_its_own_control_proof(self):
        self.bundle = composite_fixture()
        self.bundle["findings"][0]["validation"][0]["source_locations"].pop()
        self.invalid("chain evidence omits control")
        self.bundle["candidates"][0]["minimum_evidence"][-1]["step_id"] = None
        refresh_allegation(self.bundle)
        self.invalid("chain step lacks evidence requirement")

    def test_structured_chain_mutation_invalidates_candidate_receipt(self):
        self.bundle = composite_fixture()
        self.bundle["findings"][0]["exploit_chain"][0]["control_failure"] = "Changed cause"
        self.invalid("allegation field changed: exploit_chain")

    def test_distinct_controls_and_chains_have_distinct_fingerprints(self):
        candidate = self.bundle["candidates"][0]
        original = fingerprint(candidate)
        candidate["control"]["symbol"] = "alternate_enforcement"
        self.assertNotEqual(original, fingerprint(candidate))
        chain = composite_fixture()["candidates"][0]
        original = fingerprint(chain)
        chain["exploit_chain"][1]["root_cause"] = "approval:other-independent-failure"
        self.assertNotEqual(original, fingerprint(chain))
        original = fingerprint(chain)
        chain["exploit_chain"][1]["control"]["line"] += 100
        self.assertEqual(original, fingerprint(chain))

    def test_remote_outcome_needs_provider_contract_not_just_a_local_trace(self):
        add_requirement(self.bundle, "remote_write_outcome")
        self.invalid("minimum evidence not met for remote_write_outcome")
        finding = self.bundle["findings"][0]
        finding["validation"].append({"id": "EVID-PROVIDER", "method": "provider_contract", "reference": "Synthetic owner-frozen provider contract",
            "result": "Contract exposes non-idempotent commit", "limitations": ["Synthetic contract only"], "execution_id": None,
            "proves": ["REQ-SPECIAL"], "source_locations": []})
        finding["requirement_results"][-1]["evidence_ids"].append("EVID-PROVIDER")
        self.bundle["metadata"]["assurance"]["external"] = {"status": "partial", "basis": ["Provider contract inspected"], "limitations": ["No live provider execution"]}
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_network_route_requires_deployment_configuration(self):
        add_requirement(self.bundle, "network_route")
        self.invalid("minimum evidence not met for network_route")

    def test_race_needs_interleaving_proof_not_ordinary_trace(self):
        add_requirement(self.bundle, "race_interleaving")
        self.invalid("minimum evidence not met for race_interleaving")
        self.bundle["findings"][0]["validation"][0]["method"] = "static_interleaving"
        # Retain a source trace for the ordinary control requirement as well.
        trace = copy.deepcopy(self.bundle["findings"][0]["validation"][0])
        trace.update(id="EVID-TRACE", method="static_trace")
        self.bundle["findings"][0]["validation"].append(trace)
        for result in self.bundle["findings"][0]["requirement_results"]:
            result["evidence_ids"].append("EVID-TRACE")
        self.assertEqual(validate_bundle(self.bundle), [])

    def test_delegation_records_origin_scope_and_continuity(self):
        candidate = self.bundle["candidates"][0]
        candidate["delegation_provenance"] = [{"id": "DEL-1", "from_identity": "parent", "to_identity": "child",
            "grant_source": evidence(), "granted_scope": ["tenant:A:write"], "effective_scope": ["tenant:*:write"],
            "restriction": "Alleged scope expansion at worker", "unit_id": "AUTH-001"}]
        refresh_allegation(self.bundle)
        self.invalid("delegation lacks evidence requirement")
        add_requirement(self.bundle, "delegation_scope")
        self.assertEqual(validate_bundle(self.bundle), [])
        edge = copy.deepcopy(candidate["delegation_provenance"][0])
        edge.update(id="DEL-2", from_identity="unrelated", to_identity="worker")
        candidate["delegation_provenance"].append(edge)
        refresh_allegation(self.bundle)
        self.invalid("disconnected delegation provenance")

    def test_unresolved_and_rejected_verdicts_need_structured_dispositions(self):
        finding = self.bundle["findings"][0]
        finding.update(confidence="needs_validation", severity=None, severity_rationale=None,
                       missing_fact="Unbound arbitrary missing fact", validation_plan="Inspect it")
        self.invalid("needs-validation lacks structured unresolved fact")
        finding.update(confidence="rejected", missing_fact=None, validation_plan=None, rejection_reason="Assertion")
        self.invalid("rejection lacks structured refutation")

    def test_threat_markdown_is_derived_and_drift_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_bundle(directory, self.bundle)
            (directory / "threat-model.md").write_text("Replaced trust assumptions")
            self.assertTrue(any("threat-model.md: missing/stale" in e for e in validate_directory(directory, check_source=False)))

    def test_trusted_keys_cannot_come_from_target_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, output = base / "target", base / "output"
            source.mkdir(); output.mkdir()
            for directory in (source, output):
                key = directory / "keys.json"
                key.write_text(json.dumps({"synthetic": "a" * 64}))
                with self.assertRaisesRegex(ValueError, "outside target"):
                    load_trusted_keys(key, source, output)


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Install requirements-attestation.txt to exercise host signatures")
class HostAttestationTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.bundle = complete_fixture()
        self.private = Ed25519PrivateKey.generate()
        self.keys = {"synthetic-host": self.private.public_key().public_bytes_raw().hex()}
        self.bundle["metadata"]["independence_level"] = "host_attested"
        self.sign()

    def sign(self):
        receipt = {"key_id": "synthetic-host", "bundle_hash": attested_bundle_hash(self.bundle),
                   "contexts": [{"agent_id": a["id"], "context_id": "synthetic-" + a["id"], "isolation": "Synthetic independent fixture context"}
                                for a in self.bundle["metadata"]["agents"]]}
        payload = json.dumps(receipt, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        receipt["signature"] = self.private.sign(payload).hex()
        self.bundle["metadata"]["host_attestation"] = receipt

    def test_trusted_signature_is_valid_but_no_self_selected_key_is_accepted(self):
        self.assertEqual(validate_bundle(self.bundle, self.keys), [])
        self.assertTrue(any("externally trusted public key" in e for e in validate_bundle(self.bundle)))

    def test_record_mutation_and_forged_signature_fail(self):
        self.bundle["findings"][0]["recommendation"] = "Changed after signing"
        self.assertTrue(any("bundle hash differs" in e for e in validate_bundle(self.bundle, self.keys)))
        self.sign()
        self.bundle["metadata"]["host_attestation"]["signature"] = "a" * 128
        self.assertTrue(any("signature invalid" in e for e in validate_bundle(self.bundle, self.keys)))

    def test_even_signed_context_reuse_is_rejected(self):
        receipt = self.bundle["metadata"]["host_attestation"]
        receipt["contexts"][1]["context_id"] = receipt["contexts"][0]["context_id"]
        payload = {k: v for k, v in receipt.items() if k != "signature"}
        receipt["signature"] = self.private.sign(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hex()
        self.assertTrue(any("reuses context" in e for e in validate_bundle(self.bundle, self.keys)))

    def test_directory_validation_requires_external_pinned_key_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory = base / "output"
            directory.mkdir()
            key = base / "trusted-keys.json"
            key.write_text(json.dumps(self.keys))
            write_bundle(directory, self.bundle)
            self.assertEqual(validate_directory(directory, check_source=False, trusted_host_keys_path=key), [])
