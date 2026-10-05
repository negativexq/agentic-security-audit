"""Derive Markdown reports from validated JSON records; never upgrade verdicts."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from validate_audit import load_bundle, validate_directory


def md(value) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>#|])", r"\\\1", text)


def location(value: dict) -> str:
    return f"{md(value['path'])}:{value['line']} — {md(value['symbol'])}: {md(value['summary'])}"


def bullet_list(values: list) -> str:
    return "\n".join(f"- {md(value)}" for value in values) or "- None recorded."


def render(bundle: dict) -> dict[str, str]:
    metadata, units = bundle["metadata"], bundle["ledger"]
    candidates, findings = bundle["candidates"], bundle["findings"]
    counts = Counter(unit["status"] for unit in units)
    verdicts = Counter(finding["confidence"] for finding in findings)
    pending = [candidate for candidate in candidates if candidate["status"] == "pending"]
    gaps = [unit for unit in units if unit["status"] not in {"reviewed", "not_applicable"}]
    reasons = [f"{unit['id']}: {unit['status']} — {unit['reason'] or unit['result'] or 'not yet reviewed'}"
               for unit in gaps]
    report = ["# Agentic Security Audit", "", f"Run: {md(metadata['run_id'])}", "",
              f"**Status: {metadata['run_status']}**", ""]
    if metadata["run_status"] == "incomplete":
        report += [f"Incomplete reason: {md(metadata['incomplete_reason'])}", "",
                   f"Outstanding coverage units: {len(gaps)}. Pending candidates: {len(pending)}.", ""]
    report += [f"Repository: {md(metadata['repository'])}", "",
               f"Revision: {md(metadata['revision'])}. Working tree: {md(metadata['working_tree'])}.", "",
               f"Source manifest SHA-256: {metadata['source_manifest_hash']}. Audit mode: {metadata['audit_mode']}.", "",
               f"Threat model SHA-256: {metadata['threat_model_hash']}. See threat-model.md.", "",
               "## Assurance dimensions", "",
               "Completion describes the selected source pass; assessed does not mean secure.", "",
               "| Dimension | Status | Basis | Limitations |", "| --- | --- | --- | --- |"]
    for dimension, assurance in metadata["assurance"].items():
        report.append(f"| {dimension} | {assurance['status']} | {md('; '.join(assurance['basis']))} | {md('; '.join(assurance['limitations']))} |")
    report += ["", "## Target execution", "",
               f"Policy: {metadata['execution_policy']}. Recorded sandboxed executions: {len(metadata['execution_runs'])}.", "",
               "Sandbox records describe host-enforced controls; this validator does not create or attest isolation.", "",
               "## Selected scope", "", bullet_list(metadata["scope"]), "",
               "## Exclusions", "", bullet_list(metadata["exclusions"]), "",
               "## Coverage accounting", "", f"Ledger units: {len(units)}.", "",
               "| Status | Units |", "| --- | ---: |"]
    report += [f"| {status} | {counts[status]} |" for status in
               ("unreviewed", "in_progress", "reviewed", "candidate", "blocked", "deferred", "not_applicable")]
    report += ["", "Reviewed units record inspected paths, not proof of security. Completion applies only to the selected pass.", "",
               "## Coverage gaps", "", bullet_list(reasons), "", "## Pending candidates", "",
               bullet_list([f"{candidate['id']}: {candidate['title']} (units: {', '.join(candidate['unit_ids'])})"
                            for candidate in pending]), "", "## Adjudicated records", "",
               f"Confirmed: {verdicts['confirmed']}. Needs validation: {verdicts['needs_validation']}. Rejected: {verdicts['rejected']}.", "",
               "| ID | Disposition | Severity | Title | Units |", "| --- | --- | --- | --- | --- |"]
    for finding in sorted(findings, key=lambda record: record["id"]):
        report.append(f"| {finding['id']} | {finding['confidence']} | {finding['severity'] or '—'} | {md(finding['title'])} | {', '.join(finding['unit_ids'])} |")
    if not findings:
        report += ["", "No adjudicated findings recorded. This is not a security certification."]
    review = metadata["final_review"]
    budget = metadata["budget"]
    report += ["", "## Independent coverage criticism", ""]
    if not metadata["coverage_reviews"]:
        report.append("No independent coverage critique recorded.")
    for critique in metadata["coverage_reviews"]:
        report += [f"- {critique['stage']}: {critique['status']} — {md(critique['critic_id'])}; missing units raised: {len(critique['missing_units'])}.",
                   f"  Input ledger SHA-256: {critique['ledger_hash']}."]
        report += [f"  - {location(loc)}" for loc in critique["evidence"]]
        for gap in critique["missing_units"]:
            report.append(f"  - {md(gap['subsystem'])} / {md(gap['path_variant'])}: {gap['unit_id'] or 'unresolved'}.")
    report += ["", "## Independent review", "",
               f"Independence: {metadata['independence']} ({metadata['independence_level']}). Final review: {review['status']}. Reviewer: {md(review['reviewer_id'] or 'none')}.", "",
               "Declared independence is a role/context claim. Host-attested independence verifies an externally trusted host signature; it depends on the host's isolation guarantees.", "",
               bullet_list(review["evidence"]), "",
               f"Invocations used: {budget['used_invocations']}; maximum: {budget['max_invocations'] if budget['max_invocations'] is not None else 'not specified'}.", "",
               "## Evidence slices", "",
               "Deterministic, real-model and operational evidence remain separate. Passing assertions are not a security rate.", ""]
    if not metadata["evidence_slices"]:
        report.append("No measured test slices recorded.")
    for slice_ in metadata["evidence_slices"]:
        report += [f"- {slice_['layer']}: {slice_['passed']}/{slice_['attempted']} — {md(slice_['reference'])}",
                   f"  Limitations: {md('; '.join(slice_['limitations']) or 'none recorded')}"]
    report += ["", "## Limitations", "", bullet_list(metadata["limitations"]), "",
               "Detailed source/control/sink traces, verdict evidence and repairs are in FINDINGS-DETAIL.md.", ""]

    details = ["# Findings Detail", "", f"Run: {md(metadata['run_id'])}; revision: {md(metadata['revision'])}.", "",
               "Only independently adjudicated records appear here. Pending allegations remain in candidates.json.", ""]
    for finding in sorted(findings, key=lambda record: record["id"]):
        details += [f"## {finding['id']} — {md(finding['title'])}", "",
                    f"Disposition: {finding['confidence']}. Severity: {finding['severity'] or 'not assigned'}.", ""]
        for label, key in [("Candidate", "candidate_id"), ("Fingerprint", "fingerprint"),
                           ("Verified candidate SHA-256", "verified_candidate_hash"),
                           ("Source manifest SHA-256", "source_manifest_hash"),
                           ("Primary invariant", "primary_invariant"), ("Attacker", "attacker"), ("Affected principal", "principal"),
                           ("Execution identity", "execution_identity"), ("Affected resource", "affected_resource"),
                           ("Boundary", "boundary"), ("Control failure / alleged failure", "control_failure"),
                           ("Impact / alleged impact", "impact")]:
            details += [f"{label}: {md(finding[key])}", ""]
        details += [f"Coverage units: {', '.join(finding['unit_ids'])}.", "", "### Source trace", ""]
        for field in ("source", "control", "sink"):
            details.append(f"- {field.title()}: {location(finding[field])}")
        details += ["", "### Exploit chain", "",
                    f"Contributing invariants: {md(', '.join(finding['contributing_invariants']) or 'none')}.", ""]
        for step in finding["exploit_chain"]:
            details += [f"- {md(step['id'])} / {step['unit_id']} / {step['invariant']}: {md(step['input_state'])} → {md(step['output_state'])}",
                        f"  Control: {location(step['control'])}. Failure: {md(step['control_failure'])}"]
        if not finding["exploit_chain"]:
            details.append("Single-control allegation; no composite chain recorded.")
        details += ["", "### Delegation provenance", ""]
        for edge in finding["delegation_provenance"]:
            details += [f"- {md(edge['from_identity'])} → {md(edge['to_identity'])}: granted {md(', '.join(edge['granted_scope']))}; effective {md(', '.join(edge['effective_scope']))}.",
                        f"  Origin: {location(edge['grant_source'])}. Restriction / alleged failure: {md(edge['restriction'])}"]
        if not finding["delegation_provenance"]:
            details.append("No delegated authority in this allegation.")
        details += ["", "### Reachability", ""]
        for axis in ("attacker_reachability", "effect_reachability"):
            reach = finding[axis]
            details += [f"- {axis}: {reach['status']} — {md(reach['claim'])}; evidence: {md(', '.join(reach['evidence_ids']))}.",
                        f"  Missing facts: {md('; '.join(reach['missing_facts']) or 'none')}."]
        details += ["", "### Minimum evidence", ""]
        from audit_claims import mandatory_claims
        details += [f"Enabled claim features: {md(', '.join(k for k, enabled in finding['claim_features'].items() if enabled) or 'none')}.", "",
                    f"Derived mandatory claims: {md(', '.join(sorted(mandatory_claims(finding['claim_features']))))}.", ""]
        requirements = {r["id"]: r for r in finding["minimum_evidence"]}
        for result in finding["requirement_results"]:
            requirement = requirements[result["requirement_id"]]
            details += [f"- {md(result['requirement_id'])}: {requirement['claim']} ({md(requirement['step_id'] or 'whole path')}) — {result['status']}; evidence: {md(', '.join(result['evidence_ids']))}.",
                        f"  {md(result['rationale'])} Missing facts: {md('; '.join(result['missing_facts']) or 'none')}."]
        details += ["", "### Threat dependencies", "",
                    f"Threat model SHA-256: {finding['threat_model_hash']}. Assumptions: {md(', '.join(finding['assumption_ids']) or 'none')}. Attacker capabilities: {md(', '.join(finding['capability_ids']))}.", "",
                    "### Preconditions", "", bullet_list(finding["preconditions"]), "",
                    f"### Verifier evidence — {md(finding['verifier_id'])}", ""]
        details += [f"- {location(loc)}" for loc in finding["verifier_evidence"]]
        details += ["", "### Validation performed", ""]
        if not finding["validation"]:
            details.append("No runtime or static validation entry recorded; see unresolved/rejection evidence.")
        for validation in finding["validation"]:
            details += [f"- {md(validation['id'])} / {validation['method']}: {md(validation['reference'])} — {md(validation['result'])}; proves: {md(', '.join(validation['proves']))}.",
                        f"  Limitations: {md('; '.join(validation['limitations']) or 'none recorded')}"]
        details += ["", "### Counterevidence", "", bullet_list(finding["counterevidence"]), ""]
        for label, key in [("Severity rationale", "severity_rationale"), ("Missing fact", "missing_fact"),
                           ("Bounded validation plan", "validation_plan"), ("Rejection reason", "rejection_reason"),
                           ("Smallest effective fix", "recommendation"), ("Regression assertion", "regression_assertion")]:
            if finding[key]:
                details += [f"{label}: {md(finding[key])}", ""]
    if not findings:
        details += ["No adjudicated records.", ""]
    threat = bundle["threat_model"]
    model = ["# Threat Model", "", f"SHA-256: {metadata['threat_model_hash']}", "",
             "## Scope", "", bullet_list(threat["scope"]), "", "## Trust anchors", ""]
    for anchor in threat["anchors"]:
        model += [f"- {md(anchor['id'])}: {md(anchor['component'])} — {anchor['trust']}. {md(anchor['rationale'])}"]
        model += [f"  - {location(loc)}" for loc in anchor["evidence"]]
    model += ["", "## Assumptions", ""]
    for assumption in threat["assumptions"]:
        model += [f"- {md(assumption['id'])}: {assumption['status']} ({assumption['dimension']}) — {md(assumption['statement'])}",
                  f"  Anchors: {md(', '.join(assumption['anchor_ids']))}; reference: {md(assumption['reference'] or 'none')}."]
        model += [f"  - {location(loc)}" for loc in assumption["evidence"]]
    model += ["", "## Attacker capabilities", ""]
    for capability in threat["attacker_capabilities"]:
        model += [f"- {md(capability['id'])}: {capability['status']} — {md(capability['description'])}; anchors: {md(', '.join(capability['anchor_ids']))}.",
                  f"  Deployment-dependent: {capability['deployment_dependent']}; assumptions: {md(', '.join(capability['assumption_ids']) or 'none')}."]
        model += [f"  - {location(loc)}" for loc in capability["evidence"]]
        for receipt in capability["deployment_evidence"]:
            model += [f"  - Configuration: {md(receipt['reference'])}; SHA-256: {receipt['sha256']}; environment: {md(receipt['environment'])}.",
                      f"    Result: {md(receipt['result'])}. Limits: {md('; '.join(receipt['limitations']) or 'none recorded')}."]
    model += ["", "## Limitations", "", bullet_list(threat["limitations"]), ""]
    return {"REPORT.md": "\n".join(report), "FINDINGS-DETAIL.md": "\n".join(details), "threat-model.md": "\n".join(model)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--offline", action="store_true", help="Render archived structural records; do not check current source")
    parser.add_argument("--trusted-host-keys", type=Path)
    args = parser.parse_args()
    errors = validate_directory(args.directory, check_reports=False, check_source=not args.offline,
                                source_root=args.source_root, trusted_host_keys_path=args.trusted_host_keys)
    if errors:
        raise SystemExit("\n".join(errors))
    for name, content in render(load_bundle(args.directory)).items():
        (args.directory / name).write_text(content, encoding="utf-8", newline="\n")
    print("Rendered REPORT.md, FINDINGS-DETAIL.md and threat-model.md from JSON records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
