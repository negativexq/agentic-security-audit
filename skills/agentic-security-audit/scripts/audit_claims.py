"""Validate bounded claims, evidence dependencies and externally trusted receipts.

These checks account for evidence; they cannot decide whether a trace is true.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from audit_integrity import canonical_hash

# Every group must be represented. A local test is not a provider contract or
# deployment observation. Requirements follow the claim, not a category label.
MINIMUM_METHODS = {
    "source_control": ({"static_trace", "local_fixture", "existing_test"},),
    "attacker_entry": ({"static_trace", "local_fixture", "existing_test", "owner_observation", "real_model_sample"},),
    "model_inducement": ({"real_model_sample"},),
    "race_interleaving": ({"static_interleaving", "local_fixture", "existing_test"},),
    "network_route": ({"deployment_configuration"}, {"static_trace", "local_fixture", "existing_test"}),
    "remote_write_outcome": ({"provider_contract"}, {"static_trace", "local_fixture", "existing_test"}),
    "delegation_scope": ({"static_trace", "local_fixture", "existing_test"},),
    "human_action_binding": ({"static_trace", "local_fixture", "existing_test"},),
    "human_persuasion": ({"owner_observation", "controlled_human_observation"},),
    "failure_propagation": ({"static_interleaving", "local_fixture", "existing_test"},),
}
METHOD_DIMENSIONS = {
    "static_trace": "source", "static_interleaving": "source",
    "local_fixture": "runtime", "existing_test": "runtime",
    "real_model_sample": "runtime", "owner_observation": "deployment",
    "deployment_configuration": "deployment", "provider_contract": "external",
    "controlled_human_observation": "runtime",
}
FEATURE_REQUIREMENTS = {
    "remote_effect": "remote_write_outcome", "network_dependent": "network_route",
    "race_dependent": "race_interleaving", "human_dependent": "human_action_binding",
    "human_persuasion": "human_persuasion", "distributed_sequence": "failure_propagation",
    "model_mediated": "model_inducement", "delegated": "delegation_scope",
}


def mandatory_claims(features):
    """Evidence bar is derived from explicit dependency flags, not chosen claims."""
    return {"source_control", "attacker_entry"} | {
        claim for feature, claim in FEATURE_REQUIREMENTS.items() if features[feature]}


def attested_bundle_hash(bundle):
    payload = copy.deepcopy(bundle)
    # Signature and contexts cannot include themselves. All substantive records,
    # statuses, evidence and role assignments remain bound by the bundle hash.
    payload["metadata"]["host_attestation"] = None
    return canonical_hash(payload)


def load_trusted_keys(path: Path, source: Path, output: Path):
    resolved = path.resolve()
    for boundary in (source.resolve(), output.resolve()):
        if resolved == boundary or boundary in resolved.parents:
            raise ValueError("Trusted host keys must be supplied outside target and audit output")
    from validate_audit import read_json
    keys = read_json(resolved)
    if not isinstance(keys, dict) or not keys or any(
            not isinstance(k, str) or not isinstance(v, str) or len(v) != 64
            or any(c not in "0123456789abcdef" for c in v) for k, v in keys.items()):
        raise ValueError("Expected trusted key ID -> raw Ed25519 public-key hex mapping")
    return keys


def validate_claims(bundle, require, locations, trusted_host_keys=None):
    meta = bundle["metadata"]
    threat = bundle["threat_model"]
    threat_hash = canonical_hash(threat)
    units = {u["id"]: u for u in bundle["ledger"]}
    anchors = {a["id"]: a for a in threat["anchors"]}
    assumptions = {a["id"]: a for a in threat["assumptions"]}
    capabilities = {c["id"]: c for c in threat["attacker_capabilities"]}
    require(meta["threat_model_hash"] == threat_hash, "threat model hash mismatch")
    require(threat["scope"] == meta["scope"], "threat model scope differs from audit scope")
    for label, records in (("anchor", threat["anchors"]), ("assumption", threat["assumptions"]),
                           ("capability", threat["attacker_capabilities"])):
        require(len({r["id"] for r in records}) == len(records), f"duplicate threat {label}")
        for record in records:
            locations.extend(record["evidence"])
            if "anchor_ids" in record:
                require(set(record["anchor_ids"]) <= anchors.keys(), f"threat {label}: unknown anchor")
            if label == "anchor":
                require(record["trust"] == "unknown" or bool(record["evidence"]), "trust anchor lacks source evidence")
            if label == "assumption" and record["status"] in {"established", "refuted"}:
                require(bool(record["evidence"]) or bool(record["reference"]), "assumption lacks evidence/reference")
            if label == "capability":
                require(set(record["assumption_ids"]) <= assumptions.keys(), "capability references unknown assumption")
                dependent = [assumptions[aid] for aid in record["assumption_ids"] if aid in assumptions]
                if record["status"] in {"established", "refuted"}:
                    require(bool(record["evidence"]), "decisive capability lacks ingress evidence")
                if record["status"] == "established":
                    require(all(a["status"] == "established" for a in dependent), "established capability relies on unresolved/refuted assumption")
                if record["deployment_dependent"]:
                    require(meta["assurance"]["deployment"]["status"] != "not_applicable", "deployment-dependent capability cannot be marked absent")
                    if record["status"] in {"established", "refuted"}:
                        allowed = {"established"} if record["status"] == "established" else {"established", "refuted"}
                        require(any(a["dimension"] == "deployment" and a["status"] in allowed for a in dependent),
                                "decisive deployment capability lacks deployment assumption")
                        require(bool(record["deployment_evidence"]), "decisive deployment capability lacks config evidence")
                    else:
                        require(meta["assurance"]["deployment"]["status"] != "assessed", "deployment assurance hides unresolved capability")
                if record["deployment_evidence"]:
                    require(meta["assurance"]["deployment"]["status"] in {"partial", "assessed"},
                            "capability config evidence conflicts with deployment assurance")
    for agent in meta["agents"]:
        require(agent["threat_model_hash"] == threat_hash, f"agent {agent['id']}: threat model differs")
    for critic in meta["coverage_reviews"]:
        require(critic["threat_model_hash"] == threat_hash, "coverage critic threat model differs")
    if meta["final_review"]["status"] in {"passed", "changes_required"}:
        require(meta["final_review"]["threat_model_hash"] == threat_hash, "final review threat model differs")
    for dimension, assurance in meta["assurance"].items():
        if assurance["status"] in {"assessed", "partial", "not_applicable"}:
            require(bool(assurance["basis"]), f"{dimension} assurance lacks basis")
        if assurance["status"] in {"not_assessed", "partial"}:
            require(bool(assurance["limitations"]), f"{dimension} assurance lacks limitations")
        for assumption in assumptions.values():
            if assumption["dimension"] == dimension:
                require(assurance["status"] != "not_applicable", f"{dimension} assurance masks relevant assumption as absent")
                if assumption["status"] in {"assumed", "unknown"}:
                    require(assurance["status"] != "assessed", f"{dimension} assurance hides unresolved assumption")
                else:
                    require(assurance["status"] in {"partial", "assessed"}, f"{dimension} assumption evidence conflicts with assurance")
    if meta["run_status"] == "complete":
        require(bool(anchors), "complete run lacks reconstructed trust anchors")
        require(meta["assurance"]["source"]["status"] == "assessed", "complete source pass lacks source assurance")

    for candidate in bundle["candidates"]:
        cid = candidate["id"]
        require(candidate["threat_model_hash"] == threat_hash, f"{cid}: threat model differs")
        require(set(candidate["assumption_ids"]) <= assumptions.keys(), f"{cid}: unknown threat assumption")
        require(bool(candidate["capability_ids"]) and set(candidate["capability_ids"]) <= capabilities.keys(),
                f"{cid}: attacker capability missing/unknown")
        for capid in candidate["capability_ids"]:
            if capid in capabilities:
                require(set(capabilities[capid]["assumption_ids"]) <= set(candidate["assumption_ids"]),
                        f"{cid}: capability hides necessary assumption")
        invariants = {candidate["primary_invariant"], *candidate["contributing_invariants"]}
        require(candidate["primary_invariant"] not in candidate["contributing_invariants"], f"{cid}: primary repeated as contributor")
        for invariant in invariants:
            require(any(uid in units and units[uid]["invariant"] == invariant for uid in candidate["unit_ids"]),
                    f"{cid}: invariant lacks linked coverage unit")
        steps = candidate["exploit_chain"]
        step_ids = {step["id"] for step in steps}
        require(len(step_ids) == len(steps), f"{cid}: duplicate chain step")
        require(not steps or len(steps) >= 2, f"{cid}: composite chain needs at least two steps")
        require(not candidate["contributing_invariants"] or bool(steps), f"{cid}: contributors lack exploit chain")
        if steps:
            require({s["invariant"] for s in steps} == invariants, f"{cid}: chain invariant set differs")
            require(any(s["invariant"] == candidate["primary_invariant"]
                        and s["root_cause"] == candidate["root_cause"]
                        and s["control"] == candidate["control"]
                        and s["boundary"] == candidate["boundary"] for s in steps),
                    f"{cid}: primary cause is absent from exploit chain")
            require(steps[0]["source"] == candidate["source"] and steps[-1]["sink"] == candidate["sink"],
                    f"{cid}: chain endpoints differ from allegation")
            for previous, current in zip(steps, steps[1:]):
                require(previous["output_state"] == current["input_state"], f"{cid}: disconnected exploit chain")
            for step in steps:
                unit = units.get(step["unit_id"])
                require(step["unit_id"] in candidate["unit_ids"] and unit is not None
                        and unit["invariant"] == step["invariant"] and unit["boundary"] == step["boundary"],
                        f"{cid}: chain step lacks matching coverage")
                locations.extend(step[k] for k in ("source", "control", "sink"))
        delegations = candidate["delegation_provenance"]
        require(len({d["id"] for d in delegations}) == len(delegations), f"{cid}: duplicate delegation edge")
        for edge in delegations:
            require(edge["unit_id"] in candidate["unit_ids"], f"{cid}: delegation lacks coverage")
            require(bool(edge["granted_scope"]) and bool(edge["effective_scope"]), f"{cid}: delegation lacks authority scope")
            locations.append(edge["grant_source"])
        for previous, current in zip(delegations, delegations[1:]):
            require(previous["to_identity"] == current["from_identity"], f"{cid}: disconnected delegation provenance")
        requirements = candidate["minimum_evidence"]
        require(len({r["id"] for r in requirements}) == len(requirements), f"{cid}: duplicate evidence requirement")
        claims = {r["claim"] for r in requirements}
        features = candidate["claim_features"]
        for claim in sorted(mandatory_claims(features) - claims):
            require(False, f"{cid}: mandatory evidence requirements missing: {claim}")
        require(features["model_mediated"] == (candidate["attacker_route"] == "model_mediated"),
                f"{cid}: model feature differs from attacker route")
        require(features["delegated"] == bool(delegations), f"{cid}: delegated feature differs from provenance")
        require(not features["human_persuasion"] or features["human_dependent"], f"{cid}: persuasion hides human dependency")
        for feature, claim in FEATURE_REQUIREMENTS.items():
            require(claim not in claims or features[feature], f"{cid}: evidence claim has disabled feature: {feature}")
        if candidate["attacker_route"] == "model_mediated":
            require("model_inducement" in claims, f"{cid}: model-mediated entry lacks inducement requirement")
        if delegations:
            require("delegation_scope" in claims, f"{cid}: delegation lacks evidence requirement")
        for step in steps:
            require(any(r["step_id"] == step["id"] and r["claim"] == "source_control" for r in requirements),
                    f"{cid}: chain step lacks evidence requirement")
        for requirement in requirements:
            require(requirement["step_id"] is None or requirement["step_id"] in step_ids, f"{cid}: requirement references unknown chain step")
            require(set(requirement["assumption_ids"]) <= set(candidate["assumption_ids"]), f"{cid}: requirement hides threat dependency")

    for finding in bundle["findings"]:
        fid = finding["id"]
        entries = {e["id"]: e for e in finding["validation"]}
        requirements = {r["id"]: r for r in finding["minimum_evidence"]}
        results = {r["requirement_id"]: r for r in finding["requirement_results"]}
        used_caps = [capabilities[cid] for cid in finding["capability_ids"] if cid in capabilities]
        necessary = [assumptions[aid] for aid in finding["assumption_ids"] if aid in assumptions] + used_caps
        refuted_dependency = any(d["status"] == "refuted" for d in necessary)
        require(not refuted_dependency or finding["confidence"] == "rejected", f"{fid}: refuted necessary dependency requires rejection")
        if finding["attacker_reachability"]["status"] == "established":
            require(all(c["status"] == "established" for c in used_caps), f"{fid}: attacker reachability uses unestablished capability")
        if any(c["status"] in {"assumed", "unknown"} for c in used_caps):
            require(finding["attacker_reachability"]["status"] == "unresolved", f"{fid}: unknown capability requires unresolved attacker reachability")
        require(len(entries) == len(finding["validation"]), f"{fid}: duplicate validation evidence ID")
        require(len(results) == len(finding["requirement_results"]) and results.keys() == requirements.keys(),
                f"{fid}: evidence requirement dispositions differ")
        allowed_proofs = requirements.keys() | {"axis:attacker", "axis:effect"}
        for entry in entries.values():
            require(bool(entry["proves"]) and set(entry["proves"]) <= allowed_proofs, f"{fid}: evidence proves unknown fact")
            locations.extend(entry["source_locations"])
            if entry["method"] in {"static_trace", "static_interleaving"}:
                require(bool(entry["source_locations"]), f"{fid}: static evidence lacks source locations")
            dimension = METHOD_DIMENSIONS[entry["method"]]
            require(meta["assurance"][dimension]["status"] in {"partial", "assessed"},
                    f"{fid}: evidence conflicts with {dimension} assurance")
        for axis, key in (("attacker", "attacker_reachability"), ("effect", "effect_reachability")):
            record = finding[key]
            selected = [entries[eid] for eid in record["evidence_ids"] if eid in entries]
            require(set(record["evidence_ids"]) <= entries.keys(), f"{fid}: {axis} reachability references unknown evidence")
            require(all("axis:" + axis in e["proves"] for e in selected), f"{fid}: evidence not bound to {axis} reachability")
            if record["status"] in {"established", "refuted"}:
                require(bool(selected) and not record["missing_facts"], f"{fid}: {axis} reachability lacks decisive evidence")
                endpoint = finding["source" if axis == "attacker" else "sink"]
                require(any(e["method"] not in {"static_trace", "static_interleaving"} or any(
                    loc["path"] == endpoint["path"] and loc["symbol"] == endpoint["symbol"]
                    for loc in e["source_locations"]) for e in selected),
                    f"{fid}: {axis} evidence omits endpoint")
            else:
                require(bool(record["missing_facts"]), f"{fid}: unresolved {axis} reachability lacks missing fact")
            if finding["confidence"] == "confirmed":
                require(record["status"] == "established", f"{fid}: confirmed lacks established {axis} reachability")
        for rid, result in results.items():
            if rid not in requirements:
                continue
            requirement = requirements[rid]
            dependencies = [assumptions[aid] for aid in requirement["assumption_ids"] if aid in assumptions]
            if requirement["claim"] == "attacker_entry":
                dependencies += used_caps
            refuted = any(d["status"] == "refuted" for d in dependencies)
            require(not refuted or result["status"] == "refuted", f"{fid}: refuted dependency requires refuted requirement")
            selected = [entries[eid] for eid in result["evidence_ids"] if eid in entries]
            require(set(result["evidence_ids"]) <= entries.keys(), f"{fid}: requirement references unknown evidence")
            require(all(rid in e["proves"] for e in selected), f"{fid}: evidence not bound to requirement")
            if result["status"] in {"satisfied", "refuted"}:
                require((bool(selected) or (result["status"] == "refuted" and refuted))
                        and not result["missing_facts"], f"{fid}: requirement lacks decisive evidence")
            else:
                require(bool(result["missing_facts"]), f"{fid}: unresolved requirement lacks missing fact")
            if result["status"] == "satisfied":
                require(all(d["status"] == "established" for d in dependencies), f"{fid}: satisfied requirement relies on unresolved assumption/capability")
                methods = {e["method"] for e in selected}
                require(all(methods & group for group in MINIMUM_METHODS[requirement["claim"]]),
                        f"{fid}: minimum evidence not met for {requirement['claim']}")
                if requirement["step_id"] is not None:
                    step = next((s for s in finding["exploit_chain"] if s["id"] == requirement["step_id"]), None)
                    if step:
                        require(any(e["method"] not in {"static_trace", "static_interleaving"} or any(
                            loc["path"] == step["control"]["path"] and loc["symbol"] == step["control"]["symbol"]
                            for loc in e["source_locations"]) for e in selected), f"{fid}: chain evidence omits control")
                for aid in requirement["assumption_ids"]:
                    if aid in assumptions:
                        require(assumptions[aid]["status"] == "established", f"{fid}: satisfied requirement relies on unresolved assumption")
            if finding["confidence"] == "confirmed":
                require(result["status"] == "satisfied", f"{fid}: confirmed has unmet evidence requirement")
        if finding["confidence"] == "confirmed":
            require(all(c["status"] == "established" for c in used_caps), f"{fid}: confirmed uses unestablished attacker capability")
            for aid in finding["assumption_ids"]:
                if aid in assumptions:
                    require(assumptions[aid]["status"] == "established", f"{fid}: confirmed depends on unresolved threat assumption")
        if finding["confidence"] == "needs_validation":
            require(any(finding[k]["status"] == "unresolved" for k in ("attacker_reachability", "effect_reachability"))
                    or any(r["status"] == "unresolved" for r in results.values())
                    or any(assumptions[aid]["status"] in {"assumed", "unknown"} for aid in finding["assumption_ids"] if aid in assumptions),
                    f"{fid}: needs-validation lacks structured unresolved fact")
        if finding["confidence"] == "rejected":
            require(any(finding[k]["status"] == "refuted" for k in ("attacker_reachability", "effect_reachability"))
                    or any(r["status"] == "refuted" for r in results.values()) or refuted_dependency,
                    f"{fid}: rejection lacks structured refutation")

    receipt = meta["host_attestation"]
    if meta["independence_level"] == "declared":
        require(receipt is None, "declared independence cannot carry host attestation")
        return
    require(meta["independence"] == "enabled" and receipt is not None, "host-attested independence lacks receipt")
    if receipt is None:
        return
    require(receipt["bundle_hash"] == attested_bundle_hash(bundle), "host attestation bundle hash differs")
    contexts = receipt["contexts"]
    require(len({c["agent_id"] for c in contexts}) == len(contexts)
            and {c["agent_id"] for c in contexts} == {a["id"] for a in meta["agents"]},
            "host attestation contexts differ from declared agents")
    require(len({c["context_id"] for c in contexts}) == len(contexts), "host attestation reuses context")
    keys = trusted_host_keys or {}
    require(receipt["key_id"] in keys, "host attestation lacks externally trusted public key")
    if receipt["key_id"] not in keys:
        return
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        require(False, "host attestation requires optional cryptography dependency")
        return
    try:
        payload = {k: v for k, v in receipt.items() if k != "signature"}
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[receipt["key_id"]])).verify(bytes.fromhex(receipt["signature"]), encoded)
    except (ValueError, TypeError):
        require(False, "invalid trusted host public key")
    except InvalidSignature:
        require(False, "host attestation signature invalid")
