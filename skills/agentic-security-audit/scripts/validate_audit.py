"""Validate audit structure and accounting. This does not prove source claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

from audit_integrity import (ALLEGATION_FIELDS, ATTACK_CLASS_INVARIANTS, COVERAGE_FIELDS,
                             candidate_hash, canonical_hash, check_output, verify_source)

try:
    from jsonschema import Draft202012Validator
except ImportError:
    raise SystemExit("Install helper dependencies: python -m pip install -r <skill>/scripts/requirements.txt")

FILES = {
    "metadata": "run-metadata.json",
    "ledger": "coverage-ledger.json",
    "candidates": "candidates.json",
    "findings": "findings.json",
    "source_manifest": "source-manifest.json",
}
SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "bundle.schema.json"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"),
                      object_pairs_hook=_unique_object, parse_constant=_invalid_constant)


def load_bundle(directory: Path) -> dict:
    return {key: read_json(directory / filename) for key, filename in FILES.items()}


def fingerprint(candidate: dict) -> str:
    """Stable across line shifts and wording changes; root_cause is a stable key."""
    identity = [candidate["root_cause"], candidate["boundary"],
                candidate["sink"]["path"], candidate["sink"]["symbol"]]
    raw = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_bundle(bundle: dict) -> list[str]:
    schema = read_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    errors = []
    for error in Draft202012Validator(schema).iter_errors(bundle):
        path = ".".join(str(part) for part in error.absolute_path) or "bundle"
        errors.append(f"{path}: {error.message}")
    if errors:
        return errors  # Cross-record checks assume valid field types.

    metadata = bundle["metadata"]
    units = {unit["id"]: unit for unit in bundle["ledger"]}
    candidates = {candidate["id"]: candidate for candidate in bundle["candidates"]}
    agents = {agent["id"]: agent for agent in metadata["agents"]}
    findings = bundle["findings"]
    manifest = bundle["source_manifest"]
    snapshot = canonical_hash(manifest)

    def require(condition, message):
        if not condition:
            errors.append(message)

    require(metadata["source_manifest_hash"] == snapshot, "source manifest hash mismatch")
    require(metadata["repository"] == manifest["repository"], "source repository differs from manifest")
    require(metadata["revision"] == (manifest["git_commit"] or snapshot), "revision differs from source manifest")
    require((manifest["git_commit"] is None) == (manifest["dirty"] is None)
            == (manifest["diff_sha256"] is None), "inconsistent Git snapshot identity")
    for path in manifest["files"]:
        require(all(part not in {"..", "."} for part in path.split("/")),
                f"source manifest path escapes repository: {path}")
    for agent in agents.values():
        require(agent["source_manifest_hash"] == snapshot, f"agent {agent['id']}: source snapshot differs")

    for label, records, key in [("unit", bundle["ledger"], "id"),
                                 ("candidate", bundle["candidates"], "id"),
                                 ("agent", metadata["agents"], "id"),
                                 ("finding", findings, "id"),
                                 ("candidate fingerprint", bundle["candidates"], "fingerprint"),
                                 ("finding candidate", findings, "candidate_id")]:
        values = [record[key] for record in records]
        require(len(values) == len(set(values)), f"duplicate {label}")

    require(sum(agent["role"] == "parent" for agent in agents.values()) == 1,
            "exactly one parent must be declared")
    for agent in agents.values():
        require(set(agent["unit_ids"]) <= units.keys(), f"agent {agent['id']} has unknown units")
    for unit in units.values():
        uid = unit["id"]
        status = unit["status"]
        require(unit["invariant"] in ATTACK_CLASS_INVARIANTS[unit["attack_class"]],
                f"{uid}: attack-class/invariant mismatch")
        for hunter in unit["hunter_ids"]:
            allowed_roles = {"hunter", "parent"} if metadata["independence"] == "unavailable" else {"hunter"}
            require(hunter in agents and agents[hunter]["role"] in allowed_roles,
                    f"{uid}: undeclared/non-hunter assignment {hunter}")
            if hunter in agents:
                require(uid in agents[hunter]["unit_ids"], f"{uid}: hunter assignment not reciprocal")
        if status in {"reviewed", "candidate"}:
            require(bool(unit["evidence"]) and bool(unit["result"]), f"{uid}: review lacks evidence/result")
            require(bool(unit["hunter_ids"]), f"{uid}: review lacks hunter attribution")
        if status in {"blocked", "deferred", "not_applicable"}:
            require(bool(unit["reason"]), f"{uid}: {status} lacks reason")
        if status == "not_applicable":
            require(bool(unit["evidence"]), f"{uid}: absence lacks inspected evidence")
        if status == "candidate":
            require(bool(unit["candidate_ids"]), f"{uid}: candidate status lacks candidates")
        if unit["candidate_ids"]:
            require(status in {"candidate", "reviewed"}, f"{uid}: candidate links require candidate/reviewed status")
        for cid in unit["candidate_ids"]:
            require(cid in candidates and uid in candidates[cid]["unit_ids"], f"{uid}: broken candidate link {cid}")
    for agent in agents.values():
        if agent["role"] == "hunter":
            for uid in agent["unit_ids"]:
                if uid in units:
                    require(agent["id"] in units[uid]["hunter_ids"], f"{uid}: nonreciprocal agent assignment")

    adjudications = {finding["candidate_id"]: finding for finding in findings}
    for candidate in candidates.values():
        cid = candidate["id"]
        require(candidate["fingerprint"] == fingerprint(candidate), f"{cid}: invalid fingerprint")
        require(candidate["source_manifest_hash"] == snapshot, f"{cid}: source snapshot differs")
        require(any(uid in units and units[uid]["invariant"] == candidate["invariant"]
                    for uid in candidate["unit_ids"]), f"{cid}: invariant lacks linked coverage unit")
        require((candidate["status"] == "adjudicated") == (cid in adjudications), f"{cid}: disposition mismatch")
        for uid in candidate["unit_ids"]:
            require(uid in units and cid in units[uid]["candidate_ids"], f"{cid}: broken unit link {uid}")
            if uid in units and candidate["status"] == "pending":
                require(units[uid]["status"] == "candidate", f"{cid}: pending candidate masked as reviewed")
    for finding in findings:
        fid = finding["id"]
        candidate = candidates.get(finding["candidate_id"])
        require(candidate is not None, f"{fid}: finding has no candidate")
        if candidate:
            require(finding["fingerprint"] == candidate["fingerprint"], f"{fid}: fingerprint differs from candidate")
            require(set(finding["unit_ids"]) == set(candidate["unit_ids"]), f"{fid}: coverage links differ")
            require(finding["verified_candidate_hash"] == candidate_hash(candidate),
                    f"{fid}: verified candidate snapshot differs")
            for field in ALLEGATION_FIELDS:
                require(finding[field] == candidate[field], f"{fid}: allegation field changed: {field}")
        require(finding["source_manifest_hash"] == snapshot, f"{fid}: source snapshot differs")
        verifier = agents.get(finding["verifier_id"])
        require(verifier is not None and verifier["role"] == "verifier", f"{fid}: independent verifier absent")
        hunters = set()
        for uid in finding["unit_ids"]:
            if uid in units:
                hunters.update(units[uid]["hunter_ids"])
        require(finding["verifier_id"] not in hunters, f"{fid}: verifier was a hunter")
        if verifier:
            require(set(finding["unit_ids"]) <= set(verifier["unit_ids"]), f"{fid}: verifier scope incomplete")
        require(metadata["independence"] == "enabled", f"{fid}: finding claims unavailable independence")
        confidence = finding["confidence"]
        if confidence == "confirmed":
            for key in ["severity", "severity_rationale", "recommendation", "regression_assertion", "validation"]:
                require(bool(finding[key]), f"{fid}: confirmed lacks {key}")
            require(finding["missing_fact"] is None and finding["rejection_reason"] is None
                    and finding["validation_plan"] is None, f"{fid}: confirmed has unresolved/rejected fields")
        else:
            require(finding["severity"] is None and finding["severity_rationale"] is None,
                    f"{fid}: unconfirmed record has severity")
        if confidence == "needs_validation":
            require(bool(finding["missing_fact"]) and bool(finding["validation_plan"]), f"{fid}: missing validation fact/plan")
            require(finding["rejection_reason"] is None, f"{fid}: validation hypothesis has rejection reason")
        if confidence == "rejected":
            require(bool(finding["rejection_reason"]) and bool(finding["counterevidence"]), f"{fid}: rejected lacks counterevidence/reason")
            require(finding["missing_fact"] is None and finding["validation_plan"] is None, f"{fid}: rejection has unresolved fields")

    # Source paths are identifiers, never filesystem instructions. Prevent escapes.
    locations = [loc for unit in units.values() for loc in unit["evidence"]]
    for record in list(candidates.values()) + findings:
        locations.extend(record[field] for field in ("source", "control", "sink"))
        locations.extend(record.get("verifier_evidence", []))

    # Critics look for omitted paths, not whether existing findings are correct.
    latest_reviews = {}
    critic_invocations = set()
    for critique in metadata["coverage_reviews"]:
        stage = critique["stage"]
        latest_reviews[stage] = critique
        critic = agents.get(critique["critic_id"])
        require(critique["critic_id"] not in critic_invocations, "coverage critic invocation reused")
        critic_invocations.add(critique["critic_id"])
        require(critic is not None and critic["role"] == "coverage_critic",
                f"{stage}: coverage critique lacks independent critic")
        require(metadata["independence"] == "enabled", f"{stage}: coverage critique claims unavailable independence")
        require(critique["source_manifest_hash"] == snapshot, f"{stage}: critic source snapshot differs")
        require(critique["ledger_hash"] == canonical_hash(critique["ledger_snapshot"]),
                f"{stage}: critic ledger snapshot hash mismatch")
        locations.extend(critique["evidence"])
        seen = set()
        for prior in critique["ledger_snapshot"]:
            require(prior["id"] not in seen, f"{stage}: duplicate critic snapshot unit")
            seen.add(prior["id"])
            unit = units.get(prior["id"])
            require(unit is not None and all(unit[k] == prior[k] for k in COVERAGE_FIELDS),
                    f"{stage}: critiqued unit removed or materially changed")
            locations.extend(prior["evidence"])
            require(prior["invariant"] in ATTACK_CLASS_INVARIANTS[prior["attack_class"]],
                    f"{stage}: attack-class/invariant mismatch in critic snapshot")
        for missing in critique["missing_units"]:
            locations.extend(missing["evidence"])
            require(missing["invariant"] in ATTACK_CLASS_INVARIANTS[missing["attack_class"]],
                    f"{stage}: attack-class/invariant mismatch in missing unit")
            if missing["unit_id"] is not None:
                unit = units.get(missing["unit_id"])
                require(unit is not None and all(unit[k] == missing[k] for k in COVERAGE_FIELDS),
                        f"{stage}: missing coverage was not integrated")
            if critique["status"] == "passed" or metadata["run_status"] == "complete":
                require(missing["unit_id"] is not None, f"{stage}: passed critique has unresolved missing coverage")
    if "planning" in latest_reviews and "final" in latest_reviews:
        require(latest_reviews["planning"]["critic_id"] != latest_reviews["final"]["critic_id"],
                "planning and final coverage critics must use distinct contexts")
        require(metadata["coverage_reviews"].index(latest_reviews["planning"]) <
                metadata["coverage_reviews"].index(latest_reviews["final"]),
                "final coverage critique precedes planning critique")
    if "final" in latest_reviews:
        critique = latest_reviews["final"]
        if critique["status"] == "passed":
            require(critique["ledger_hash"] == canonical_hash(bundle["ledger"]),
                    "final coverage critique is stale; rerun after ledger changes")

    executions = {record["id"]: record for record in metadata["execution_runs"]}
    require(len(executions) == len(metadata["execution_runs"]), "duplicate execution ID")
    if metadata["execution_policy"] == "static_only":
        require(not executions, "static-only audit contains target executions")
    for execution in executions.values():
        require(execution["source_manifest_hash"] == snapshot, "execution source snapshot differs")
    for finding in findings:
        for entry in finding["validation"]:
            if entry["method"] in {"local_fixture", "existing_test"}:
                require(metadata["execution_policy"] == "sandboxed" and entry["execution_id"] in executions,
                        f"{finding['id']}: executed validation lacks sandbox record")
            else:
                require(entry["execution_id"] is None, f"{finding['id']}: non-executed evidence has execution ID")
    for loc in locations:
        raw = loc["path"]
        require(all(part not in {"..", "."} for part in raw.split("/"))
                and not PurePosixPath(raw).is_absolute(), f"source path escapes repository: {raw}")
        require(raw in manifest["files"], f"source evidence absent from snapshot: {raw}")

    budget = metadata["budget"]
    require(budget["used_invocations"] >= sum(agent["role"] != "parent" for agent in agents.values()),
            "invocation accounting omits declared agents")
    if budget["max_invocations"] is not None:
        require(budget["used_invocations"] <= budget["max_invocations"], "strict invocation budget exceeded")
    for slice_ in metadata["evidence_slices"]:
        require(slice_["passed"] <= slice_["attempted"], "evidence slice exceeds denominator")

    review = metadata["final_review"]
    reviewer = agents.get(review["reviewer_id"])
    if review["status"] in {"passed", "changes_required"}:
        require(reviewer is not None and reviewer["role"] == "reviewer", "final review lacks a distinct reviewer")
        require(bool(review["evidence"]), "final review lacks evidence")
        require(metadata["independence"] == "enabled", "final review claims unavailable independence")
        require(review["source_manifest_hash"] == snapshot, "final review source snapshot differs")
    if metadata["run_status"] == "complete":
        require(metadata["incomplete_reason"] is None, "complete run has incomplete reason")
        require(metadata["independence"] == "enabled", "complete run lacks independent review")
        require(bool(units), "complete run has no coverage units")
        require(bool(manifest["files"]), "complete run has empty source snapshot")
        if metadata["audit_mode"] == "full":
            require(any(unit["status"] == "reviewed" for unit in units.values()),
                    "complete full audit has no reviewed unit")
        for stage in ("planning", "final"):
            require(stage in latest_reviews and latest_reviews[stage]["status"] == "passed",
                    f"complete run lacks passed {stage} coverage critique")
        require(all(unit["status"] in {"reviewed", "not_applicable"} for unit in units.values()),
                "complete run has unfinished coverage")
        require(all(candidate["status"] == "adjudicated" for candidate in candidates.values()),
                "complete run has pending candidates")
        require(review["status"] == "passed", "complete run lacks passed final review")
    else:
        require(bool(metadata["incomplete_reason"]), "incomplete run lacks exact reason")
    return errors


def validate_directory(directory: Path, check_reports: bool = True, check_source: bool = True,
                       source_root: Path | None = None) -> list[str]:
    try:
        bundle = load_bundle(directory)
        errors = validate_bundle(bundle)
        if errors:
            return errors
        root = source_root or Path(bundle["metadata"]["repository"])
        check_output(root, directory, bundle["metadata"]["allow_in_target_output"])
        if check_source:
            errors.extend(verify_source(bundle["source_manifest"], root, directory))
        for name in ("architecture.md", "authority-map.md"):
            if not (directory / name).is_file() or not (directory / name).read_text(encoding="utf-8-sig").strip():
                errors.append(f"missing or empty {name}")
        if check_reports and not errors:
            from render_report import render
            for name, expected in render(bundle).items():
                path = directory / name
                if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                    errors.append(f"{name}: missing/stale; regenerate from final JSON")
        return errors
    except (OSError, ValueError) as error:
        return [str(error)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-root", type=Path, help="Relocated copy of the same frozen source")
    parser.add_argument("--offline", action="store_true", help="Structural validation only; no current-source verification")
    args = parser.parse_args()
    errors = validate_directory(args.directory, check_source=not args.offline, source_root=args.source_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Audit bundle consistent" + (" (offline; current source NOT checked)." if args.offline else "; current source matches snapshot.")
          + " Source claims, sandbox enforcement and real context isolation require independent review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
