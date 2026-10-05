"""Initialize an explicitly requested audit in a new directory; perform no hunting."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from uuid import uuid4

from audit_integrity import canonical_hash, capture_source, check_output
from render_report import render
from validate_audit import FILES, validate_bundle


def initial_bundle(repository: str, scope: list[str], working_tree: str,
                   manifest: dict | None = None, audit_mode: str = "full",
                   allow_in_target: bool = False) -> dict:
    # Pure record constructor also supports synthetic contract fixtures. CLI always
    # captures actual source; an empty synthetic manifest is not a completed audit.
    manifest = manifest if manifest is not None else {
        "schema_version": 1, "repository": repository, "git_commit": None,
        "dirty": None, "diff_sha256": None, "files": {}}
    digest = canonical_hash(manifest)
    return {
        "metadata": {
            "schema_version": 2, "run_id": f"audit-{uuid4().hex[:12]}",
            "repository": repository, "revision": manifest["git_commit"] or digest, "working_tree": working_tree,
            "source_manifest_hash": digest, "audit_mode": audit_mode,
            "allow_in_target_output": allow_in_target,
            "execution_policy": "static_only", "execution_runs": [], "coverage_reviews": [],
            "scope": scope, "exclusions": [], "run_status": "incomplete",
            "incomplete_reason": "initialized_not_reviewed", "independence": "unavailable",
            "agents": [{"id": "parent", "role": "parent", "unit_ids": [], "source_manifest_hash": digest}],
            "budget": {"max_invocations": None, "used_invocations": 0},
            "final_review": {"status": "pending", "reviewer_id": None, "evidence": [], "source_manifest_hash": None},
            "evidence_slices": [], "limitations": ["No audit pass or target tests have run."]
        },
        "ledger": [], "candidates": [], "findings": [], "source_manifest": manifest
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", help="Fresh output directory; defaults outside target")
    parser.add_argument("--repository", type=Path, required=True, help="Local source directory, not a URL")
    parser.add_argument("--revision", help="Optional expected Git commit; mismatch aborts")
    parser.add_argument("--scope", action="append", required=True)
    parser.add_argument("--working-tree", help="Optional additional source-state description")
    parser.add_argument("--audit-mode", choices=("full", "focused"), default="full")
    parser.add_argument("--allow-in-target-output", action="store_true")
    args = parser.parse_args()
    source = args.repository.absolute()
    output = args.directory or (Path.home() / "agentic-security-audit" /
                               source.name / f"run-{uuid4().hex[:12]}")
    try:
        check_output(source, output, args.allow_in_target_output)
        manifest = capture_source(source)
        revision = manifest["git_commit"] or canonical_hash(manifest)
        if args.revision and args.revision != revision:
            raise ValueError("Expected revision differs from captured source identity")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
    state = args.working_tree or ("dirty" if manifest["dirty"] else "clean" if manifest["dirty"] is False else "non-Git snapshot")
    bundle = initial_bundle(manifest["repository"], args.scope, state,
                            manifest, args.audit_mode, args.allow_in_target_output)
    errors = validate_bundle(bundle)
    if errors:
        raise SystemExit("\n".join(errors))
    # Snapshot precedes any output writes. exist_ok=False protects earlier reports.
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise SystemExit(f"Output directory already exists; choose a fresh run directory: {output}")
    for key, name in FILES.items():
        (output / name).write_text(json.dumps(bundle[key], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for name in ("architecture.md", "authority-map.md"):
        (output / name).write_text("# Not yet inspected\n\nNo architecture or authority claim has been established.\n", encoding="utf-8")
    for name, content in render(bundle).items():
        (output / name).write_text(content, encoding="utf-8", newline="\n")
    print(f"Initialized incomplete audit: {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
