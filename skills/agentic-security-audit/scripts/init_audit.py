"""Initialize an explicitly requested audit in a new directory; perform no hunting."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

from render_report import render
from validate_audit import FILES, validate_bundle


def initial_bundle(repository: str, revision: str, scope: list[str], working_tree: str) -> dict:
    return {
        "metadata": {
            "schema_version": 1, "run_id": f"audit-{uuid4().hex[:12]}",
            "repository": repository, "revision": revision, "working_tree": working_tree,
            "scope": scope, "exclusions": [], "run_status": "incomplete",
            "incomplete_reason": "initialized_not_reviewed", "independence": "unavailable",
            "agents": [{"id": "parent", "role": "parent", "unit_ids": []}],
            "budget": {"max_invocations": None, "used_invocations": 0},
            "final_review": {"status": "pending", "reviewer_id": None, "evidence": []},
            "evidence_slices": [], "limitations": ["No audit pass or target tests have run."]
        },
        "ledger": [], "candidates": [], "findings": []
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--scope", action="append", required=True)
    parser.add_argument("--working-tree", default="not yet inspected")
    args = parser.parse_args()
    bundle = initial_bundle(args.repository, args.revision, args.scope, args.working_tree)
    errors = validate_bundle(bundle)
    if errors:
        raise SystemExit("\n".join(errors))
    # exist_ok=False protects earlier reports; no target repository operations.
    try:
        args.directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise SystemExit(f"Output directory already exists; choose a fresh run directory: {args.directory}")
    for key, name in FILES.items():
        (args.directory / name).write_text(json.dumps(bundle[key], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for name in ("architecture.md", "authority-map.md"):
        (args.directory / name).write_text("# Not yet inspected\n\nNo architecture or authority claim has been established.\n", encoding="utf-8")
    for name, content in render(bundle).items():
        (args.directory / name).write_text(content, encoding="utf-8", newline="\n")
    print(f"Initialized incomplete audit: {args.directory.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
