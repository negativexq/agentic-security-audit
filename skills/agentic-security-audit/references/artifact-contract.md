# Artifact contract v1

The authority map is the planning input; the ledger is the coverage record; candidates are allegations; findings are independently adjudicated dispositions. Keep all four distinct. Machine structure is defined by [bundle.schema.json](../schemas/bundle.schema.json). The validator checks schema, cross-links, coverage state, declared role independence, dispositions, budget accounting and exact report derivation. It cannot attest source correctness, real context isolation or exhaustive coverage.

## Helper usage

Requires Python 3.10+ and the helper's declared `jsonschema` dependency:

```text
python -m pip install -r <skill>/scripts/requirements.txt
python <skill>/scripts/init_audit.py <new-output-dir> --repository <path-or-url> --revision <commit-or-snapshot> --scope <subsystem> --working-tree <state>
python <skill>/scripts/render_report.py <output-dir>
python <skill>/scripts/validate_audit.py <output-dir>
```

Use a fresh directory per run, such as `.agentic-audit/<run-id>`. Initialization creates an explicitly incomplete bundle and performs no audit. The parent fills JSON and the two map files, updates metadata, then renders reports. Reports are generated views; edit JSON and rerender to change findings. Pending candidates stay in `candidates.json`. Do not hand-edit reports and let them drift from the records.

Record the exact source revision and any relevant dirty/untracked content identity in `working_tree`; for a dirty tree include the reviewed file hashes or an immutable snapshot reference. Recheck source identity before final review. Helpers do not inspect Git, launch agents or verify target line numbers automatically.

## Maps

`architecture.md`: inspected subsystems/components, source locations, data stores, runtime identities, entry points, absent/unknown components and evidence limits. `authority-map.md`: actual code edges for each principal/context/proposal/admission/approval/dispatch/sink/receipt path, effective credentials, deterministic controls and alternate/recovery variants. A Mermaid graph can help, but each edge needs source evidence. Unknown edges remain visible.

## Ledger

Arrays in `coverage-ledger.json` preserve stable `AUTH-001`-style IDs. Include subsystem, boundary, path variant, attack class `01`–`20`, invariant, priority, status, hunter IDs, inspected `evidence`, `result`, `reason` and candidate links. Source locations use repository-relative forward-slash paths, positive line numbers, symbols and short summaries. Never put raw secrets in summaries.

`reviewed` means an evidence-backed scoped pass was completed; it does not mean no vulnerability exists. `candidate` means a reviewed unit has an unresolved admitted allegation. After all dispositions, set it to `reviewed` and retain candidate links. `blocked`/`deferred` require reasons, `not_applicable` requires inspected absence. Unknown provider behavior is not `not_applicable`.

## Candidates and findings

Candidate gate fields: `source`, `control`, `sink`, `attacker`, affected `principal`, `execution_identity`, `affected_resource`, `boundary`, `control_failure`, `impact`, `preconditions`, `counterevidence`, invariant and linked units. `control` cites the defective/expected enforcement location, including a dispatcher where a check is absent. Do not fabricate a nonexistent source line.

Each candidate has a stable `root_cause` key identifying the defective control, e.g. `dispatcher.dispatch:missing-resource-authorization`. Compute `fingerprint` with `validate_audit.fingerprint(candidate)`: SHA-256 of the compact UTF-8 JSON array `[root_cause, boundary, sink.path, sink.symbol]`. Normalize the boundary label deliberately; changing its spelling changes identity. Merge duplicates before assigning final IDs and preserve every unit link.

Final records have `AGENT-001`-style IDs, one `candidate_id` and the same fingerprint/unit links. Findings include the verifier's own `verifier_evidence`, bounded `validation` entries and explicit limits. Allegation fields such as impact remain contextual for rejected records; counterevidence and rejection reason explain why they do not hold.

- `confirmed`: non-null severity/rationale, validation evidence, smallest effective source repair and regression assertion. Missing-fact, validation-plan and rejection fields are null.
- `needs_validation`: null severity/rationale; exact missing fact and safe local/owner check. This is an independently assessed hypothesis, not a synonym for no verifier.
- `rejected`: null severity/rationale; defeating counterevidence and rejection reason. Retain the record in the detail report but do not count it as a vulnerability.

Use `static_trace` only for behavior directly established by code; `local_fixture`/`existing_test` for checks actually executed; `owner_observation` for evidence provided by an owner. Record command/artifact reference, result and limitations. A hypothetical test plan is not executed validation.

Severity follows demonstrated impact: `critical` for catastrophic broad takeover/execution/data access; `high` for substantial cross-principal disclosure/mutation or defeated consequential authorization; `medium` for a narrower meaningful violation with limiting conditions; `low` for limited consequence; `informational` for a demonstrated minimal-impact observation. Do not label all cross-tenant mutations critical. Explain actor access, blast radius, preconditions and effect; never average certainty into severity.

## Metadata and completion

`run-metadata.json` records version, run/source identity, selected scope, explicit exclusions, limitations, role assignments, invocation budget, separate evidence slices and final review. Each independent invocation gets a unique role ID; only a parent writes shared files. List actual agent IDs, not invented verifier personas. In sequential fallback use the parent ID for `hunter_ids`, set its assigned unit IDs, record independence unavailable and keep candidates pending.

Set `used_invocations` to all non-parent agent invocations, including repeats/recon/critics; declare additional reconnaissance/critic work under the closest review role with evidence in limitations if used. The helper checks that declared agents are not omitted from the count. A strict maximum may never be exceeded silently. Five role types are a routing design, not a fixed number of calls.

A complete pass needs at least one evidence-backed unit, no pending candidates, no unreviewed/blocked/deferred units, independently adjudicated findings, and a passed distinct final review. Specific external hypotheses may remain `needs_validation` while a scoped pass is complete; the report must show the unresolved facts and limits. A blocked unreviewed path means the pass is incomplete. Narrow scope only with explicit rationale/exclusions; do not retroactively drop inconvenient units to satisfy completion.

Keep deterministic, real-model and operational denominators separate in `evidence_slices`. `passed` counts the assertions/scenarios described by its reference; it is not a percentage of system security. No fresh target tests means no claimed measured slice. Report architecture gaps, runtime facts and tests not executed under limitations.
