# Artifact contract v4

The authority map is the planning input; the ledger is the coverage record; candidates are allegations; findings are independently adjudicated dispositions. Keep all four distinct. Machine structure is defined by [bundle.schema.json](../schemas/bundle.schema.json). The validator checks schema, cross-links, coverage state, declared role independence, dispositions, budget accounting and exact report derivation, source snapshot bindings, candidate allegation integrity, attack-class/invariant routing and coverage critic accounting. It cannot attest source correctness, real context isolation or exhaustive coverage.

## Helper usage

Requires Python 3.10+ and the helper's declared `jsonschema` dependency:

```text
python -m pip install -r <skill>/scripts/requirements.txt
python <skill>/scripts/init_audit.py <new-output-dir> --repository <local-source-path> --scope <subsystem>
python <skill>/scripts/render_report.py <output-dir>
python <skill>/scripts/validate_audit.py <output-dir>
```

Use a fresh host-isolated directory outside target per run. Omit the positional directory to default to `~/agentic-security-audit/<repository-name>/run-<id>/`. In-target output requires `--allow-in-target-output`, remains excluded from the frozen file inventory, and must be inaccessible to target execution. Initialization creates an explicitly incomplete bundle and performs no audit. The parent fills JSON and the two map files, updates metadata, then renders reports. Reports are generated views; edit JSON and rerender to change findings. Pending candidates stay in `candidates.json`. Do not hand-edit reports and let them drift from the records.

Initialization captures `source-manifest.json` from a local source directory using read-only hashing and trusted host Git. It records `git_commit`, `dirty`, `diff_sha256` (canonical hash of raw tracked-file byte deltas and index deltas against HEAD) and every regular working-tree file's SHA-256/size, including ignored/untracked files. Only root `.git` administration is excluded. `dirty` includes raw tracked-byte/index differences and Git-recognized untracked paths; raw CRLF/LF differences can therefore mark a checkout dirty even when ordinary Git status reports clean. Ignored files still bind through the file inventory. The identity helper uses `rev-parse`, `ls-tree` and `ls-files`, never working-tree diff/status commands or target-defined clean/smudge filters. Non-Git sources have null Git fields; their revision is the manifest hash. Links, reparse points and special files are rejected. Prefer a frozen regular-file source snapshot and disclose its omissions.

`source_manifest_hash` is SHA-256 over project canonical JSON: sorted object keys, compact separators, UTF-8, unchanged array order, no Unicode normalization or nonfinite numbers. Use `audit_integrity.canonical_hash`. Every declared agent, candidate, finding, execution, critique and final review binds that hash. Recompute actual source before each independent pass and final review; drift requires a new run. Helpers rehash by default; `--source-root` supplies a relocated copy and `--offline` checks archived structure only. Helpers do not launch agents, run target tests or attest sandbox enforcement. Source paths must exist in the manifest; line/symbol correctness remains independently inspected.

Version 4 is intentionally incompatible with v1–v3 bundles. Reassess capability states, deployment-dependent access, explicit claim features and human claim types; do not fill defaults or retroactively upgrade confirmation. Read [claim and evidence rules](claim-evidence.md) before constructing records. Optional signed host receipts require the attestation dependency and externally pinned public keys.

## Maps

`architecture.md`: inspected subsystems/components, source locations, data stores, runtime identities, entry points, absent/unknown components and evidence limits. `authority-map.md`: actual code edges for each principal/context/proposal/admission/approval/dispatch/sink/receipt path, effective credentials, deterministic controls and alternate/recovery variants. A Mermaid graph can help, but each edge needs source evidence. Unknown edges remain visible.

## Ledger

Arrays in `coverage-ledger.json` preserve stable `AUTH-001`-style IDs. Include subsystem, boundary, path variant, attack class `01`–`20`, invariant, priority, status, hunter IDs, inspected `evidence`, `result`, `reason` and candidate links. Source locations use repository-relative forward-slash paths, positive line numbers, symbols and short summaries. Never put raw secrets in summaries. Attack-class/invariant pairs must match [INDEX.md](attack-classes/INDEX.md); the validator enforces this mapping, including critic discoveries. Each candidate invariant must have a matching linked coverage unit.

`reviewed` means an evidence-backed scoped pass was completed; it does not mean no vulnerability exists. `candidate` means a reviewed unit has an unresolved admitted allegation. After all dispositions, set it to `reviewed` and retain candidate links. `blocked`/`deferred` require reasons, `not_applicable` requires inspected absence. Unknown provider behavior is not `not_applicable`.

## Candidates and findings

Candidate `claim_features` declares all dependency flags explicitly. The validator derives required claim types; the hunter cannot lower that bar by omitting a requirement. Flags must match structured model/delegation paths and present claim types, and remain immutable in findings. Source interpretation and falsely omitted dependencies still require independent challenge. Human action binding and observed persuasion use separate claim types and evidence methods.

Candidate gate fields: `source`, `control`, `sink`, `attacker`, affected `principal`, `execution_identity`, `affected_resource`, `boundary`, `control_failure`, `impact`, `preconditions`, `counterevidence`, `primary_invariant` and linked units. Also record `contributing_invariants`, `exploit_chain`, `delegation_provenance`, `minimum_evidence`, `attacker_route`, `assumption_ids`, `capability_ids` and `threat_model_hash` according to [claim-evidence.md](claim-evidence.md). Empty chains/contributors/delegation arrays represent a single-control claim. `control` cites the defective/expected enforcement location, including a dispatcher where a check is absent. Do not fabricate a nonexistent source line.

Each candidate has a stable `root_cause` key identifying the defective control, e.g. `dispatcher.dispatch:missing-resource-authorization`. Compute `fingerprint` with `validate_audit.fingerprint(candidate)`: SHA-256 of compact UTF-8 JSON `[root_cause, boundary, control.path, control.symbol, sink.path, sink.symbol, chain_identities]`. Each ordered chain identity is `[root_cause, boundary, control.path, control.symbol, sink.path, sink.symbol]`. Normalize boundary labels deliberately; changing their spelling changes identity. Merge duplicates before assigning final IDs and preserve every unit link. Preserve separately fixable causes without counting aggregate impact twice.

Before giving a candidate to a verifier, compute `audit_integrity.candidate_hash(candidate)`: canonical SHA-256 over **all candidate fields except `status`**, including ID, unit links, title, allegation, counterevidence and source manifest hash. Status can advance from pending to adjudicated without invalidating the receipt. The verifier returns the exact `verified_candidate_hash`. Final records have `AGENT-001`-style IDs, one `candidate_id`, that hash and the same fingerprint/unit links.

All allegation fields listed in `audit_integrity.ALLEGATION_FIELDS` must equal the candidate: title, primary invariant, trace, identities, resource, boundary, failure, impact, preconditions, both snapshot hashes, contributors, chain, delegation, requirements, assumptions, capabilities and attacker route. Verifier counterevidence, disposition, reachability axes, requirement results, severity/rationale and repair fields are separate adjudication fields. Correct allegations in the candidate and obtain fresh verification rather than changing only the finding. Hashes are integrity bindings, not signatures; optional externally trusted host receipts bind the whole bundle. The final reviewer checks real receipts/contexts. Findings include the verifier's own source evidence, bounded validation entries and explicit limits. Allegation impact remains contextual for rejected records; counterevidence explains why it does not hold.

- `confirmed`: non-null severity/rationale, validation evidence, smallest effective source repair and regression assertion. Missing-fact, validation-plan and rejection fields are null.
- `needs_validation`: null severity/rationale; exact missing fact and safe local/owner check. This is an independently assessed hypothesis, not a synonym for no verifier.
- `rejected`: null severity/rationale; defeating counterevidence and rejection reason. Retain the record in the detail report but do not count it as a vulnerability.

Use `static_trace` only for behavior directly established by code; `local_fixture`/`existing_test` for checks actually executed; `owner_observation` for evidence provided by an owner. Record command/artifact reference, result and limitations. A hypothetical test plan is not executed validation. Every validation entry includes `execution_id`: null for static/owner evidence; an actual `execution_runs` ID for `local_fixture`/`existing_test`. The latter require `execution_policy: sandboxed` and a complete [execution safety record](execution-safety.md). A `static_only` run may not declare executed target validation. A record does not implement a sandbox.

Severity follows demonstrated impact: `critical` for catastrophic broad takeover/execution/data access; `high` for substantial cross-principal disclosure/mutation or defeated consequential authorization; `medium` for a narrower meaningful violation with limiting conditions; `low` for limited consequence; `informational` for a demonstrated minimal-impact observation. Do not label all cross-tenant mutations critical. Explain actor access, blast radius, preconditions and effect; never average certainty into severity.

## Metadata and completion

Reconstruct `threat-model.json` before planning and derive its Markdown view. Record source/runtime/deployment/external assurance dimensions and `independence_level: declared | host_attested` using [claim-evidence.md](claim-evidence.md). Complete requires source assessed and reconstructed trust anchors; other dimensions may remain unassessed/partial. Each agent, critique and final review binds `threat_model_hash` in addition to source identity.

`run-metadata.json` records version, run/source identity, selected scope, explicit exclusions, limitations, role assignments, invocation budget, separate evidence slices and final review. Each independent invocation gets a unique role ID; only a parent writes shared files. List actual agent IDs, not invented verifier personas. In sequential fallback use the parent ID for `hunter_ids`, set its assigned unit IDs, record independence unavailable and keep candidates pending.

Set `used_invocations` to all non-parent agent invocations, including repeats/recon/critics. Declare each coverage critic invocation under `coverage_critic` with a unique ID and source hash. Declare extra source reconstruction invocations under the appropriate actual role and disclose their purpose. The helper checks that declared agents are not omitted from the count. A strict maximum may never be exceeded silently. Five role types are a routing design, not a fixed number of calls.

Metadata `audit_mode` is `full` or `focused`. A complete full pass needs at least one **reviewed** unit; a focused pass may have only evidence-backed `not_applicable` units. Both modes need passed planning and final independent coverage criticism, a nonempty source manifest, no pending candidates, no unreviewed/blocked/deferred units, independently adjudicated findings, and a passed distinct final review binding the same source manifest. Default directory validation must also confirm current source bytes. Specific external hypotheses may remain `needs_validation` while a scoped pass is complete; the report must show the unresolved facts and limits. A blocked unreviewed path means the pass is incomplete. Narrow scope only with explicit rationale/exclusions; do not retroactively drop inconvenient units to satisfy completion.

Keep deterministic, real-model and operational denominators separate in `evidence_slices`. `passed` counts the assertions/scenarios described by its reference; it is not a percentage of system security. No fresh target tests means no claimed measured slice. Report architecture gaps, runtime facts and tests not executed under limitations.

## Coverage critique records

`coverage_reviews` preserves input snapshots and missing coverage discoveries.
Each record includes `stage: planning | final`, `status: passed | changes_required`,
`critic_id`, `source_manifest_hash`, the full input `ledger_snapshot`, its canonical
`ledger_hash`, positive source-location `evidence` and `missing_units`.

A missing-unit entry contains the five coverage axes (`subsystem`, `boundary`,
`path_variant`, `attack_class`, `invariant`), source `evidence` and `unit_id`.
`unit_id` is null until the parent integrates it into the ledger. Passing requires
all discoveries to link to matching units; old snapshot units cannot be removed
or materially changed. Preserve discoveries and stable IDs through subsequent
passes. Out-of-scope paths remain explicit in exclusions/limitations and must be
explained to the critic, not silently marked absent.

Use distinct independent agents for planning/final criticism, outside hunter,
verifier and reviewer roles. Latest planning and final critiques must pass in that
order. A passed final critique's ledger hash must match the **entire current
ledger**, including statuses and candidate links; any subsequent ledger change
requires a new final critique. Newly raised units go through hunting and candidate
adjudication before final criticism passes. No independent critic means an
incomplete run, not invented criticism under the parent ID.
