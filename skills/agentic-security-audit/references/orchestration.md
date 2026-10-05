# Scoped hunting and independent validation

## Five specialists

Assign actual ledger units, not whole topics without boundaries. A small repo may need fewer assignments; a large subsystem may need several waves for one specialist.

| Role | Scope | Attack-class references |
| --- | --- | --- |
| authority-hunter | Identity, tenant/customer scope, semantic compiler, grounding, policy and fail-open paths | 01, 03, 08, 20 |
| execution-hunter | Handler admission, direct APIs, typed dispatch, privileged writes, transaction/idempotency, unknown outcomes, shell/file/network sinks | 02, 07, 13, 14, 16, 17 |
| context-hunter | RAG ingestion/retrieval, memory lifecycle, provenance, cross-session caches and leakage | 09, 10, 13, 14 |
| lifecycle-hunter | Action binding, preview/confirmation, suspend/resume, replacement, checkpoint/recovery and TOCTOU | 04, 05, 06, 07 |
| integration-hunter | MCP identity/correlation, tool metadata, delegation, workers, budgets, output/telemetry and gate integrity | 11, 12, 15, 18, 19, 20 |

Overlapping classes are deliberate; assign separate concrete paths to prevent duplicate work. Prioritize privileged writes and sensitive reads, then durable context, recovery and integrations. Reconcile newly discovered boundaries between waves. Include a counterevidence pass for apparently protected paths.

## Parent ownership and context isolation

Parent assigns unique agent IDs and coverage units, records invocation usage, consolidates results, computes fingerprints, reconciles evidence and writes shared artifacts. Hunters and verifiers return results or write only isolated scratch directories. All target execution must satisfy [execution safety](execution-safety.md). Bind every result to the same source manifest hash and rehash before inspection; an instruction alone is not filesystem isolation.

Do not fork the full audit conversation into hunters. Send minimum source scope, map facts, references and unit assignments. Never send other hunters' findings, expected answers, or prior audit verdicts as exemplars. Verifiers necessarily receive the candidate allegation and evidence locations; treat those as a hypothesis rather than a conclusion. Candidate verifiers must not be any hunter for that candidate's linked units. The final reviewer must not be any hunter, candidate verifier or coverage critic. Planning and final critics use distinct fresh contexts; critics do not also hunt or verify.

Fresh-context independence reduces anchoring; it is not a guarantee of correctness or model diversity. Record actual agent identities, roles and limits. Respect available concurrency and any strict user budget. Reserve planning and final coverage critic invocations, at least one fresh candidate verifier plus a separate final reviewer before starting hunters; queue sequentially when slots are limited. If the candidate set exceeds validation budget, stop hunting and retain unvalidated candidates with `incomplete_reason`.

## Coverage critic template (planning and final)

```text
Independently inspect selected scope <scope/exclusions> at manifest <SHA-256>.
Recheck source identity before reading. This is <planning/final> criticism.
You are not a hunter, candidate verifier or final reviewer. Do not adjudicate
findings. Receive source and the input ledger snapshot/hash, not finding narratives.
Start at privileged writes and sensitive reads and reconstruct alternate callers.
Look for omitted queue/cron/background, retry/resume/recovery, direct/admin/human
paths; hidden identities, context stores, tool/MCP surfaces and unseeded relevant
attack classes. Compare source against the ledger, not only ledger rows with each
other. Return inspected source locations and missing coverage units only, with
subsystem, boundary, path variant, attack class, invariant and source evidence.
Return changes_required if gaps are unresolved. Parent integrates units and hunts
new paths; a fresh final critique must pass on the resulting current ledger.
Return source_manifest_hash and the exact input ledger_hash. Do not edit shared
artifacts. An empty missing_units list requires positive inspected source evidence.
```

Criticism is not proof of exhaustive coverage. Preserve discoveries in
`coverage_reviews`; the parent links each discovery to an actual ledger unit.
The validator prevents dropped discoveries and stale final review snapshots;
independent source inspection remains necessary to discover an unseeded boundary.

## Hunter task template

```text
Audit only units: <IDs and exact boundaries/path variants> at <revision>.
Read <invariant IDs> and <relevant attack-class files>.
Trace attacker-controlled source through final admission to effect/receipt.
Inspect every downstream defense and alternate path relevant to these units.
Separate identity, authorization, intentional action binding and atomic effect.
Recheck and return source_manifest_hash. Execute only under the full OS-enforced
execution safety contract; otherwise use static evidence. Use synthetic checks; do not mutate external systems or target source.
Recheck threat_model_hash; name necessary assumptions and attacker capabilities.
Select minimum_evidence by the actual claim, not just its attack-class label.
For composites return connected steps and coverage links; for delegation trace
who granted which scope to whom and which effective scope reached the effect.
Return for each unit: inspected locations, controls, result, gaps and candidates.
Candidate fields must satisfy the artifact contract, with disconfirming evidence.
Do not write shared artifacts or assume other specialists covered a missing edge.
```

## Candidate verifier template

```text
Independently adjudicate candidate <ID> at <manifest hash> and <candidate hash>.
Recheck source identity. Return the exact verified_candidate_hash.
Allegation fields remain immutable; propose candidate corrections for fresh verification.
The allegation and evidence locations are hypotheses, not trusted interpretation.
Inspect source independently from source through dispatch, handler and final sink.
Look for controls that defeat the alleged result and for unmet attacker preconditions.
Distinguish deterministic-proposal reachability from attacker-to-model reachability.
Return separate attacker_reachability and effect_reachability evidence axes.
Disposition every minimum_evidence requirement; independently inspect omitted
requirements and necessary assumptions, every composite edge and delegation grant.
Observed model samples prove only their stated model/conditions; direct proposals
do not establish attacker-induced model behavior. Bind threat_model_hash.
Only execute under the full OS-enforced execution safety contract; disclose tests not run.
Return confirmed / needs_validation / rejected, your own source evidence,
validation evidence, defeating controls, preconditions and severity rationale
(severity only if confirmed). For missing external facts state the exact fact
and a safe local or owner-observed check; do not infer it from unavailable code.
Do not edit shared artifacts. You did not hunt these units.
```

## Final reviewer template

```text
Review final findings and coverage at <revision> in a fresh context.
You were neither hunter, candidate verifier nor coverage critic. Re-read final source claims,
effect evidence, root-cause fingerprints, severity and missing external facts.
Check every admitted candidate has a disposition, no pending candidate appears
as a finding, rejected candidates preserve counterevidence, and reports do not
overclaim coverage. Rehash current source and bind source_manifest_hash. Check both coverage critiques
and the final ledger hash, candidate hashes, immutable allegation fields, sandbox
enforcement evidence, artifact isolation and report derivation.
Check threat_model_hash, both reachability axes, every chain requirement and
separate source/runtime/deployment/external assurance. A finished source pass
does not imply deployment/provider behavior was assessed. Independence defaults
to declared; host_attested requires an externally pinned valid host signature.
Return passed or changes_required plus exact record/unit corrections.
Material source-to-effect changes require another candidate verification.
```

Confirmation is a verdict about demonstrated evidence. When tests are unavailable, a direct and unambiguous source trace may be static evidence; do not claim race behavior, model causation or provider effects that static inspection cannot establish. Keep those as specific `needs_validation` hypotheses after independent review.
