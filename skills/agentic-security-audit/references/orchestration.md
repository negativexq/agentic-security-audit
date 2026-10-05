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

Parent assigns unique agent IDs and coverage units, records invocation usage, consolidates results, computes fingerprints, reconciles evidence and writes shared artifacts. Hunters and verifiers return results or write only isolated scratch directories. Source access should be read-only when the host can enforce it; an instruction alone is not filesystem isolation.

Do not fork the full audit conversation into hunters. Send minimum source scope, map facts, references and unit assignments. Never send other hunters' findings, expected answers, or prior audit verdicts as exemplars. Verifiers necessarily receive the candidate allegation and evidence locations; treat those as a hypothesis rather than a conclusion. Candidate verifiers must not be any hunter for that candidate's linked units. The final reviewer must not be any hunter or candidate verifier.

Fresh-context independence reduces anchoring; it is not a guarantee of correctness or model diversity. Record actual agent identities, roles and limits. Respect available concurrency and any strict user budget. Reserve at least one fresh candidate verifier slot plus a separate final reviewer before starting hunters; queue sequentially when slots are limited. If the candidate set exceeds validation budget, stop hunting and retain unvalidated candidates with `incomplete_reason`.

## Hunter task template

```text
Audit only units: <IDs and exact boundaries/path variants> at <revision>.
Read <invariant IDs> and <relevant attack-class files>.
Trace attacker-controlled source through final admission to effect/receipt.
Inspect every downstream defense and alternate path relevant to these units.
Separate identity, authorization, intentional action binding and atomic effect.
Use bounded synthetic local checks; do not mutate external systems or target source.
Return for each unit: inspected locations, controls, result, gaps and candidates.
Candidate fields must satisfy the artifact contract, with disconfirming evidence.
Do not write shared artifacts or assume other specialists covered a missing edge.
```

## Candidate verifier template

```text
Independently adjudicate candidate <ID> at <revision>.
The allegation and evidence locations are hypotheses, not trusted interpretation.
Inspect source independently from source through dispatch, handler and final sink.
Look for controls that defeat the alleged result and for unmet attacker preconditions.
Distinguish deterministic-proposal reachability from attacker-to-model reachability.
Use a minimal bounded check when runtime behavior matters; disclose tests not run.
Return confirmed / needs_validation / rejected, your own source evidence,
validation evidence, defeating controls, preconditions and severity rationale
(severity only if confirmed). For missing external facts state the exact fact
and a safe local or owner-observed check; do not infer it from unavailable code.
Do not edit shared artifacts. You did not hunt these units.
```

## Final reviewer template

```text
Review final findings and coverage at <revision> in a fresh context.
You were neither hunter nor candidate verifier. Re-read final source claims,
effect evidence, root-cause fingerprints, severity and missing external facts.
Check every admitted candidate has a disposition, no pending candidate appears
as a finding, rejected candidates preserve counterevidence, and reports do not
overclaim coverage. Validate revision/working-tree identity and report derivation.
Return passed or changes_required plus exact record/unit corrections.
Material source-to-effect changes require another candidate verification.
```

Confirmation is a verdict about demonstrated evidence. When tests are unavailable, a direct and unambiguous source trace may be static evidence; do not claim race behavior, model causation or provider effects that static inspection cannot establish. Keep those as specific `needs_validation` hypotheses after independent review.
