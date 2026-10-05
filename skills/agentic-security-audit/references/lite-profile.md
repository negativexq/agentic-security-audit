# Lite profile

One agent/context reviews selected domains and relevant source-to-effect paths.
Use the shared finding standard in [SKILL.md](../SKILL.md), including equivalent
controls and execution safety. Lite reduces breadth, independence and artifact
work; it does not lower the evidence needed for a security claim.

Do not initialize the v4 JSON bundle, assign five hunter roles, run coverage
critics/final reviewers or produce host attestations. Inspect source by default.
Keep revision/working-tree state, scope, inspected locations and limitations in
the report. Source may be a non-Git snapshot; disclose the identity available.

## Domain selection

Route the user's terminology through the existing [attack-class index](attack-classes/INDEX.md).
Load only classes needed for the actual question, using the valid class/invariant
pairs in that index. Domains are starting points, not mandatory coverage promises.

| Domain | Questions / natural aliases | Starting classes |
| --- | --- | --- |
| Authority | Identity, tenant/customer scope, tool authorization, protected reads/writes | 01, 02, 03 |
| Actions | Grounding, action binding, preview, confirmation, human approval | 04, 05; 19 when evidence influences a decision |
| Lifecycle | Resume, recovery, retry, idempotency, uncertain writes | 04, 05, 06, 07 as relevant |
| Context | Prompt injection, RAG/retrieval, memory, context authority | 08, 09, 10 |
| Integrations | MCP, delegation, tool metadata/poisoning | 11, 12, 15 |
| Effects | Exfiltration, secrets, filesystem/shell, network egress | 13, 14, 16, 17 |
| Resilience | Loops, budgets, cascading failures, fail-open, audit evidence | 18, 19, 20 |

“Audit MCP” selects Integrations/MCP, not every integration class. “Confirmation
+ resume” selects relevant Actions/Lifecycle paths, not every lifecycle topic.
“RAG + memory” selects Context/retrieval and memory. If no domain is stated,
derive a bounded scope from the question or feature/diff and state it. For a broad
unspecified request, identify consequential entry-to-effect paths and disclose
the selected subset; do not silently claim a full repository audit.

Follow adjacent code needed to assess the selected effect: an MCP result may
reach a worker or database handler outside the integration folder. Inspect that
control and relevant alternate callers. Report unrelated high-risk paths as an
uninspected scope limit or escalation recommendation rather than silently
expanding the review. Respect user time/token constraints; retain unfinished
paths explicitly instead of reducing evidence standards.

## Review workflow

1. **Reconstruct selected paths.** Start from consequential writes/sensitive reads;
   identify entry, attacker-controlled fields, authoritative identity/scope,
   final admission, effect and receipt. Cite path/symbol/line at the source state.
   Record necessary assumptions and unknown facts in prose.
2. **Hunt the real consequence.** Search relevant invariants on those paths. Ask
   what another user/tenant, money, protected data or system could actually lose.
   Read handler/query/transaction/provider boundaries after arguments are final.
   A schema-valid proposal, broad credential or missing mechanism is insufficient.
3. **Self-challenge every hypothesis.** Read downstream and alternate defenses:
   server-owned scope, ownership filters, signed capabilities, atomic claims,
   uniqueness/conditional writes, policy checks and provider guarantees. Try to
   defeat the claim; record why each apparent control stops it or fails on the
   alleged path. Distinguish authorized intent, same-principal self-impact and
   unintended effects. Self-challenge is not independent verification.
4. **Check evidence dependencies.** Separate attacker ingress from conditional
   effect. Do not infer public exposure from a handler, model induction from an
   invented proposal, concurrency from call order, remote outcomes from a local
   receipt, or persuasion from UI text. Use the semantic evidence rules in
   [claim-evidence.md](claim-evidence.md) when needed, without filling Standard
   JSON fields. A rigorous static interleaving can establish a bounded race;
   unknown isolation guarantees remain explicit. Refuted necessary conditions
   defeat the claim; unknown necessary conditions remain validation questions.
5. **Report and stop at scope.** Recheck cited source for drift, deduplicate by
   defective enforcement point, and produce the compact report below. Keep a
   single root cause unless multiple broken controls are jointly necessary.
   Recommend narrow fixes/regression assertions without applying target changes
   unless requested. Recommend independent verification when consequence or
   uncertainty warrants it; do not automatically start a Standard audit.

## Compact report

Chat is sufficient. If a file is requested, use `LITE-REPORT.md` in the supplied
or host-isolated output location outside the target. No new machine schema is
required. Omit empty detail sections or state none recorded; no measured security
score, PASS/FAIL or secure/insecure label.

```text
Profile: Lite
Scope: <domains, paths, exclusions>
Source: <revision / working-tree state / snapshot limits>
Independent verification: not performed

Inspected paths
- <entry → control → effect; source locations and review limits>

Potential production risks
- LITE-001: <source, boundary, broken control, effect and bounded consequence>
  Attacker access and preconditions: ...
  Counterevidence checked / why it fails: ...
  Remaining necessary facts: ...
  Narrow fix and regression assertion: ...

Unknowns requiring validation
- <source-grounded hypothesis, exact necessary missing fact, bounded check>

Containment observed
- <bounded source path, effective control, evidence and limits>

Non-finding observations
- <optional hardening/maintainability note, explicitly no demonstrated defect>

Coverage limits and next action
- <uninspected paths, tests not run, selected candidate for optional verification>
```

Use stable report-local `LITE-001` IDs for traceable hypotheses, including those
whose necessary facts remain unknown. Conditional potential risks must name the
necessary facts that would make the effect reachable and the checks needed to
establish them; do not present those facts as established. Count each hypothesis
once; cross-reference its validation gap rather than counting it as another security issue. Purely
unknown external facts without a concrete source-to-effect hypothesis are scope
limits, not potential findings. No potential risk receives Standard severity or
the `confirmed`/`needs_validation` adjudication labels. A blocked malicious
proposal can be containment evidence for its inspected path; rejected hypotheses
are not automatically proof that the broader system is contained.

## Candidate escalation

When the user asks to verify selected IDs, escalate only those hypotheses. This
is a bounded independent-verification operation, not a third audit profile or
automatic repository-wide Standard run. Use a fresh context that did not hunt
the candidate, where the host supports it and delegation is authorized. With no
independent context, disclose that verification was not performed; do not
manufacture a verifier persona or relabel self-review as confirmed.

Provide the candidate's exact allegation, source identity/locations, affected
actor/resource, preconditions, checked counterevidence and necessary unknowns.
The verifier independently reads current source, checks source drift, reconstructs
both reachability axes, challenges equivalent controls and applies Standard's
claim-dependent evidence and verdict rules. Corrected material allegations need
fresh verification. Do not ask the verifier to rubber-stamp the Lite result.

Return a compact candidate verification note with the actual verifier identity,
source state, verdict (`confirmed | needs_validation | rejected`), independent
evidence, limits, and repair/regression assertion. Severity may be assigned only
after independent confirmation under the shared impact rules. State **candidate
independently adjudicated; Standard coverage criticism and final audit review not
performed**. This prose result is not a schema-validated Standard bundle.

If the user requests Standard artifacts or an audit-wide conclusion, follow the
[Standard workflow](standard-profile.md): reconstruct source/threat bindings,
coverage and immutable candidates. Map the Lite ID to the new `CAND-...` ID and
obtain verification of the exact canonical candidate; do not reuse a prose note
as a `verified_candidate_hash` receipt. Without critics/final review the Standard
run remains incomplete, even if a particular candidate is independently confirmed.
