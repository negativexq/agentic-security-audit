# Threat models, composite claims and evidence

These records account for what a verifier established, assumed and left unknown.
A valid bundle does not prove that interpretations or evidence descriptions are
true. Critics and verifiers must independently challenge undeclared dependencies.

## Threat model first

Populate `threat-model.json` before planning. Its scope equals the audit scope.
Trust anchors identify components, `trusted | untrusted | unknown` status,
rationale and source locations. Trust is a threat-model boundary, not a security
verdict. Cite where software relies on auth providers, operator consoles, queue
brokers or MCP peers; source defaults do not establish deployment configuration.

Assumptions have stable IDs, statements, `established | assumed | unknown |
refuted` status, `source | runtime | deployment | external` dimension, anchor
IDs, source evidence and an optional owner/document reference. Established and
refuted facts require evidence or a reference. Attacker capabilities have IDs,
descriptions, anchor IDs and ingress evidence; disclose unestablished access.
Candidates cite `capability_ids` and all necessary `assumption_ids`. Confirmation
requires every necessary assumption established. Unrelated deployment unknowns
do not invalidate a bounded source finding.

Bind `threat_model_hash` using `audit_integrity.canonical_hash`. Agents, critics,
candidates, findings and final review bind the same model. Changes require
reassessment and fresh affected receipts; recomputing hashes is not reassessment.
`threat-model.md` is derived from JSON and checked for drift.

## Two reachability axes

Findings have `attacker_reachability` and `effect_reachability`: each includes
`status: established | unresolved | refuted`, bounded claim, `evidence_ids` and
`missing_facts`. Decisive statuses require evidence and no missing facts;
unresolved status requires an exact missing fact. Confirmation requires both
axes established. Rejection requires a refuted axis or requirement.
`needs_validation` requires a structured unresolved axis, requirement or necessary
assumption, rather than an unrelated prose caveat.

`attacker_route: direct_input` means direct attacker control of the relevant
ingress. `model_mediated` requires a separate `model_inducement` requirement and
observed `real_model_sample`. Frozen owner-supplied samples record model/provider/
version, input, output, conditions, denominator and limits in reference/result/
limitations. One observed bounded route is not reliable induction across models
or a measured success rate. An arbitrary malicious proposal proves dispatch
behavior only; do not relabel that as attacker access.

Validation entries have unique IDs, method, reference, result, limitations,
`source_locations`, execution ID and `proves` fact IDs. Bind axes using
`axis:attacker` and `axis:effect`, and requirements using their IDs. One entry may
support both axes only when its actual trace establishes both; duplication is
not independence. Static axis evidence includes the corresponding source/sink.

## Formal minimum evidence

Freeze candidate `minimum_evidence`: ID, claim type, bounded description, optional
chain `step_id` and dependent `assumption_ids`. Every candidate requires
`attacker_entry` and `source_control`. Verifiers return exactly one
`requirement_results` record per requirement: `satisfied | unresolved | refuted`,
evidence IDs, rationale and missing facts. Referenced evidence must explicitly
name that requirement in `proves`. Confirmation requires every requirement
satisfied and every necessary assumption established.

| Claim | Minimum methods for satisfaction |
| --- | --- |
| `source_control` | Static trace or executed local fixture/existing test. |
| `attacker_entry` | Ingress trace, fixture/test, bounded owner observation or observed model sample. |
| `model_inducement` | Observed real-model sample; an invented proposal is insufficient. |
| `race_interleaving` | Explicit static interleaving proof or executed fixture/test. |
| `network_route` | Deployment configuration **and** source trace or executed fixture/test. |
| `remote_write_outcome` | Provider contract **and** source trace or executed fixture/test. |
| `delegation_scope` | Trace or fixture/test of grant-to-use scope. |
| `human_decision` | Trace or fixture/test of evidence, approval object and effect. |
| `failure_propagation` | Static interleaving proof or executed bounded fixture/test. |

`static_interleaving` describes competing actors, reads, state changes, checks
and commits, including defeating synchronization/isolation controls. Ordinary
call order is insufficient. Unknown scheduling/isolation guarantees leave the
requirement unresolved. A fixture does not prove all deployments behave alike.

Select requirements by actual claim: 04–07 action races/unknown outcomes; 11/17
deployment-dependent routes; 08–10/15 model inducement; 12 delegation; 05/19 human
decisions; 12/18/20 distributed propagation. A category alone does not require
runtime evidence: local store retry differs from remote provider commit.
Critics/verifiers must challenge missing requirements. The validator cannot
discover undeclared dependencies or interpret free-text claims automatically.

Executed fixtures/tests require the existing OS-enforced sandbox record.
Model samples, owner observations, deployment configurations and provider
contracts are inspected frozen/owner-provided evidence with null execution ID;
they do not authorize live requests or target execution. Do not mislabel target
execution as an owner observation. Live evidence requires separate authorization
and applicable execution controls.

## Composite exploits and delegation

Use `primary_invariant`, `contributing_invariants` and `exploit_chain`; empty
contributor/chain arrays represent a single control. A composite has at least two
ordered steps, each naming invariant, root cause, boundary, source/control/sink,
coverage unit, control failure and input/output authority states. Adjacent states
match; initial source and final sink match the allegation. Matching state labels
alone do not prove data flow: independently inspect every connecting edge.

Each step has a matching class/invariant ledger unit and source-control
requirement. Static evidence includes that step's control. The chain invariant
set equals primary plus contributors. One trace can support several steps only
when it covers each control; any unresolved necessary step blocks confirmation.
The primary root cause, control and boundary must identify an actual chain step;
an invented aggregate cause outside the chain is invalid.

Example: poisoned RAG document → delegated capability → mutable approved action
→ privileged write. Distinguish context influence, delegation failure and approval
binding failure. Keep independently fixable causes separate where useful and do
not duplicate severity by repeatedly counting the same aggregate impact.
Fingerprints include primary control and ordered chain control identities;
line/prose changes do not alter identity, different enforcement points do.

`delegation_provenance` records who delegated to whom, grant source, granted
scope, effective scope, restriction/alleged expansion and coverage unit. Use
explicit resource/capability scope atoms and record expiry, audience, cancellation
and resume conditions in restriction/evidence. An expanded effective scope can
be the defect, so it is allowed in the record. Adjacent identities match and
delegated claims require `delegation_scope`. Branches use separate path
candidates; this ordered representation is not arbitrary graph analysis.

## Assurance versus completion

Metadata `assurance.source/runtime/deployment/external` each records
`not_assessed | partial | assessed | not_applicable`, basis and limitations.
Assessed means examined within the stated scope, never secure. Partial/unassessed
dimensions need limitations; partial/assessed/not-applicable need a basis.
Unresolved assumptions prevent their dimension being assessed. Not-applicable
requires a justified absence, not lack of access. Evidence cannot inhabit an
unassessed/not-applicable dimension.

A source-complete pass needs source assessed and reconstructed trust anchors.
Other dimensions may remain partial/unassessed with `run_status=complete`.
Expose them alongside dependent findings; do not calculate a security score.

## Independence evidence

Default `independence_level: declared` preserves the role/context separation
contract, with no host receipt. `host_attested` requires an externally trusted
Ed25519 signature. Install `scripts/requirements-attestation.txt` and pass
`--trusted-host-keys /host/trusted-keys.json` to renderer/validator. The pinned
file maps key IDs to raw 32-byte public keys in lowercase hex and must resolve
outside target and audit output. Never trust keys supplied inside the bundle.

The host receipt has key ID, bundle hash, contexts for every declared agent
(agent ID, distinct context ID, isolation description), and lowercase hex
signature. `audit_claims.attested_bundle_hash` canonically hashes the entire bundle
with only host_attestation set to null. Sign canonical JSON of the receipt
excluding signature: sorted keys, compact separators, UTF-8, unchanged array
order, no NaN. Keep the host private key inaccessible to parent and target.
These helpers verify receipts; they do not launch contexts, provision keys or
issue attestations. Sign after final records and independent reviews; mutations
require a new host receipt.

Verification authenticates the trusted host's isolation claim, not semantic
isolation independently of that host. A parent-accessible signing key cannot
supply independent assurance. Missing keys/crypto, forged signatures, duplicate
contexts and changed records fail closed without falling back to declared.
