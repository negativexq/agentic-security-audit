# agentic-security-audit — AI Agent Security Audit Skill

**A coverage-led security audit skill for tracing where untrusted agent context becomes real execution authority.**

Review tool-using agents, RAG and memory pipelines, MCP integrations, approval workflows and durable execution. Use Lite for focused developer reviews and Standard for independent release/security audits. Follow source from realistic attacker control to a meaningful effect and accept equivalent controls that stop it.

The skill is agent- and model-independent. Use it with any agent that can inspect repository files and follow Markdown instructions. It has no vendor-specific SDK, agent API or required installation path.

## Project at a glance

| Question | Answer |
| --- | --- |
| What is it? | An agent-independent security audit skill for agentic applications. |
| What does it trace? | Untrusted context becoming execution authority and a real system effect. |
| What does it cover? | AI agent security, tool authorization, MCP security, RAG and memory poisoning, approval binding, resume and replay safety. |
| How is it organized? | 12 invariants, 20 attack classes and 5 specialist hunter roles. |
| What does it produce? | Lite: compact scoped review. Standard: authority maps, coverage ledger, independently adjudicated records and reports. |
| What runs the audit? | Your chosen repository-reading agent; separate contexts are required for independent verification. |
| What do the helpers require? | Python 3.10+ and `jsonschema`. |

## Documentation navigation

- [What it investigates](#what-it-investigates)
- [Profiles and finding philosophy](#profiles-and-finding-philosophy)
- [Quick start](#quick-start)
- [Installation and portability](#installation-and-portability)
- [Audit workflow](#audit-workflow)
- [OWASP Agentic Top 10 mapping](#owasp-agentic-top-10-mapping)
- [Outputs and finding states](#outputs-and-finding-states)
- [Artifact helpers](#artifact-helpers)
- [Frequently asked questions](#frequently-asked-questions)
- [Development checks](#development-checks)
- [Scope and evidence limits](#scope-and-evidence-limits)
- [Related writing](#related-writing)

Detailed references: [security invariants](skills/agentic-security-audit/references/invariants.md), [attack-class index](skills/agentic-security-audit/references/attack-classes/INDEX.md), [hunter and verifier orchestration](skills/agentic-security-audit/references/orchestration.md), and [artifact contract](skills/agentic-security-audit/references/artifact-contract.md).

The central model is:

```text
context → proposal → decision → authority → execution → effect → evidence
```

## What it investigates

A model can propose a valid-looking action while the application still needs to establish identity, resource scope, intentional action binding and current business eligibility. These are separate controls.

The skill organizes those questions into [12 security invariants](skills/agentic-security-audit/references/invariants.md) and [20 attack classes](skills/agentic-security-audit/references/attack-classes/INDEX.md), including:

- Model-controlled identity, authorization scope and tool dispatch.
- Approval of an exact action, argument changes and confirmation bypass.
- Suspend/resume, restart recovery, stale authority and check-to-write races.
- Stable action identity, concurrent writes and unknown write outcomes.
- RAG and memory poisoning that reaches permissions or protected data.
- MCP identity, tool metadata, delegation and capability amplification.
- Data exfiltration, secrets, filesystem/shell access and network egress.
- Resource budgets, fail-open branches and audit-evidence integrity.

Prompt injection alone does not qualify as a vulnerability. A candidate needs:

```text
attacker-controlled source
  + crossed trust boundary
  + missing or broken authoritative control
  + reachable security effect
```

An unsafe proposal stopped by verified deterministic enforcement is containment evidence for the inspected path. A model-quality warning and an unauthorized committed effect are different outcomes.

## Profiles and finding philosophy

**Find production-relevant failures, accept equivalent controls, and spend audit cost proportional to requested scope and assurance.** Missing best practices, broad-but-contained credentials, unusual architectures and unknown external facts are not vulnerabilities by themselves. Require a realistic source, crossed boundary, broken authoritative control and reachable effect with a meaningful consequence. Recommend the smallest effective fix at the actual enforcement point.

| | Lite | Standard |
| --- | --- | --- |
| Use | Quick, PR, feature or domain review | Full, independent, release or pre-production audit |
| Contexts | One, including a self-challenge pass | Scoped hunters, independent critics/verifiers and final reviewer |
| Scope | Selected domains and necessary adjacent paths | Focused or full selected scope |
| Output | Chat or `LITE-REPORT.md` | Existing schema v4 artifact bundle |
| Risk label | Potential production risk; no severity | Independently adjudicated; severity only if confirmed |
| Evidence | Same source-to-effect standard, explicit necessary unknowns | Same standard plus independent verification and artifact accounting |

Choose the smallest profile that answers the question without overstating confidence. Lite does not initialize a Standard bundle or launch independent roles. Explicit Standard requests retain their completion gates even when independence is unavailable. Profile selection adds no JSON fields, attack classes or invariants.

Lite routes **Authority, Actions, Lifecycle, Context, Integrations, Effects and Resilience** to existing guides. Users can say “audit MCP”, “RAG + memory” or “confirmation + resume”; class numbers are not required. Follow relevant downstream controls even when they live outside the selected domain's folder. Read [Lite workflow/domain routing](skills/agentic-security-audit/references/lite-profile.md) or [Standard workflow](skills/agentic-security-audit/references/standard-profile.md).

Deployment evidence is required only when the claim depends on actual exposure/topology. An LLM on a path does not require induction evidence when direct attacker control is deterministically preserved. Technical approval-object mismatches do not require human persuasion experiments. Single root cause is the default; composite chains are for jointly necessary broken controls.

## Quick start

Make the skill folder and target repository available to your chosen agent. For a focused review:

```text
Read skills/agentic-security-audit/SKILL.md. Use Lite to review confirmation
and resume safety in this application. Trace relevant paths, challenge each
hypothesis against equivalent controls, and give a compact scoped report.
```

For an independent release review:

```text
Read skills/agentic-security-audit/SKILL.md. Perform a Standard release
security audit of this application within the agreed scope and budget.
Produce the v4 bundle with independent coverage criticism, candidate
verification and final review.
```

To escalate one Lite hypothesis:

```text
Independently verify only LITE-001. Re-read source and challenge its
attacker-to-effect trace. Return the candidate verdict and evidence;
do not start a repository-wide Standard audit.
```

A fresh context must actually be available and authorized. This returns a bounded candidate verification note, not a completed Standard audit or a schema-validated bundle. Standard artifacts require canonical source/threat/candidate bindings and fresh verification of that exact record. See [candidate escalation](skills/agentic-security-audit/references/lite-profile.md#candidate-escalation).

## Installation and portability

Keep the entire [`skills/agentic-security-audit`](skills/agentic-security-audit) folder together so its references, schemas and scripts resolve through relative paths.

1. Place the folder in a location your agent can read, such as the target workspace or a shared instructions directory.
2. Ask the agent to read [`SKILL.md`](skills/agentic-security-audit/SKILL.md) and load supporting references as directed.
3. Provide the target repository and specify the desired scope, exclusions and budget.

If your agent supports native skill discovery, register this folder using that environment's own convention. Native registration is optional; direct loading of the instructions works without a product-specific command or directory layout. Adjust the paths in the usage examples to where you placed the folder.

The package supplies instructions and artifact helpers. The host executes the investigation and provides agent isolation. Independent hunters, verifiers, coverage critics and the final reviewer require actual separate agent contexts. When these are unavailable, the skill supports sequential investigation, preserves pending candidates and reports the full audit as `incomplete`.

## Audit workflow

Lite follows **selected domain → source-to-effect reconnaissance → hunt → counterevidence/self-challenge → compact report**. It records inspected paths, potential production risks, necessary unknowns, containment observed, optional non-finding observations and narrow fixes. Self-review is disclosed and never relabeled independent confirmation.

The following workflow and specialist roles apply to **Standard**. The v4 schema and validation gates remain its contract.

| Phase | Work | Evidence produced |
| --- | --- | --- |
| Reconnaissance | Map principals, credentials, context sources, tools, stores, approvals and alternate execution paths. | Architecture and source-backed authority map. |
| Coverage planning and criticism | Assign units by subsystem, boundary/path variant, attack class and invariant; a fresh critic searches source for omitted paths. | Ledger, input snapshot and missing-unit records. |
| Scoped hunting | Search assigned paths for invariant violations and defeating controls. | Structured candidates and inspected-unit evidence. |
| Candidate gate | Require a complete source-to-effect hypothesis and deduplicate root causes. | Admitted candidates linked to coverage units. |
| Independent validation | Fresh verifiers prove, qualify or reject each candidate. | Adjudicated findings with validation and counterevidence. |
| Final coverage criticism, review and reporting | A second critic searches for omissions; a distinct reviewer checks final records. Rehash source, derive reports and validate. | Current-ledger critique and consistent output. |

Five [specialist hunter roles](skills/agentic-security-audit/references/orchestration.md) divide the investigation:

| Hunter | Focus |
| --- | --- |
| Authority | Identity, scope, grounding, compiler and policy. |
| Execution | Tool admission, writes, idempotency and privileged sinks. |
| Context | RAG, memory, provenance and context leakage. |
| Lifecycle | Approval binding, interruption, resume, recovery and revalidation. |
| Integration | MCP, delegation, tool metadata, budgets and evidence integrity. |

Hunters receive scoped assignments without other hunters' finding narratives. Only the parent writes shared artifacts. Planning and final coverage critics use distinct fresh contexts and return omitted units without finding narratives. A candidate verifier must not have hunted the candidate; the final reviewer is distinct from hunters, verifiers and critics. Roles run in waves within the host's concurrency and the user's budget.

## OWASP Agentic Top 10 mapping

The [2026 crosswalk](skills/agentic-security-audit/references/owasp-agentic-crosswalk.md) maps ASI01–ASI10 to existing attack classes and invariants. It distinguishes direct hunting routes from partial scope and gives coverage critics concrete questions about omitted boundaries.

Supply chain, communication guarantees, cascading failures, human trust and rogue-agent behavior have explicit limits in the mapping. This is a project-authored interpretation of [OWASP’s taxonomy](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/); it does not claim OWASP endorsement, full category coverage or compliance. The source-to-effect candidate gate and lifecycle invariants still govern findings.

## Outputs and finding states

Standard audits produce:

| Artifact | Purpose |
| --- | --- |
| `architecture.md` | Components, entry points, identities, stores and visibility limits. |
| `authority-map.md` | Source-backed paths from context and principal to admission, dispatch and effect. |
| `coverage-ledger.json` | What was inspected, outstanding units, evidence and candidate links. |
| `candidates.json` | Admitted allegations, root-cause fingerprints and adjudication status. |
| `findings.json` | Independently adjudicated records, including rejected hypotheses. |
| `source-manifest.json` | Frozen Git/working-tree identity and SHA-256/size of source files. |
| `threat-model.json` / `threat-model.md` | Trust anchors, attacker capabilities, assumptions and unknowns; Markdown is derived. |
| `run-metadata.json` | Source revision, scope, exclusions, agent roles, budget, review status and evidence slices. |
| `REPORT.md` | Run status, coverage, findings, gaps and limitations. |
| `FINDINGS-DETAIL.md` | Source/control/sink traces, verifier evidence and repair guidance. |

| Disposition | Meaning | Severity |
| --- | --- | --- |
| `confirmed` | The boundary failure and meaningful effect are established under stated conditions. | Assigned from demonstrated impact. |
| `needs_validation` | An independently assessed hypothesis depends on an exact unresolved external/runtime fact. | Not assigned. |
| `rejected` | Evidence defeats the alleged boundary failure or impact. | Not assigned. |

Pending candidates stay outside `findings.json`. Missing an independent verifier makes the audit incomplete; it does not convert an allegation into a `needs_validation` finding.

Lite uses potential-risk descriptions without these Standard verdict/severity labels. Unknown facts alone are coverage limits; a concrete source hypothesis with a necessary missing fact is a validation question. `needs_validation` in Standard likewise does not mean the product failed its security audit.

Lite reports can include **Containment observed** and **Non-finding observations** directly. Standard may supply optional **Verified containment** and **Non-finding observations** in chat or `REVIEW-NOTES.md`, clearly labeled supplemental and outside the canonical/host-attested bundle. Cite bounded control evidence and source/ledger references. Do not append free text to generated `REPORT.md` or treat every rejected hypothesis as containment. Hardening notes receive no vulnerability severity.

`complete` means the selected pass finished: coverage units have evidence-backed dispositions, both independent coverage critiques passed, candidates are adjudicated, final independent review passed and current-source bundle validation succeeds. A full audit requires at least one reviewed unit. It does not imply exhaustive coverage or certify the target as secure. Partial runs retain their evidence and exact incomplete reason.

## Artifact helpers

These helpers serve Standard bundles. Lite source reviews require no Python, JSON initialization or full report artifacts.

The Python helpers require **Python 3.10+** and `jsonschema`. Install the dependency from the repository root:

```shell
python -m pip install -r skills/agentic-security-audit/scripts/requirements.txt
```

Create a fresh output directory for an explicitly requested audit:

```shell
python skills/agentic-security-audit/scripts/init_audit.py --repository ./target-repo --scope agent-runtime
```

Provide a local target repository and scope. Initialization reads and hashes source files and captures Git identity without running target code; it creates an incomplete bundle and launches no agents. It prints the fresh output path, defaulting to `~/agentic-security-audit/<repo>/run-<id>/` outside the target. Use that printed path below. `--revision` can assert an exact expected commit. In-target output requires explicit `--allow-in-target-output` and exclusion from target execution mounts. The auditing agent fills the maps and records.

After updating the JSON artifacts, regenerate and validate the reports:

```shell
python skills/agentic-security-audit/scripts/render_report.py AUDIT_OUTPUT
python skills/agentic-security-audit/scripts/validate_audit.py AUDIT_OUTPUT
```

Artifact schema v4 binds source and threat models, separates attacker/effect reachability, and accounts for composite chains, delegation provenance and capability status. Required `claim_features` deterministically derive evidence requirements. Deployment-dependent access needs established assumptions and configuration evidence; refuted necessary dependencies require rejection. Human action binding and observed persuasion have separate evidence bars. Older v1–v3 confirmations need reassessment rather than default-filled migration. The validator checks structure and declared dependency semantics; independent reviewers must still challenge falsely omitted features and incorrect source interpretations. Read the [artifact contract](skills/agentic-security-audit/references/artifact-contract.md) and [claim/evidence rules](skills/agentic-security-audit/references/claim-evidence.md).

`assurance.source/runtime/deployment/external` records each dimension separately; `complete` can describe a finished source pass with unassessed deployment/provider behavior. Confirmation requires both reachability axes established, all necessary chain requirements satisfied and necessary assumptions established. Model-mediated entry needs observed model-inducement evidence; a direct proposal is insufficient.

Independence defaults to `declared`. Hosts can optionally provide Ed25519-signed bundle/context receipts verified with externally pinned public keys. Install `scripts/requirements-attestation.txt` from the skill folder and supply `--trusted-host-keys /host/trusted-keys.json` to both helpers. This verifies the trusted host's attestation; the package does not launch isolated agents, generate signing keys or establish isolation beyond the host's guarantees.

## Frequently asked questions

### What is agentic-security-audit?

agentic-security-audit is a reusable security audit skill for AI agent applications. It guides a repository-reading agent through authority mapping, coverage-led hunting, independent validation and structured reporting.

### How do I audit an AI agent application with this skill?

Give your agent the skill folder and repository, ask it to read `skills/agentic-security-audit/SKILL.md`, and state scope/assurance. Specific developer reviews use Lite; explicit full, independent or release audits use Standard. For Standard provide separate contexts for critics, hunters, candidate verifiers and final review. Python helpers account for Standard artifacts; they do not investigate source.

### Does it require a particular agent or model?

No. The instructions are Markdown, the artifact schema is JSON Schema, and the optional helpers are Python. Your chosen agent needs repository access and instruction-following capabilities. Independent verification requires genuinely separate contexts.

### Is this a scanner or an audit methodology?

It is an audit methodology packaged as a skill, supported by artifact-validation and report-generation tools. It does not automatically scan source code or launch agents when a Python helper runs.

### What makes prompt injection a security finding?

A finding requires attacker-controlled input, a crossed trust boundary, a broken authoritative control and a reachable security effect. Persuasive text or an unsafe model proposal alone is insufficient when deterministic software prevents the effect.

### Does it cover MCP, RAG and agent memory security?

Yes. The attack classes cover MCP identity and request correlation, tool metadata, delegated capabilities, retrieval scope and provenance, memory admission and authority-bearing use. Each class must be tied to an actual target path and effect.

### How are confirmation and resume safety checked?

The audit compares the exact action shown or approved with the object executed, including actor, scope, tool, resource and material arguments. It also examines expiry, replacement, concurrent consumption, resumed authorization, current business state and the final mutation boundary.

### What happens when independent agents are unavailable?

Lite works in a single context and explicitly discloses self-review. A requested Standard audit can proceed through sequential investigation, but candidates remain pending and the audit stays incomplete until independent criticism, adjudication and final review are performed. A request to verify a Lite candidate cannot claim independence when no fresh verifier exists.

### Does a complete audit mean the application is secure?

No. Completion means the selected pass satisfied its coverage, adjudication, review and artifact requirements. It does not certify exhaustive coverage, resolve unobserved deployment facts or guarantee the absence of vulnerabilities.

### Where can I find the machine-readable project description?

The [project metadata](metadata/project.jsonld) describes the package using Schema.org `SoftwareSourceCode`. The [documentation index](llms.txt) links to the source instructions and references.

## Development checks

After installing the helper dependency:

```shell
python -m unittest discover -s tests -v
```

The tests exercise incomplete-run handling, candidate/verifier separation, coverage accounting, deduplication, severity rules, source-path constraints and JSON/report consistency with synthetic fixtures. They do not measure vulnerability-detection performance or prove an agent follows the workflow.

## Scope and evidence limits

Target-controlled execution requires an OS-enforced sandbox: no network, credential mounts or inherited secret environment; read-only source, isolated scratch writes, inaccessible audit artifacts, finite resource limits, offline dependencies and synthetic data. If the host cannot enforce every requirement, use static evidence and record exact unresolved runtime facts. Helpers record this contract; they do not create a sandbox. See [execution safety](skills/agentic-security-audit/references/execution-safety.md). Target fixes and external mutations require separate scope. Unavailable deployment, identity-provider and external-service behavior remains explicit rather than assumed.

Deterministic control-plane tests, real-model samples and operational fault tests retain separate denominators. Reports do not turn those measurements into a synthetic security score.

## Related writing

- [Designing Guardrails for Production AI Agents](https://omerfkoc.dev/writing/production-agent-guardrails)
- [How I Keep Prompt Injection Away from Agent Tools](https://omerfkoc.dev/writing/agent-prompt-injection-guardrails)
- [A Confirmation Is Not a Boolean](https://omerfkoc.dev/writing/a-confirmation-is-not-a-boolean)
- [The Write May Have Succeeded](https://omerfkoc.dev/writing/the-write-may-have-succeeded)
- [Memory Is Context, Not Authority](https://omerfkoc.dev/writing/memory-is-context-not-authority)
- [RAG Can Provide Evidence. It Cannot Grant Authority.](https://omerfkoc.dev/writing/rag-can-provide-evidence)
- [Testing AI Agents Without Pretending They Are Deterministic](https://omerfkoc.dev/writing/testing-ai-agents-without-pretending-they-are-deterministic)
- [Decision, Authority, Execution](https://omerfkoc.dev/writing/decision-authority-execution-observability)
- [Hard Gates + Frozen Hashes](https://omerfkoc.dev/writing/hard-gates-frozen-hashes)

## License

Copyright 2026 Ömer Faruk Koç. Licensed under [Apache-2.0](LICENSE).
