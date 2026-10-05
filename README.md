# agentic-security-audit — AI Agent Security Audit Skill

**A coverage-led security audit skill for tracing where untrusted agent context becomes real execution authority.**

Audit tool-using agents, RAG and memory pipelines, MCP integrations, approval workflows, delegated tasks and durable execution paths. Follow actual source code from an attacker-controlled input to a privileged effect, then independently verify the finding.

The skill is agent- and model-independent. Use it with any agent that can inspect repository files and follow Markdown instructions. It has no vendor-specific SDK, agent API or required installation path.

## Project at a glance

| Question | Answer |
| --- | --- |
| What is it? | An agent-independent security audit skill for agentic applications. |
| What does it trace? | Untrusted context becoming execution authority and a real system effect. |
| What does it cover? | AI agent security, tool authorization, MCP security, RAG and memory poisoning, approval binding, resume and replay safety. |
| How is it organized? | 12 invariants, 20 attack classes and 5 specialist hunter roles. |
| What does it produce? | Source-backed authority maps, a coverage ledger, adjudicated findings and generated reports. |
| What runs the audit? | Your chosen repository-reading agent; separate contexts are required for independent verification. |
| What do the helpers require? | Python 3.10+ and `jsonschema`. |

## Documentation navigation

- [What it investigates](#what-it-investigates)
- [Quick start](#quick-start)
- [Installation and portability](#installation-and-portability)
- [Audit workflow](#audit-workflow)
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

An unsafe proposal stopped by deterministic software is containment evidence. A model-quality warning and an unauthorized committed effect are different outcomes.

## Quick start

Make the skill folder and target repository available to your chosen agent, then give it these instructions:

```text
Read skills/agentic-security-audit/SKILL.md and follow its audit workflow
for this agentic application. Load supporting references as directed.
Map its authority boundaries, maintain a coverage ledger, and produce
independently verified findings with source evidence and a final report.
```

For a narrower review:

```text
Read skills/agentic-security-audit/SKILL.md and review confirmation
and resume safety in this application.
Focus on exact action binding, expiry, argument changes and revalidation.
```

A focused review uses the relevant guidance without automatically starting a full audit or creating a report bundle.

## Installation and portability

Keep the entire [`skills/agentic-security-audit`](skills/agentic-security-audit) folder together so its references, schemas and scripts resolve through relative paths.

1. Place the folder in a location your agent can read, such as the target workspace or a shared instructions directory.
2. Ask the agent to read [`SKILL.md`](skills/agentic-security-audit/SKILL.md) and load supporting references as directed.
3. Provide the target repository and specify the desired scope, exclusions and budget.

If your agent supports native skill discovery, register this folder using that environment's own convention. Native registration is optional; direct loading of the instructions works without a product-specific command or directory layout. Adjust the paths in the usage examples to where you placed the folder.

The package supplies instructions and artifact helpers. The host executes the investigation and provides agent isolation. Independent hunters, verifiers and the final reviewer require actual separate agent contexts. When these are unavailable, the skill supports sequential investigation, preserves pending candidates and reports the full audit as `incomplete`.

## Audit workflow

| Phase | Work | Evidence produced |
| --- | --- | --- |
| Reconnaissance | Map principals, credentials, context sources, tools, stores, approvals and alternate execution paths. | Architecture and source-backed authority map. |
| Coverage planning | Assign units by subsystem, boundary/path variant, attack class and invariant. | Coverage ledger with explicit scope and gaps. |
| Scoped hunting | Search assigned paths for invariant violations and defeating controls. | Structured candidates and inspected-unit evidence. |
| Candidate gate | Require a complete source-to-effect hypothesis and deduplicate root causes. | Admitted candidates linked to coverage units. |
| Independent validation | Fresh verifiers prove, qualify or reject each candidate. | Adjudicated findings with validation and counterevidence. |
| Final review and reporting | A distinct reviewer checks records and coverage; derive reports from JSON and validate the bundle. | Consistent machine-readable and human-readable output. |

Five [specialist hunter roles](skills/agentic-security-audit/references/orchestration.md) divide the investigation:

| Hunter | Focus |
| --- | --- |
| Authority | Identity, scope, grounding, compiler and policy. |
| Execution | Tool admission, writes, idempotency and privileged sinks. |
| Context | RAG, memory, provenance and context leakage. |
| Lifecycle | Approval binding, interruption, resume, recovery and revalidation. |
| Integration | MCP, delegation, tool metadata, budgets and evidence integrity. |

Hunters receive scoped assignments without other hunters' finding narratives. Only the parent writes shared artifacts. A candidate verifier must not have hunted the candidate; the final reviewer is distinct from both. Roles run in waves within the host's concurrency and the user's budget.

## Outputs and finding states

Full audits produce:

| Artifact | Purpose |
| --- | --- |
| `architecture.md` | Components, entry points, identities, stores and visibility limits. |
| `authority-map.md` | Source-backed paths from context and principal to admission, dispatch and effect. |
| `coverage-ledger.json` | What was inspected, outstanding units, evidence and candidate links. |
| `candidates.json` | Admitted allegations, root-cause fingerprints and adjudication status. |
| `findings.json` | Independently adjudicated records, including rejected hypotheses. |
| `run-metadata.json` | Source revision, scope, exclusions, agent roles, budget, review status and evidence slices. |
| `REPORT.md` | Run status, coverage, findings, gaps and limitations. |
| `FINDINGS-DETAIL.md` | Source/control/sink traces, verifier evidence and repair guidance. |

| Disposition | Meaning | Severity |
| --- | --- | --- |
| `confirmed` | The boundary failure and meaningful effect are established under stated conditions. | Assigned from demonstrated impact. |
| `needs_validation` | An independently assessed hypothesis depends on an exact unresolved external/runtime fact. | Not assigned. |
| `rejected` | Evidence defeats the alleged boundary failure or impact. | Not assigned. |

Pending candidates stay outside `findings.json`. Missing an independent verifier makes the audit incomplete; it does not convert an allegation into a `needs_validation` finding.

`complete` means the selected pass finished: coverage units have evidence-backed dispositions, candidates are adjudicated, final independent review passed and bundle validation succeeds. It does not imply exhaustive coverage or certify the target as secure. Partial runs retain their evidence and exact incomplete reason.

## Artifact helpers

The Python helpers require **Python 3.10+** and `jsonschema`. Install the dependency from the repository root:

```shell
python -m pip install -r skills/agentic-security-audit/scripts/requirements.txt
```

Create a fresh output directory for an explicitly requested audit:

```shell
python skills/agentic-security-audit/scripts/init_audit.py .agentic-audit/run-001 --repository ./target-repo --revision REVIEWED_COMMIT --scope agent-runtime --working-tree clean
```

Replace the repository, revision, scope and working-tree values with the actual reviewed source identity. Initialization creates an incomplete bundle; it does not inspect the target or launch agents. The auditing agent fills the maps and records.

After updating the JSON artifacts, regenerate and validate the reports:

```shell
python skills/agentic-security-audit/scripts/render_report.py .agentic-audit/run-001
python skills/agentic-security-audit/scripts/validate_audit.py .agentic-audit/run-001
```

The validator checks schema, cross-links, coverage states, declared role independence, finding dispositions, invocation accounting and report consistency. It cannot prove source claims or actual context isolation. Read the [artifact contract](skills/agentic-security-audit/references/artifact-contract.md) for record fields and evidence requirements.

## Frequently asked questions

### What is agentic-security-audit?

agentic-security-audit is a reusable security audit skill for AI agent applications. It guides a repository-reading agent through authority mapping, coverage-led hunting, independent validation and structured reporting.

### How do I audit an AI agent application with this skill?

Give your agent the skill folder and target repository, ask it to read `skills/agentic-security-audit/SKILL.md`, and define the audit scope. For a full pass, provide separate contexts for hunters, candidate verifiers and a final reviewer. Python helpers initialize and validate artifacts; they do not perform the investigation.

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

The investigation can proceed through sequential scoped passes. Candidates stay pending, independence is recorded as unavailable, and the full audit remains incomplete until independent adjudication and final review are performed.

### Does a complete audit mean the application is secure?

No. Completion means the selected pass satisfied its coverage, adjudication, review and artifact requirements. It does not certify exhaustive coverage, resolve unobserved deployment facts or guarantee the absence of vulnerabilities.

### Where can I find the machine-readable project description?

The [project metadata](metadata/project.jsonld) describes the package using Schema.org `SoftwareSourceCode`. The [documentation index](llms.txt) links to the source instructions and references. Publication settings and the distinction between repository files and deployed website metadata are in the [discovery guide](docs/DISCOVERY.md).

## Development checks

After installing the helper dependency:

```shell
python -m unittest discover -s tests -v
```

The tests exercise incomplete-run handling, candidate/verifier separation, coverage accounting, deduplication, severity rules, source-path constraints and JSON/report consistency with synthetic fixtures. They do not measure vulnerability-detection performance or prove an agent follows the workflow.

## Scope and evidence limits

Audits use source inspection and bounded local checks with synthetic data. Target fixes and external mutations require separate scope. Unavailable deployment, identity-provider and external-service behavior remains explicit rather than assumed.

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
