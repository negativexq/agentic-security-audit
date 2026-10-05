# OWASP Agentic Top 10 crosswalk

Taxonomy baseline: **OWASP Top 10 for Agentic Applications 2026**, ASI01–ASI10.
Category identifiers checked on **2026-10-05** against the official
[resource page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
and [release announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).
Table labels follow the **Agentic Top 10 At A Glance** overview (page 8) in the
[official 2026 document](https://genai.owasp.org/download/52117/?tmstv=1765059207).
Detailed sections and other OWASP pages sometimes expand `&` to `and` or omit
`(RCE)`; those wording variants refer to the same ASI identifiers.

The mappings and scope judgments below are this project's interpretation, not an
OWASP-issued crosswalk, endorsement or certification. They route source inspection;
they do not establish detection performance, exhaustive coverage or target safety.
No OWASP mitigation text is reproduced here.

## Read the mapping

- **Direct route:** existing hunting instructions explicitly investigate a relevant
  authority boundary. This does not mean the entire OWASP category is covered.
- **Partial route:** instructions address some relevant mechanisms, with material
  category dimensions outside the current dedicated guidance.
- Invariant suffix `002` means `AGENT-INV-002` in the [invariant library](invariants.md).
  Each ledger unit still uses one attack class and one compatible invariant from
  the [routing index](attack-classes/INDEX.md); the row's invariant list is not a
  Cartesian product of valid class/invariant pairs.

## Category routes and limits

| OWASP category | Route | Existing attack classes | Relevant invariants across listed routes | Inspect in source / coverage limit |
| --- | --- | --- | --- | --- |
| ASI01 — Agent Goal Hijack | Direct | [01 Model authority](attack-classes/01-model-authority.md), [04 Action binding](attack-classes/04-action-binding.md), [08 Prompt injection](attack-classes/08-prompt-injection.md), [09 RAG](attack-classes/09-rag-and-untrusted-context.md), [10 Memory](attack-classes/10-memory.md) | 002, 003, 004, 011 | Follow attacker-controlled instructions into a changed action, target or scope and the final effect. A changed answer or plan stopped by authoritative admission is containment evidence. |
| ASI02 — Tool Misuse & Exploitation | Direct | [02 Tool authorization](attack-classes/02-tool-authorization.md), [04 Action binding](attack-classes/04-action-binding.md), [16 Filesystem/shell](attack-classes/16-filesystem-shell.md), [17 Network egress](attack-classes/17-network-egress.md), [18 Resource exhaustion](attack-classes/18-resource-exhaustion.md) | 002, 005, 009, 010, 011 | Inspect admission and actual tool effects, including otherwise valid calls used against an unintended resource. Tool availability and valid argument shape do not establish misuse or authorization. |
| ASI03 — Identity & Privilege Abuse | Direct | [01 Model authority](attack-classes/01-model-authority.md), [03 Identity/scope](attack-classes/03-identity-and-scope.md), [11 MCP](attack-classes/11-mcp.md), [12 Delegation](attack-classes/12-agent-delegation.md), [14 Secrets](attack-classes/14-secret-handling.md) | 001, 002, 009 | Trace authenticated actor, effective credentials and resource predicates across callers and workers. Prove identity substitution or scope amplification; broad service credentials alone are insufficient. |
| ASI04 — Agentic Supply Chain Vulnerabilities | Partial | [11 MCP](attack-classes/11-mcp.md), [15 Tool poisoning](attack-classes/15-tool-poisoning.md), [16 Filesystem/shell](attack-classes/16-filesystem-shell.md) | 002, 009, 010, 011 | Existing routes cover peer/tool metadata, discovery changes and resulting capability admission. Package provenance, skills/plugins, remote instruction bundles, update channels, signer governance and artifact/version integrity lack a dedicated end-to-end supply-chain review. Do not infer coverage from class 15 alone. |
| ASI05 — Unexpected Code Execution (RCE) | Direct | [16 Filesystem/shell](attack-classes/16-filesystem-shell.md), [02 Tool authorization](attack-classes/02-tool-authorization.md), [15 Tool poisoning](attack-classes/15-tool-poisoning.md) | 002, 009, 010 | Follow attacker-derived commands, paths or executable content through allowlists, normalization, sandbox boundaries and the executed effect. An intentionally authorized code runner is not automatically a defect. The [auditor execution contract](execution-safety.md) protects the audit; it is not evidence that the target enforces equivalent isolation. |
| ASI06 — Memory & Context Poisoning | Direct | [09 RAG](attack-classes/09-rag-and-untrusted-context.md), [10 Memory](attack-classes/10-memory.md), [08 Prompt injection](attack-classes/08-prompt-injection.md) | 002, 003, 004, 011 | Inspect writers, ingestion, scope, persistence, compaction and policy consumers. Establish a poisoned-context path into authority, an unrequested action or protected data; inaccurate stored content alone fails the candidate gate. |
| ASI07 — Insecure Inter-Agent Communication | Partial | [11 MCP](attack-classes/11-mcp.md), [12 Delegation](attack-classes/12-agent-delegation.md) | 001, 002, 009, 010 | Existing routes cover peer identity, tenant propagation, request/result correlation, forged approvals and child-to-parent authority. Channel encryption, message authenticity/freshness and protocol-specific replay protection need explicit target evidence; routing checks alone do not establish those guarantees. |
| ASI08 — Cascading Failures | Partial | [12 Delegation](attack-classes/12-agent-delegation.md), [18 Resource exhaustion](attack-classes/18-resource-exhaustion.md), [20 Fail-open](attack-classes/20-fail-open-behavior.md), [07 Uncertain writes](attack-classes/07-idempotency.md) | 007, 008, 009, 010 | Follow fan-out, retries, durable execution and uncertain writes into amplified effects or exhausted shared budgets. System-wide dependency propagation, circuit-breaker behavior and coordinated recovery are not fully covered by a bounded-loop check. Runtime claims require sandboxed or owner-supplied evidence. |
| ASI09 — Human-Agent Trust Exploitation | Partial | [04 Action binding](attack-classes/04-action-binding.md), [05 Confirmation](attack-classes/05-confirmation.md), [19 Evidence integrity](attack-classes/19-observability-audit.md) | 005, 011, 012 | Compare agent-controlled explanation/evidence, authoritative preview, approved object and dispatched effect. Approval binding and misleading security evidence have direct routes; wider operator persuasion, interface interpretation and manual actions outside the inspected flow require additional product/owner evidence. |
| ASI10 — Rogue Agents | Partial | [12 Delegation](attack-classes/12-agent-delegation.md), [18 Resource exhaustion](attack-classes/18-resource-exhaustion.md), [19 Evidence integrity](attack-classes/19-observability-audit.md), [20 Fail-open](attack-classes/20-fail-open-behavior.md) | 002, 009, 010, 012 | Inspect capability containment, cancellation, continued background work and concealed effects. The skill does not measure alignment, motivation or emergent behavior. Autonomous deviation without an established attacker-controlled source and reachable boundary failure is outside its vulnerability gate; record a separate behavioral limitation instead of inventing an attacker. |

## Use during planning and coverage criticism

1. Compare the selected source scope and authority map with each category. Record
   applicable boundaries, evidence-backed absences, unknown external facts and
   explicit exclusions. A linked guide is a starting point, not a reviewed unit.
2. Seed concrete units for actual entry variants, enforcement points and sinks.
   Example: a delegated recovery worker accepting an MCP-selected tenant can need
   `attack_class: 11` with `AGENT-INV-002`, and a separate resume unit using class
   `06` with `AGENT-INV-006`. The category label does not replace those axes.
3. Give coverage critics this crosswalk as an omissions prompt, without hunter
   finding narratives. Ask them to inspect alternate callers and relevant partial
   dimensions. Add discovered units and preserve unresolved scope limits.
4. When a partial dimension is relevant but unreviewed, keep a concrete ledger
   gap blocked/deferred, or an explicitly justified exclusion. A helper-valid
   bundle or `complete` selected pass cannot establish OWASP-wide coverage.
5. Keep the existing candidate gate and independent validation. Use ASI IDs as
   contextual labels in authority-map/report prose, linked to actual unit IDs.
   The current schema has no `owasp_id` field; do not add undeclared JSON fields
   or assign a category solely because the agent used a tool.

## Beyond this taxonomy

The [claim/evidence contract](claim-evidence.md) records composite paths, delegated
grant provenance, human-decision and distributed-propagation requirements, and
separate assurance dimensions. These improve evidence accounting within existing
routes; they do not turn the partial categories into end-to-end coverage. Supply
chain remains partial without a dedicated provenance/update-governance audit.

Approval expiry, resume revalidation, stable action identity and unknown-write
reconciliation remain explicit native audit concerns even when several ASI
categories overlap them. Preserve these lifecycle units instead of replacing
them with one generic category check. This crosswalk adds no attack class,
invariant, benchmark result or independent assurance claim.
