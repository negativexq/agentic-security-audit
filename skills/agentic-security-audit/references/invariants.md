# Agentic invariant library

These are contracts to investigate, not a universal architecture prescription. Bind each invariant to a concrete target behavior and enforcement point. A failed design preference is not automatically a vulnerability. Missing evidence is not evidence of missing enforcement.

| ID | Security contract | Hunt at / evidence needed |
| --- | --- | --- |
| AGENT-INV-001 | Probabilistic output must not establish authenticated identity. | Principal construction, token verification, request context, checkpoint reload; prove which actor reaches a protected handler. |
| AGENT-INV-002 | Probabilistic output must not expand authorization scope. | Tenant/customer selectors, resource resolution, handler and query predicates, credential audience; prove an out-of-scope read/write. |
| AGENT-INV-003 | Retrieved content must not grant capabilities. | Ingestion → retrieval → proposal → admission; an attacker-writable source must reach a forbidden or unrequested effect, or private context. |
| AGENT-INV-004 | Memory must not establish execution authority. | All writers, summaries, merge/compaction, retrieval, policy consumers; trace durable low-trust data into a permission decision or cross-principal read. |
| AGENT-INV-005 | Required approval must bind the exact pending action. | Validated action shown to approver versus object dispatched: actor, tenant, conversation, tool, normalized arguments, target, amount/currency, batch, expiry and single effect. Approval of changed work requires a fresh decision. |
| AGENT-INV-006 | Resumed execution must revalidate mutable authority and business state. | Resume, restart, queue, retry, cached policy; revocation, expiry, supersession, registry changes and final write preconditions. Check for a race after revalidation. |
| AGENT-INV-007 | Privileged writes must have stable action identity and replay-safe effects. | Identity minting, key scope, payload fingerprint, atomic mutation/receipt, unique constraints, concurrent invocation; a second committed effect is stronger evidence than a second dispatch. |
| AGENT-INV-008 | Unknown write outcomes must not be blindly replayed. | Commit succeeded/response lost, provider timeout, checkpoint failure after commit; preserve identity, distinguish uncertainty and reconcile before replay. A new identity must not disguise a retry. |
| AGENT-INV-009 | Delegated tool access must stay within intended least authority. | MCP credentials, worker context, subagent capabilities, shell/files/network permissions; prove authority amplification or unbound use, not broad credentials alone. |
| AGENT-INV-010 | Failed or unknown security decisions must not grant execution. | Parse/schema errors, unknown tools, exceptions, timeouts, absent scope, fallback and human escalation; enumerate reachable deny-to-allow branches. |
| AGENT-INV-011 | Action targets and material arguments must bind to authenticated intent or a valid approved object. | Current request, deterministic target resolution, argument provenance and preview; grounding is separate from ownership. Server-resolved symbolic targets can be safe where product semantics explicitly permit them. |
| AGENT-INV-012 | Audit evidence must distinguish proposal, decision, authority and committed effect without becoming authority. | Durable receipts, replay, operator projections, logs and protected acceptance gates; demonstrate misleading security evidence, evidence tampering or disclosure with real impact. Missing dashboards alone are observations. |

The first ten express the initial authority model; 011 adds intent grounding and 012 adds evidence integrity. Risk categories, approval TTLs, accepted phrases and tool names are application-specific decisions. Stateless reads need no pending-action state machine; idempotent effects may be enforced through several sound mechanisms.

For effects outside the local database, a local receipt cannot prove remote atomicity or exactly-once delivery. Inspect the provider's idempotency retention, request binding, correlation and reconciliation contract. Mark unobserved guarantees explicitly.
