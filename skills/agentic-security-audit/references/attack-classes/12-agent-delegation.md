# 12 — Agent delegation

Trace parent → child/worker authority and child → parent results. Check credential/capability narrowing, tenant propagation, task scope, approved-action binding, shared memory, queue ownership and cancellation. Inspect background work that outlives the user session or permission. Can a delegated agent mint further capabilities, return a forged approval, or persuade the parent to use broader authority?

Require authority amplification or an unintended cross-boundary effect with actual execution identity. Parent permission alone is not proof the child should inherit it; compare the intended task and resource set.

Multiple agents or a shared context are not automatically vulnerabilities. Treat returned conclusions as untrusted proposals, then inspect the parent's final admission. A subagent may legitimately need broad read scope for a requested task; demonstrate misuse rather than prescribing arbitrary capability sizes.
