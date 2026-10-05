# Source lineage and attribution

Research snapshot: 2026-10-05. These references explain the design; they are not certifications or audit findings. The skill's invariant and orchestration text is newly written. No upstream skill text, code or license is bundled.

## Ömer Faruk Koç's writing

| Source | Design contribution |
| --- | --- |
| [Designing Guardrails for Production AI Agents](https://omerfkoc.dev/writing/production-agent-guardrails) | Distinguish semantic proposal, registry-owned policy, typed execution, transaction-time eligibility and remote effects. |
| [How I Keep Prompt Injection Away from Agent Tools](https://omerfkoc.dev/writing/agent-prompt-injection-guardrails) | Keep identity outside model context; ground material targets in the current request and retain deterministic containment even when proposals are unsafe. |
| [A Confirmation Is Not a Boolean](https://omerfkoc.dev/writing/a-confirmation-is-not-a-boolean) | Approval is bound to a persisted action; interruption, suspension, replacement and resume are separate transitions. |
| [The Write May Have Succeeded](https://omerfkoc.dev/writing/the-write-may-have-succeeded) | A transport error is not proof of rollback; reconcile uncertain effects using stable action identity. |
| [Memory Is Context, Not Authority](https://omerfkoc.dev/writing/memory-is-context-not-authority) | Review memory admission, privacy, scope, retention and downstream consumption independently of permissions. |
| [RAG Can Provide Evidence. It Cannot Grant Authority.](https://omerfkoc.dev/writing/rag-can-provide-evidence) | Retrieval and citation grounding inform answers while action authorization stays in software. |
| [Testing AI Agents Without Pretending They Are Deterministic](https://omerfkoc.dev/writing/testing-ai-agents-without-pretending-they-are-deterministic) | Separate deterministic control-plane checks, real-model semantic samples and operational fault tests; preserve denominators. |
| [Decision, Authority, Execution](https://omerfkoc.dev/writing/decision-authority-execution-observability) | Keep proposal/decision/permission/effect evidence distinct and privacy bounded. |
| [Hard Gates + Frozen Hashes](https://omerfkoc.dev/writing/hard-gates-frozen-hashes) | Evaluate outside the agent's write scope; writable baselines and gate scripts cannot independently attest integrity. |
| [The Model Wrote the SQL. It Doesn't Get to Run It.](https://omerfkoc.dev/writing/the-model-wrote-the-sql-it-doesnt-get-to-run-it) | Admission must produce the artifact the executor accepts; rewriting a proposal requires fresh admission. |

The authority and lifecycle principles also draw on selected source from [agentic-customer-service-platform](https://github.com/negativexq/agentic-customer-service-platform) at `d2523b027f8280319ba22ec2e0ae1e981c5f79a2`. The skill applies these principles across agentic applications without prescribing that project's implementation.

## Methodology inspiration

[Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill), inspected at `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`, especially `skills/security-audit/SKILL.md` and `AI-AND-LLM.md`. Its source-first mapping, coverage accounting, isolated hunting and fresh verification informed the workflow. The agentic companion already covers trust-sensitive LLM/MCP/memory/action paths. This skill specializes the entire audit in execution authority, lifecycle and committed-effect evidence; adding an AI checklist alone would not be a distinction.

MCP, delegation, shell/network and resource-budget classes extend the authority model to other targets.
