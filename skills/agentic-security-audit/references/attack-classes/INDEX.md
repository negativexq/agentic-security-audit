# Attack-class routing

Load only classes reachable in the target. Each class defines a hunt, minimum evidence and a false-positive guard. The numbers are routing IDs used in the ledger's `attack_class` field. For all classes require an attacker-controlled source, boundary failure and meaningful effect. A question in these files is not a finding.

| ID | Class | Principal invariants |
| --- | --- | --- |
| 01 | [Model authority](01-model-authority.md) | 001, 002, 010 |
| 02 | [Tool authorization](02-tool-authorization.md) | 002, 009, 010 |
| 03 | [Identity and scope](03-identity-and-scope.md) | 001, 002 |
| 04 | [Action binding](04-action-binding.md) | 005, 011 |
| 05 | [Confirmation](05-confirmation.md) | 005, 011 |
| 06 | [Resume and revalidation](06-resume-and-revalidation.md) | 005, 006 |
| 07 | [Idempotency and uncertain writes](07-idempotency.md) | 007, 008 |
| 08 | [Prompt injection](08-prompt-injection.md) | 002, 003, 004, 011 |
| 09 | [RAG and untrusted context](09-rag-and-untrusted-context.md) | 003, 011 |
| 10 | [Memory](10-memory.md) | 004, 002 |
| 11 | [MCP](11-mcp.md) | 001, 002, 009 |
| 12 | [Agent delegation](12-agent-delegation.md) | 002, 009, 010 |
| 13 | [Data exfiltration](13-data-exfiltration.md) | 002, 009 |
| 14 | [Secret handling](14-secret-handling.md) | 002, 009, 012 |
| 15 | [Tool poisoning](15-tool-poisoning.md) | 009, 010, 011 |
| 16 | [Filesystem and shell](16-filesystem-shell.md) | 002, 009, 010 |
| 17 | [Network egress](17-network-egress.md) | 002, 009 |
| 18 | [Resource exhaustion](18-resource-exhaustion.md) | 009, 010 |
| 19 | [Observability and gate integrity](19-observability-audit.md) | 012 |
| 20 | [Fail-open behavior](20-fail-open-behavior.md) | 010 |

For standards-oriented coverage planning, consult the [OWASP Agentic Top 10 crosswalk](../owasp-agentic-crosswalk.md). It maps ASI categories to these existing guides and records partial dimensions; class/invariant pairs in this index remain authoritative for ledger validation.
