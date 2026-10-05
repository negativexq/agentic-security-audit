# 05 — Confirmation

Do not treat the existence of confirmation as sufficient. Inspect the complete approval object and lifecycle:

- Approver identity/role and tenant/customer/conversation binding.
- Tool, resource, full normalized arguments, amount/currency, batch membership and validated preview.
- Expiry at actual use, single-effect consumption and simultaneous confirmations.
- Mutations after preview/approval, schema or registry changes and fresh approval of changed work.
- Mixed confirmation/question messages, interruption, rejection, replacement and resume.
- Live identity/policy/business-state revalidation and mutation-time preconditions.
- Agent-produced explanations, citations or evidence shown to the approver versus the actual pending action, recipient, arguments and effect.

Hunt the explicit pattern **agent-produced misleading evidence → human decision → privileged effect**. Check evidence provenance, authoritative action previews, stale or substituted receipts, omitted batch members and whether the operator can inspect the actual bound action. A persuasive or false sentence alone is not a finding: identify attacker-controlled evidence, the broken presentation/binding control and a reachable unauthorized effect. Use a `human_decision` evidence requirement. Static evidence can establish a technical mismatch; claims that a human will be persuaded require bounded observed evidence and explicit limits.

Require the action shown/approved, the object executed and the mismatched or duplicated effect. Check receipts and final business state, not just an `approved=true` flag or number of dispatches.

Confirmation is not required for every action in every product. Establish the target's intended requirement and consequential effect. A safe signed capability, durable action record or transaction-bound token may all implement the contract.
