# 05 — Confirmation

Do not treat the existence of confirmation as sufficient. Inspect the complete approval object and lifecycle:

- Approver identity/role and tenant/customer/conversation binding.
- Tool, resource, full normalized arguments, amount/currency, batch membership and validated preview.
- Expiry at actual use, single-effect consumption and simultaneous confirmations.
- Mutations after preview/approval, schema or registry changes and fresh approval of changed work.
- Mixed confirmation/question messages, interruption, rejection, replacement and resume.
- Live identity/policy/business-state revalidation and mutation-time preconditions.
- Agent-produced explanations, citations or evidence shown to the approver versus the actual pending action, recipient, arguments and effect.

Hunt the explicit pattern **agent-produced misleading evidence → human decision → privileged effect**. Check evidence provenance, authoritative previews, substituted/stale receipts and whether the operator sees the actual bound action. A false sentence alone is not a finding: identify attacker-controlled evidence, broken presentation/binding control and reachable unauthorized effect. Set `human_dependent` and require `human_action_binding` for technical mismatches. Claims of actual persuasion additionally set `human_persuasion` and require bounded `owner_observation` or `controlled_human_observation`; static trace or software tests cannot satisfy that behavioral claim.

Require the action shown/approved, the object executed and the mismatched or duplicated effect. Check receipts and final business state, not just an `approved=true` flag or number of dispatches.

Confirmation is not required for every action in every product. Establish the target's intended requirement and consequential effect. A safe signed capability, durable action record or transaction-bound token may all implement the contract.
