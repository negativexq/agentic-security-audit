# 05 — Confirmation

Do not treat the existence of confirmation as sufficient. Inspect the complete approval object and lifecycle:

- Approver identity/role and tenant/customer/conversation binding.
- Tool, resource, full normalized arguments, amount/currency, batch membership and validated preview.
- Expiry at actual use, single-effect consumption and simultaneous confirmations.
- Mutations after preview/approval, schema or registry changes and fresh approval of changed work.
- Mixed confirmation/question messages, interruption, rejection, replacement and resume.
- Live identity/policy/business-state revalidation and mutation-time preconditions.

Require the action shown/approved, the object executed and the mismatched or duplicated effect. Check receipts and final business state, not just an `approved=true` flag or number of dispatches.

Confirmation is not required for every action in every product. Establish the target's intended requirement and consequential effect. A safe signed capability, durable action record or transaction-bound token may all implement the contract.
