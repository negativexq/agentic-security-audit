# 03 — Identity and scope

Map token/session verification, trusted proxy headers, request-body selectors, support impersonation, conversation ownership and service identities. Follow tenant/customer scope into queries, retrieval filters, cache keys, checkpoint keys, receipts, exports and operator projections. Compare nested/bulk endpoints and recovery paths. A persisted tenant attribute is not a query predicate.

Prove who supplies the selector, which authenticated identity is effective and which other principal's resource is reachable. Inspect authorization for support operators acting on a customer; do not assume that choice is forbidden.

Identity and scope must come from authoritative authentication/authorization sources. Caller-requested scope may be safe when independently checked. Absent external identity-provider/proxy configuration is a specific evidence gap, not proof of bypass.
