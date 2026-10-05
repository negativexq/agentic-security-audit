# 07 — Idempotency and uncertain writes

Trace stable action identity from minting through retries, resume, queues and service receipts. Inspect key scope (actor/tenant/operation), payload fingerprint, same-key changed-payload rejection, concurrent conflicts, retention and atomic mutation/receipt commit. Business uniqueness and action idempotency cover different duplicate classes.

Inject a bounded commit-success/response-loss fixture. Confirm the uncertain state preserves identity and reconciles before new execution. Check checkpoint and audit failure after business commit. Read retry policy and write retry policy separately.

Require a duplicate committed effect or unsafe reachable replay, not merely repeated calls. A local database receipt does not prove a remote payment/email operation is atomic. Inspect provider idempotency and reconciliation; unknown remote guarantees remain `needs_validation` after independent review. Do not demand a particular UUID format or exactly-once mechanism when equivalent effect guarantees exist.
