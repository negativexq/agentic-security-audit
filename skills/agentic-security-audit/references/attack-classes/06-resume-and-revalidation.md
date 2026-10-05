# 06 — Resume and revalidation

Draw transitions among pending, suspended, superseded, rejected, expired, resumed, executing, committed and uncertain. Compare restart, checkpoint restoration, queued work, retries, manual recovery and delegation. Which identity is refreshed? Are policy, scope, registry, exact arguments and current business conditions checked after restoration? Can an old action revive after replacement?

Test with bounded fixtures: revoke permission, change target state, expire approval, replace workflow or alter arguments between pause and resume. For TOCTOU inspect locks, conditional writes, transactions and every competing state writer; a successful preflight alone cannot protect a later commit.

Require a stale authority/state path to an effect. Durable state is useful recovery context, not an authorization source. Revalidation requirements apply to mutable facts, not needless recomputation of immutable values.
