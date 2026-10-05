# 18 — Resource exhaustion

Trace loop bounds, recursion, agents spawning agents, fan-out, tool pagination, retries, queue depth, token/context growth, per-tenant quotas, provider spend and cancellation. Identify budget ownership and whether delegation/restart resets accounting. Examine resource reservations before dispatch and admission of background work.

Require attacker-driven amplification affecting shared availability, other tenants or authorized spend boundaries. Quantify a code-derived bound or demonstrate a tiny isolated sequence crossing a synthetic budget. Do not exhaust a live dependency.

A long answer, a user's bounded expensive request or missing optimization is not denial of service. A timeout alone may leave work running; inspect cancellation and worker limits. Different token, tool, currency and concurrency budgets are separate controls; do not treat one as covering all resources.
