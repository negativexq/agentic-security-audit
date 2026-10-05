# 18 — Resource exhaustion

Inspect distributed propagation: queue amplification, retry storms, dependency cycles, cascading fan-out, circuit-breaker state, bulkheads and recovery after partial outage. Follow budget ownership across workers and check whether redelivery, restart or fallback resets limits. Trace rejected admission through producer retries and consumers; a local limit may still amplify shared work. Use a `failure_propagation` requirement with an explicit bounded interleaving or isolated tiny fixture. Unknown deployment topology and broker/provider behavior remain separate assurance gaps; source-only reasoning does not establish production blast radius.

Trace loop bounds, recursion, agents spawning agents, fan-out, tool pagination, retries, queue depth, token/context growth, per-tenant quotas, provider spend and cancellation. Identify budget ownership and whether delegation/restart resets accounting. Examine resource reservations before dispatch and admission of background work.

Require attacker-driven amplification affecting shared availability, other tenants or authorized spend boundaries. Quantify a code-derived bound or demonstrate a tiny isolated sequence crossing a synthetic budget. Do not exhaust a live dependency.

A long answer, a user's bounded expensive request or missing optimization is not denial of service. A timeout alone may leave work running; inspect cancellation and worker limits. Different token, tool, currency and concurrency budgets are separate controls; do not treat one as covering all resources.
