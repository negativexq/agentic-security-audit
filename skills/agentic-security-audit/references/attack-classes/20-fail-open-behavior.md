# 20 — Fail-open behavior

Trace partial-outage authority fallbacks across dependencies: unavailable identity/policy service, stale cache, queue redelivery, recovery worker, alternate MCP peer and circuit-breaker reset. Identify who selects fallback credentials/scope and whether degraded availability expands authority. Use `failure_propagation` for claims requiring a distributed sequence and bind unknown broker/provider/deployment assumptions explicitly. Never exercise a live outage to establish the path.

Enumerate errors and defaults at parsing, grounding, auth, scope lookup, policy, registry, confirmation persistence, revalidation, tool calls and recovery. Compare deterministic and live-model providers, compatibility adapters, fallback clients and human paths. Does timeout/unknown/error become allow? Is escalation treated as approval? Does missing context inherit a broad default tenant?

Require a reachable failure/default branch, the security decision it bypasses and a sensitive effect. Use bounded injected exceptions or missing-field fixtures; assert no dispatch or no committed effect as appropriate.

A fallback producing a harmless answer is not fail-open authorization. An unavailable post-commit audit sink cannot undo a committed effect; classify uncertainty and prevent unsafe replay instead of pretending rollback occurred. Unknown outcomes and explicit denial are different states.
