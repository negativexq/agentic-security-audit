# 13 — Data exfiltration

Map protected reads to all outbound destinations: response text, tool/API args, URLs, email, webhooks, auto-loaded Markdown images, exports, logs and telemetry. Identify who controls the destination and which credential reads the data. Check tenant filters and redaction after transformations, not just at initial retrieval.

Require a protected datum, an actor not permitted to receive it, a reachable destination and the missing enforcement point. Use synthetic canaries in an isolated receiver or inspect deterministic output; do not send real secrets externally.

Data a user intentionally exports under their own permitted authority is not exfiltration. Renderer auto-load or external API behavior outside source needs a specific validation fact. Generic instruction disclosure alone is not secret leakage.
