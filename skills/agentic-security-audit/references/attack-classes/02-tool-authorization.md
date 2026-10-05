# 02 — Tool authorization

Start at every sensitive read and write. Enumerate registered handlers and direct API, worker, batch and human callers. Check requesting actor/resource permission at the effective handler boundary, not just visibility in a model's tool list. Trace aliases, schema coercion, extra fields, default arguments and registry/dispatcher disagreement. Identify the credential actually used to execute.

Require an out-of-scope resource or an unrequested effect, the missing control and a complete caller-to-sink trace. A dummy second customer/tenant and final state assertion are useful minimal evidence.

An allowlisted tool can still be too powerful; a broad credential can still be safely constrained. Do not report shared credentials or direct-tool calling alone. Handler authorization and user intent binding answer different questions.
