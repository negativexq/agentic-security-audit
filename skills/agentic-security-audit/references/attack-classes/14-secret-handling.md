# 14 — Secret handling

Inspect credentials in prompt assembly, tool metadata, MCP env/config, error objects, traces, memory, checkpoints, artifacts and client bundles. Follow secret injection, service identity, redaction, token refresh, retention and access to raw/debug output. Model-visible credentials are exposed to an untrusted semantic component; prove the route to an unauthorized reader or usable capability.

Use synthetic markers and redacted evidence. Report file/symbol and secret type without embedding a value in audit artifacts. Check whether an apparent key is a fixture or public identifier before reporting it.

The audit itself must not become a secret archive. A redaction failure needs an actual sensitive field and recipient boundary. Lack of a named secret manager alone is hardening advice, not a vulnerability.
