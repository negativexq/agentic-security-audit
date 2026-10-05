# 15 — Tool poisoning

Trace tool discovery, descriptions, schemas, prompts, completion metadata and updates. Identify which peers may supply or change them. Compare registered identity and fixed capabilities with advertised behavior. Look for metadata-driven risk downgrade, approval suppression, shadowed tools, widened argument domains or credential selection.

Require maliciously controllable metadata, the client decision that trusts it and a resulting unauthorized/unrequested action or disclosure. A benign local schema swap can test whether admission remains authoritative after discovery drift.

Tool text influencing model preference is not itself an authority violation. Signed metadata also requires a trusted signer and change-control boundary; signatures alone do not make tool instructions policy. Analyze implementation-specific registry admission and pinned identity rather than assuming descriptions are executable.
