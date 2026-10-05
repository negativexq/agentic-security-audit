# 16 — Filesystem and shell

Trace tool fields into command executors, paths, archive extraction, imports, code runners and working directories. Inspect allowlists, structured argv, shell expansion, traversal, symlinks, canonicalization races and host mounts/credentials. Compare sandbox promises with actual permissions, including delegated and resumed jobs.

Require attacker control, failed confinement/admission and an out-of-scope read/write or command effect. Use disposable files and harmless local sentinels; avoid persistence or destructive demonstrations. Inspect final resolved path and actual process identity.

An intentionally authorized coding agent can legitimately execute commands. The defect is crossing its intended scope or letting lower-trust content substitute an unrequested command. A textual instruction to stay inside a directory is not an enforced filesystem boundary.
