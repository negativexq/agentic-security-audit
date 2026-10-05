# 17 — Network egress

Trace model/context-controlled URLs and destinations into fetch, browser, webhook, callback and service-client tools. Inspect schemes, credentials, redirects, DNS resolution/rebinding, private/link-local destinations, proxy behavior and validation-to-connect races. Follow forwarded headers and sensitive bodies.

Require an unauthorized reachable service/data destination, effective network identity and concrete read/write/disclosure effect. Prefer a bounded isolated loopback fixture or static destination-policy evidence. Never probe real metadata endpoints or unrelated services for this audit.

A URL parser is not an egress policy. A requested public fetch is not automatically SSRF. Deployment network ACLs may defeat a source hypothesis; when unavailable record the exact topology/egress fact for independent `needs_validation` rather than claiming unrestricted reach.
