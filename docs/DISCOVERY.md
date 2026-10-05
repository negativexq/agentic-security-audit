# Discovery and publication

This project uses a clear definition, task-oriented headings, direct FAQ answers, linked source references and machine-readable package metadata. These structures support readers and tools consuming the documentation. They do not guarantee search rankings, indexing or citations in generated answers.

## Repository metadata

Use these values when publishing the repository. They are prepared settings, not changes already applied to a remote service.

**Repository name:** `agentic-security-audit`

**Short description:**

```text
Agent-independent AI agent security audit skill for execution authority, MCP, RAG, memory, approvals and replay safety, with coverage-led independent verification.
```

**Suggested topics:**

```text
ai-security
agentic-security
ai-agents
security-audit
agent-skills
llm-security
prompt-injection
mcp-security
rag-security
tool-authorization
trust-boundaries
human-in-the-loop
idempotency
```

Use topics that reflect the project's actual scope. GitHub's [topics documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics) describes how admins add them to repository settings. A local topics list does not set remote repository metadata.

## Public documentation structure

The [README](../README.md) provides the primary project definition, entry points and visible FAQ. The [audit instructions](../skills/agentic-security-audit/SKILL.md) define behavior. [Invariants](../skills/agentic-security-audit/references/invariants.md), [attack classes](../skills/agentic-security-audit/references/attack-classes/INDEX.md) and the [artifact contract](../skills/agentic-security-audit/references/artifact-contract.md) support specific claims with inspectable detail.

Keep the same project name and core description across repository settings and published documentation. Preserve links to the detailed sources and distinguish demonstrated capabilities from expected visibility. Do not publish invented benchmarks, adoption figures, ratings, endorsements or vulnerability counts.

## Machine-readable files

[`metadata/project.jsonld`](../metadata/project.jsonld) uses Schema.org [`SoftwareSourceCode`](https://schema.org/SoftwareSourceCode) to describe the instruction package and Python helpers. It contains no guessed publication URL, repository URL, license or release version. Add `url`, `codeRepository` and an absolute `@id` once the corresponding public addresses are known; add other properties only when established.

On a documentation website, embed that JSON as an `application/ld+json` script on a page whose visible content describes the same project. A JSON-LD file committed to a repository is a reusable metadata source; it is not automatically embedded into the repository's rendered README or a website. The markup describes the package and does not establish eligibility for a particular search feature.

[`llms.txt`](../llms.txt) is a compact documentation index for consumers that use the [llms.txt proposal](https://llmstxt.org/). It points to existing files instead of duplicating the complete skill. The relative links work as repository navigation; when publishing a website, preserve those routes or replace them with real public Markdown/documentation URLs. It is not a crawling permission file or an authorization source.

Google's [generative AI search guide](https://developers.google.com/search/docs/fundamentals/ai-optimization-guide) states that ordinary search fundamentals remain relevant and that special AI text files or special schema are not required for its AI search features. In particular, `llms.txt` is not a Google ranking mechanism. Its role here is optional documentation navigation.

## Website metadata when a public site exists

Recommended page title:

```text
agentic-security-audit | AI Agent Security Audit Skill
```

Recommended meta description:

```text
Audit AI agent execution authority, MCP, RAG, memory, approvals and replay safety with an agent-independent skill and independently verified findings.
```

Use the actual public page for its canonical URL and Open Graph URL. Match the Open Graph title and description to the visible page. Add a social preview image only when an image has been created and published at a real URL.

Serve important project content as readable page text with working navigation. Generate a sitemap from real public pages and place crawler policies at the website origin. Repository-local `robots.txt`, HTML meta tags in Markdown and guessed sitemap URLs do not configure a hosted repository's crawling or page head. No canonical tag, sitemap or robots policy is emitted by this package before a website URL and publishing setup exist.

## Answer-oriented content

The README's visible FAQ answers practical questions about purpose, installation, platform independence, prompt injection, MCP/RAG/memory coverage, confirmation/resume and incomplete audits. Keep answers consistent with `SKILL.md` and the artifact contract. Update them when behavior changes.

Use explicit terminology: a candidate is an allegation, a confirmed finding is an independently established boundary failure, and a complete run is a completed selected pass. This lets readers quote the project without confusing artifact-validation tests with detection-performance benchmarks.

## Measure after publication

Track the published pages that are indexed, search queries that lead to them, visits to documentation and citations where the platform reports them. Compare results over time without attributing every change to a single metadata file.

For a website you control, use its search-console and webmaster reports. Bing's [AI Performance documentation](https://www.bing.com/webmasters/help/ai-performance-9f8e7d6c) describes citation and grounding-query reporting for supported experiences. Repository owners cannot configure the hosting platform's origin-level webmaster settings through files in this package.
