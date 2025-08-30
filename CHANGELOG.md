# Changelog

## [0.4.0] - 2025-08-30
### Added
- GraphRAG support:
  - `FirewallGraph` wrapper to sanitize graph-based subgraphs (NetworkX adapter included).
  - `GraphTextSerializer` to flatten nodes/edges into LLM-friendly documents.
- Policy engine improvements:
  - List-aware matching for `findings.*` (scanner, severity, nested url.reason).
  - Policies can now cleanly deny based on scanner type or severity.
- Audit improvements:
  - `_ragfw.findings` now attached to metadata for downstream consumers.

### Fixed
- Consistent audit logs between retriever and graph paths.
- Better consistency between `decide()` and `evaluate_one()`.


## [0.3.1] - 2025-08-29
### Changed
- Added SPDX headers and NOTICE to all source files.
- No functional changes vs 0.3.0.


## [0.3.0] - 2025-08-29
### Added
- First stable release after reset
- Scanners: regex injection, PII, secrets, encoded blobs, URL/domain, conflict/staleness
- Policy engine with deny/allow/rerank actions
- Provenance store (SHA256, SQLite)
- Audit log (JSONL)
- CLI commands: `ragfw index`, `ragfw query`
- Integrations: LangChain (`FirewallRetriever`), LlamaIndex (`TrustyRetriever`)
- Examples and Quickstart guide
- CI workflows for tests, PyPI publish, Docker
- CONTRIBUTING.md, ROADMAP.md

---

## [0.2.0] - Removed
- Yanked (internal testing only, not a public release)

## [0.1.0] - Removed
- Yanked (internal testing only, not a public release)