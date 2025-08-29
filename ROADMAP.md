# RAG Integrity Firewall Roadmap

This roadmap outlines where the project is headed.  
It covers **open-source milestones** as well as **enterprise features** we plan to explore for organizations with stricter requirements.

---

## Open Source (Community Edition)

These features will remain free and open:

- **Core scanners**  
  - Prompt injection (regex)  
  - Secrets & API keys  
  - PII (emails, phones, SSNs)  
  - Encoded/Base64 detection  
  - URL/domain allow & deny lists  
  - Conflict/staleness detection  

- **Policy engine**  
  - Allow, deny, rerank decisions  
  - Weighting for recency, provenance, relevance  

- **Provenance**  
  - SHA256 hashing of chunks  
  - Optional SQLite store  

- **Audit logs**  
  - JSONL audit trail for each decision  

- **Integrations**  
  - LangChain retrievers (`FirewallRetriever`)  
  - LlamaIndex retrievers (`TrustyRetriever`)  

- **CLI**  
  - `ragfw index` — index and hash documents  
  - `ragfw query` — run queries with firewall checks  

---

## Short-Term Enhancements (OSS)

- Additional regex/signature patterns (prompt injection & secrets)  
- Expanded test suite and benchmarks  
- Config schema validation  
- Examples with more frameworks (Haystack, OpenAI RAG SDK)  

---

## Enterprise Features (Planned)

These are under active design and may be offered as part of a **paid Enterprise Edition**:

- **Policy Management Dashboard**  
  Web UI for managing firewall policies, roles, and configs without YAML editing.

- **Centralized Audit & Alerts**  
  Aggregated audit logs with dashboards, Slack/email/SIEM integration for high-severity findings.

- **Threat Intelligence Feeds**  
  Regular updates with new prompt injection patterns, API key formats, and risk signatures.

- **Enterprise Connectors**  
  Pre-built ingestion + firewall adapters for platforms like SharePoint, Confluence, and Google Workspace.

- **Compliance Mapping**  
  Exportable reports mapping firewall policies to frameworks such as:  
  - EU AI Act  
  - NIST AI Risk Management Framework  
  - ISO/IEC 42001  

---

## Longer-Term Ideas

- ML-based classifiers for sophisticated prompt injection patterns (optional, local-only).  
- Policy simulation mode (dry-run audits without enforcement).  
- “Red team” testing harness to evaluate RAG pipelines automatically.  
- Multi-tenant support for large organizations.  

---

## How to Contribute

- Use the [Issues](https://github.com/taladari/rag-firewall/issues) tab for bug reports and feature requests.  
- Pull requests are welcome — especially for new scanners, policy examples, or framework integrations.  
- For enterprise features, please [contact us](mailto:talbuilds0@gmail.com) if you’d like to be an early design partner.

---
