# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import time
from .audit import Audit, AuditEvent
from .policies.engine import PolicyEngine
try:
    import yaml
except Exception: yaml=None

class Firewall:
    def __init__(self, scanners=None, policies=None, policy_engine=None):
        self.scanners=scanners or []
        self.policy_engine=policy_engine or PolicyEngine(policies or [])

    @classmethod
    def from_yaml(cls, path):
        with open(path,"r",encoding="utf-8") as f:
            if not yaml: raise RuntimeError("PyYAML is required to load YAML configs.")
            cfg=yaml.safe_load(f)
        scanners=[]
        from .scanners.regex_scanner import RegexInjectionScanner
        from .scanners.pii_scanner import PIIScanner
        from .scanners.secrets_scanner import SecretsScanner
        from .scanners.encoding_scanner import EncodedContentScanner
        from .scanners.url_scanner import URLScanner
        from .scanners.conflict_scanner import ConflictScanner
        for s in cfg.get("scanners",[]):
            t=s.get("type")
            if t=="regex_injection": scanners.append(RegexInjectionScanner(patterns=s.get("patterns")))
            elif t=="pii":
                if s.get("enabled", True): scanners.append(PIIScanner())
            elif t=="secrets": scanners.append(SecretsScanner(extra_patterns=s.get("extra_patterns")))
            elif t=="encoded": scanners.append(EncodedContentScanner(min_len=s.get("min_len",200), ratio_threshold=s.get("ratio_threshold",0.35)))
            elif t=="url": scanners.append(URLScanner(allowlist=s.get("allowlist"), denylist=s.get("denylist")))
            elif t=="conflict": scanners.append(ConflictScanner(stale_days=s.get("stale_days",180)))
        policies=cfg.get("policies",[])
        return cls(scanners=scanners, policies=policies)

    def scan(self, doc):
        findings=[]
        for s in self.scanners:
            try:
                res=s.scan(doc.get("page_content",""), doc.get("metadata",{}))
                if res: findings.extend(res)
            except Exception as e:
                findings.append({"scanner":"error","error":str(e)})
        return findings

    def decide(self, doc, base_score=1.0, context=None):
        context = context or {}
        findings = self.scan(doc)

        # NEW: enrich metadata with easy-to-match flags
        has_secrets = any(f.get("scanner") == "secrets" for f in findings)
        has_high_findings = any(f.get("severity") == "high" for f in findings)
        md = doc.get("metadata", {}) or {}
        md["has_secrets"] = has_secrets
        md["has_high_findings"] = has_high_findings
        doc["metadata"] = md

        decision = self.policy_engine.evaluate(doc, findings, context, base_score)

        Audit.log(AuditEvent(
            ts=time.time(),
            chunk_hash=doc.get("metadata", {}).get("hash"),
            decision=decision.get("action", "allow"),
            score=decision.get("score", base_score),
            reasons=decision.get("reasons", []),
            findings=findings,
            policy=decision.get("policy"),
        ))

        return decision, findings

    def evaluate_one(self, doc, base_score: float = 1.0, context: dict | None = None):
        dec, findings = self.decide(doc, base_score=base_score, context=context)
        md = doc.get("metadata", {}) or {}
        md["_ragfw"] = {
            "decision": dec.get("action", "allow"),
            "score": dec.get("score", 1.0),
            "reasons": dec.get("reasons", []),
            "policy": dec.get("policy"),
            "findings": findings
        }
        doc["metadata"] = md
        return doc

    def evaluate(self, docs: list[dict], base_score: float = 1.0, context: dict | None = None) -> list[dict]:
        out = []
        for d in docs:
            out.append(self.evaluate_one(d, base_score=base_score, context=context))
        return out

class _RetrieverWrapper:
    def __init__(self, retriever, firewall, provenance_store=None):
        self._inner=retriever; self.firewall=firewall; self.provenance=provenance_store

    def get_relevant_documents(self, query):
        docs = self._inner.get_relevant_documents(query)
        safe = []
        for d in docs:
            out = self.firewall.evaluate_one(d, base_score=1.0, context={"query": query})
            if out["metadata"]["_ragfw"]["decision"] == "deny":
                continue
            safe.append(out)
        safe.sort(key=lambda x: x.get("metadata", {}).get("_ragfw", {}).get("score", 1.0), reverse=True)
        return safe

def wrap_retriever(retriever, firewall, provenance_store=None):
    return _RetrieverWrapper(retriever, firewall, provenance_store)
