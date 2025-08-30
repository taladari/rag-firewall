# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import time
from rag_firewall.policies.engine import PolicyEngine

def _doc(ts=None):
    return {"page_content": "x", "metadata": {"timestamp": ts or time.time()}}

def test_policy_matches_findings_scanner_any():
    findings = [
        {"scanner": "pii", "match": "email", "severity": "medium"},
        {"scanner": "secrets", "match": "aws_access_key", "severity": "high"},
    ]
    pe = PolicyEngine([
        {"name": "deny_secrets", "match": {"findings.scanner": "secrets"}, "action": "deny"},
        {"name": "allow_default", "action": "allow"},
    ])
    dec = pe.evaluate(_doc(), findings, context={}, base_score=1.0)
    assert dec["action"] == "deny"
    assert dec["policy"] == "deny_secrets"

def test_policy_matches_findings_severity_any():
    findings = [
        {"scanner": "regex_injection", "match": "Ignore previous instructions", "severity": "high"},
    ]
    pe = PolicyEngine([
        {"name": "deny_high", "match": {"findings.severity": "high"}, "action": "deny"},
        {"name": "allow_default", "action": "allow"},
    ])
    dec = pe.evaluate(_doc(), findings, context={}, base_score=1.0)
    assert dec["action"] == "deny"
    assert dec["policy"] == "deny_high"

def test_policy_matches_nested_findings_url_reason():
    findings = [
        {"scanner": "url", "match": "evil.example.com", "severity": "high", "url": {"reason": "denylist_domain"}},
    ]
    pe = PolicyEngine([
        {"name": "block_denylisted_urls", "match": {"findings.url.reason": "denylist_domain"}, "action": "deny"},
        {"name": "allow_default", "action": "allow"},
    ])
    dec = pe.evaluate(_doc(), findings, context={}, base_score=1.0)
    assert dec["action"] == "deny"
    assert dec["policy"] == "block_denylisted_urls"

def test_policy_allow_when_no_match():
    findings = [{"scanner": "pii", "match": "email", "severity": "medium"}]
    pe = PolicyEngine([
        {"name": "deny_secrets", "match": {"findings.scanner": "secrets"}, "action": "deny"},
        {"name": "allow_default", "action": "allow"},
    ])
    dec = pe.evaluate(_doc(), findings, context={}, base_score=1.0)
    assert dec["action"] == "allow"
    assert dec["policy"] == "allow_default"

def test_rerank_weights_applied_and_no_deny():
    # No high findings -> expect rerank to adjust score, not deny
    findings = []
    base_score = 0.5
    pe = PolicyEngine([
        {"name": "prefer_recent", "action": "rerank", "weight": {"recency": 0.6, "relevance": 0.4}},
        {"name": "allow_default", "action": "allow"},
    ])
    dec = pe.evaluate(_doc(), findings, context={}, base_score=base_score)
    assert dec["action"] in ("allow", "rerank")
    assert "policy:prefer_recent:rerank" in dec["reasons"]