import time
def _get(meta, dotted, default=None):
    cur=meta
    for p in dotted.split('.'):
        if not isinstance(cur, dict): return default
        cur = cur.get(p, default)
    return cur
def _recency_score(ts, half_life_days=30.0):
    if not ts: return 1.0
    age_days=max(0.0,(time.time()-float(ts))/86400.0)
    return 1.0/(1.0+(age_days/half_life_days))
class PolicyEngine:
    def __init__(self, policies): self.policies = policies or []
    def evaluate(self, doc, findings, context, base_score=1.0):
        meta = doc.get("metadata",{}); reasons=[]; score=base_score; action="allow"; policy_name=None
        if any(f.get("scanner") in ("regex_injection","secrets") and f.get("severity") in ("high","critical") for f in findings):
            action="deny"; reasons.append("scanner:auto-deny")
        for p in self.policies:
            m=p.get("match",{}); matched=True
            for k,v in m.items():
                if _get({"metadata":meta,"context":context}, k, None)!=v: matched=False; break
            if not matched: continue
            policy_name=p.get("name"); act=p.get("action","allow")
            if act=="deny":
                action="deny"; reasons.append(f"policy:{policy_name}"); break
            elif act=="rerank":
                w=p.get("weight",{})
                recency=_recency_score(meta.get("timestamp"))
                provenance=1.0 if meta.get("source") else 0.8
                relevance=base_score
                penalty=0.0
                if any(f.get("scanner") in ("encoded","url") and f.get("severity")=="high" for f in findings): penalty+=0.2
                if any(f.get("scanner") in ("conflict",) for f in findings): penalty+=0.1
                score=max(0.0,(w.get("recency",0.0)*recency + w.get("provenance",0.0)*provenance + w.get("relevance",1.0)*relevance)-penalty)
                reasons.append(f"policy:{policy_name}:rerank")
            elif act=="allow":
                action="allow"; reasons.append(f"policy:{policy_name}:allow")
        return {"action":action,"score":score,"reasons":reasons,"policy":policy_name}
