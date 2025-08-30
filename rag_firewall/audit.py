# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import json, os, time
from dataclasses import dataclass, asdict
from typing import Any, List, Optional

_LOG_PATH = os.environ.get("RAGFW_AUDIT_LOG", "audit.jsonl")

@dataclass
class AuditEvent:
    ts: float
    chunk_hash: Optional[str]
    decision: str
    score: float
    reasons: List[str]
    findings: List[dict]
    policy: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        return cls(
            ts=data.get("ts", time.time()),
            chunk_hash=data.get("chunk_hash"),
            decision=data.get("decision", "allow"),
            score=float(data.get("score", 1.0)),
            reasons=data.get("reasons", []),
            findings=data.get("findings", []),
            policy=data.get("policy"),
        )

    def to_dict(self) -> dict:
        return asdict(self)


class Audit:
    @staticmethod
    def log(event: AuditEvent | dict):
        try:
            if isinstance(event, AuditEvent):
                event = event.to_dict()
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    @staticmethod
    def tail(n: int = 20) -> List[dict]:
        if not os.path.exists(_LOG_PATH):
            return []
        with open(_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        return [json.loads(x) for x in lines[-n:]]