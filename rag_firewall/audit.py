# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import json, os
_LOG_PATH = os.environ.get("RAGFW_AUDIT_LOG","audit.jsonl")
class Audit:
    @staticmethod
    def log(event):
        try:
            with open(_LOG_PATH,"a",encoding="utf-8") as f: f.write(json.dumps(event)+"\n")
        except Exception: pass
    @staticmethod
    def tail(n=20):
        if not os.path.exists(_LOG_PATH): return []
        return [json.loads(x) for x in open(_LOG_PATH,"r",encoding="utf-8").read().splitlines()[-n:]]
