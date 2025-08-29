# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re
DEFAULT_PATTERNS=[r"(?i)ignore (all|previous) instructions", r"(?i)reveal (the )?system prompt", r"(?i)disregard all rules"]
class RegexInjectionScanner:
    def __init__(self, patterns=None): import regex as re; self.patterns=[re.compile(p) for p in (patterns or DEFAULT_PATTERNS)]
    def scan(self, text, metadata): 
        t=text or ""; out=[]
        for patt in self.patterns:
            m=patt.search(t)
            if m: out.append({"scanner":"regex_injection","match":m.group(0)[:120],"severity":"high"})
        return out
