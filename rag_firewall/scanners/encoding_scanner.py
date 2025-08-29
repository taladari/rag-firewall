# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re
BASE64_RE=re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
def _base64_ratio(text):
    if not text: return 0.0
    t=re.sub(r"\s+","",text)
    if not t: return 0.0
    b64_chars=sum(1 for ch in t if ch.isalnum() or ch in "+/=")
    return b64_chars/max(1,len(t))
class EncodedContentScanner:
    def __init__(self, min_len=200, ratio_threshold=0.35):
        self.min_len=min_len; self.ratio=ratio_threshold
    def scan(self, text, metadata):
        t=text or ""
        if len(t)>=self.min_len and _base64_ratio(t)>=self.ratio and BASE64_RE.search(t):
            return [{"scanner":"encoded","match":"suspicious_base64_blob","severity":"high"}]
        return []
