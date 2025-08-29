# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re
PATTERNS=[(r"AKIA[0-9A-Z]{16}","aws_access_key"),(r"ASIA[0-9A-Z]{16}","aws_temp_key"),
(r"(?i)aws(.{0,20})?(secret|key|access).{0,5}[:=].{0,2}[A-Za-z0-9/+=]{32,}","aws_secret_suspect"),
(r"ghp_[A-Za-z0-9]{36}","github_token"),(r"AIza[0-9A-Za-z\-_]{35}","google_api_key"),
(r"xox[abp]-\d{10,}-\d{10,}-[A-Za-z0-9-]{24,}","slack_token"),(r"sk-[A-Za-z0-9]{32,}","generic_sk_token"),
(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}","bearer_token"),
(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----","private_key")]
class SecretsScanner:
    def __init__(self, extra_patterns=None):
        import regex as re
        self.patterns=[(re.compile(p),name) for p,name in PATTERNS]
        if extra_patterns:
            for p in extra_patterns: self.patterns.append((re.compile(p),"custom_secret"))
    def scan(self, text, metadata):
        t=text or ""; out=[]
        for patt,name in self.patterns:
            if patt.search(t): out.append({"scanner":"secrets","match":name,"severity":"high"})
        return out
