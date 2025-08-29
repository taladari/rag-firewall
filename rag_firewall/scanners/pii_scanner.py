# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re
EMAIL=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE=re.compile(r"(?:\+?\d{1,3})?[\s.-]?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
SSN=re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
class PIIScanner:
    def scan(self, text, metadata):
        t=text or ""; out=[]
        if EMAIL.search(t): out.append({"scanner":"pii","match":"email","severity":"medium"})
        if PHONE.search(t): out.append({"scanner":"pii","match":"phone","severity":"medium"})
        if SSN.search(t): out.append({"scanner":"pii","match":"ssn","severity":"high"})
        return out
