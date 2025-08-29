# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import time
STALE_DAYS_DEFAULT=180
class ConflictScanner:
    def __init__(self, stale_days=STALE_DAYS_DEFAULT): self.stale_days=stale_days
    def scan(self, text, metadata):
        out=[]; ts=metadata.get("timestamp"); deprecated=metadata.get("deprecated", False) or metadata.get("status")=="deprecated"
        if deprecated: out.append({"scanner":"conflict","match":"deprecated","severity":"medium"})
        if ts:
            age_days=(time.time()-float(ts))/86400.0
            if age_days>self.stale_days: out.append({"scanner":"conflict","match":"stale","severity":"medium"})
        return out
