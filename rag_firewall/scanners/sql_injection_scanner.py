# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import regex as re

# Read-only probe patterns — attacker is fishing for data (UNION-based, boolean blind, comment stripping)
_PROBE_PATTERNS = [
    (r"(?i)\bUNION\s+(ALL\s+)?SELECT\b", "union_select"),
    (r"(?i)\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "or_tautology"),    # OR 1=1, OR '1'='1'
    (r"(?i)'\s*OR\s+'[^']*'\s*=\s*'[^']*'", "or_string_tautology"),            # ' OR 'a'='a
    (r"(?i)--\s*$", "comment_strip"),                                            # trailing --
    (r"(?i);--", "semicolon_comment"),                                           # ;--
    (r"(?i)\bSLEEP\s*\(\s*\d+\s*\)\b", "time_blind_sleep"),                    # SLEEP(5)
    (r"(?i)\bWAITFOR\s+DELAY\b", "time_blind_waitfor"),                         # MSSQL WAITFOR DELAY
    (r"(?i)\bBENCHMARK\s*\(", "time_blind_benchmark"),                          # MySQL BENCHMARK(
]

# Destructive DDL/DML patterns — attacker is trying to mutate or destroy data
_DESTRUCTIVE_PATTERNS = [
    (r"(?i)\bDROP\s+TABLE\b", "drop_table"),
    (r"(?i)\bDROP\s+DATABASE\b", "drop_database"),
    (r"(?i)\bTRUNCATE\s+TABLE\b", "truncate_table"),
    (r"(?i)\bDELETE\s+FROM\b", "delete_from"),
    (r"(?i)\bINSERT\s+INTO\b", "insert_into"),
    (r"(?i)\bUPDATE\s+\w+\s+SET\b", "update_set"),
    (r"(?i)\bALTER\s+TABLE\b", "alter_table"),
    (r"(?i)\bEXEC\s*\(", "exec_call"),                                           # EXEC( for stacked queries
    (r"(?i)\bxp_cmdshell\b", "xp_cmdshell"),                                    # MSSQL shell escape
]


class SQLInjectionScanner:
    """Detects SQL injection attempts in retrieved text chunks.

    Splits findings into two severity tiers:
    - ``medium``: read-only probes (UNION SELECT, tautologies, time-based blind)
    - ``high``:   destructive DDL/DML (DROP TABLE, DELETE FROM, xp_cmdshell ...)

    Args:
        extra_patterns: Optional list of ``(pattern, name, severity)`` tuples
            to extend the built-in set at runtime.
    """

    def __init__(self, extra_patterns=None):
        self._probes = [(re.compile(p), name, "medium") for p, name in _PROBE_PATTERNS]
        self._destructive = [(re.compile(p), name, "high") for p, name in _DESTRUCTIVE_PATTERNS]
        self._extra = []
        if extra_patterns:
            for p, name, sev in extra_patterns:
                self._extra.append((re.compile(p), name, sev))

    def scan(self, text: str, metadata: dict) -> list[dict]:
        """Scan *text* for SQL injection patterns.

        Args:
            text: The document chunk content.
            metadata: Document metadata (unused but required by scanner protocol).

        Returns:
            A list of finding dicts with keys ``scanner``, ``match``, ``severity``.
        """
        t = text or ""
        out = []
        for patt, name, severity in self._probes + self._destructive + self._extra:
            if patt.search(t):
                out.append({"scanner": "sql_injection", "match": name, "severity": severity})
        return out
