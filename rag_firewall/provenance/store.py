# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import sqlite3, time
class ProvenanceStore:
    def __init__(self, path='prov.sqlite'):
        self.path=path; self._ensure()
    def _ensure(self):
        con=sqlite3.connect(self.path); cur=con.cursor();
        cur.execute('''CREATE TABLE IF NOT EXISTS provenance (hash TEXT PRIMARY KEY, source TEXT, sensitivity TEXT, timestamp REAL, version TEXT)'''); con.commit(); con.close()
    def record(self, *, hash, source='', sensitivity='low', timestamp=None, version=None):
        ts=time.time() if timestamp is None else float(timestamp)
        con=sqlite3.connect(self.path); cur=con.cursor(); cur.execute('INSERT OR REPLACE INTO provenance(hash,source,sensitivity,timestamp,version) VALUES (?,?,?,?,?)',(hash,source,sensitivity,ts,version)); con.commit(); con.close()
    def get(self, hash):
        con=sqlite3.connect(self.path); cur=con.cursor(); cur.execute('SELECT hash,source,sensitivity,timestamp,version FROM provenance WHERE hash=?',(hash,)); row=cur.fetchone(); con.close();
        return None if not row else {'hash':row[0],'source':row[1],'sensitivity':row[2],'timestamp':row[3],'version':row[4]}
