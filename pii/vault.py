"""Local PII vault — token <-> value mapping plus audit trail, SQLite.

Tokens are stable per (scope, type, value): the same email in the same
scope always maps to the same token, so a cloud model can reason about
[PII_PERSON_1] coherently across a whole conversation. The same value in
a DIFFERENT scope gets a different token — scopes exist so two
conversations cannot be cross-linked through shared placeholders.

Sequence numbers are per (scope, type) and rows are never deleted, so
COUNT()+1 is a safe next-sequence source under the module lock. After a
delete, COUNT()+1 names a token that still exists unless the deleted row
was the newest, and PRIMARY KEY (scope, token) then makes the insert fail;
if it was the newest, its token is minted again for a different value.
So erasure needs a separate sequence first. Values are plaintext in the file: the controls are the
file system (0600, umask set by the caller) and, for the service, its
bind address. Encryption at rest would be a design change of its own, not
something to improvise here.
"""

import datetime
import os
import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pii (
  scope   TEXT NOT NULL,
  token   TEXT NOT NULL,
  type    TEXT NOT NULL,
  value   TEXT NOT NULL,
  created TEXT NOT NULL,
  PRIMARY KEY (scope, token),
  UNIQUE (scope, type, value)
);
CREATE TABLE IF NOT EXISTS audit (
  ts     TEXT NOT NULL,
  scope  TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class Vault:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    def token_for(self, scope: str, typ: str, value: str) -> str:
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT token FROM pii WHERE scope=? AND type=? AND value=?",
                (scope, typ, value),
            ).fetchone()
            if row:
                return row[0]
            n = c.execute(
                "SELECT COUNT(*) FROM pii WHERE scope=? AND type=?", (scope, typ)
            ).fetchone()[0] + 1
            token = f"[PII_{typ}_{n}]"
            c.execute(
                "INSERT INTO pii (scope, token, type, value, created) VALUES (?,?,?,?,?)",
                (scope, token, typ, value, _now()),
            )
            return token

    def value_for(self, scope: str, token: str):
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT value FROM pii WHERE scope=? AND token=?", (scope, token)
            ).fetchone()
            return row[0] if row else None

    def scope_tokens(self, scope: str) -> list:
        """Token inventory for a scope — types and tokens only, never values."""
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT token, type, created FROM pii WHERE scope=? ORDER BY created, token",
                (scope,),
            ).fetchall()
            return [{"token": t, "type": ty, "created": cr} for t, ty, cr in rows]

    def audit(self, scope: str, action: str, detail: str):
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO audit (ts, scope, action, detail) VALUES (?,?,?,?)",
                (_now(), scope, action, detail),
            )
