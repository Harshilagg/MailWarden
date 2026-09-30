"""SQLCipher-encrypted SQLite repository (v1 storage).

The 256-bit key is random, generated on first use and kept only in the OS
keyring. The DB file is created 0600 inside the 0700 mailwarden home.
Refuses to open if the library is not actually SQLCipher.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
from pathlib import Path

import sqlcipher3

from mailwarden.core.applications import company_key, role_key
from mailwarden.core.models import (
    Application,
    Classification,
    EmailMeta,
    GateDecision,
    MessageStatus,
    Stage,
    Tier,
)
from mailwarden.security.fs import check_private, ensure_private_dir
from mailwarden.security.secrets import SecretKeys, SecretStore
from mailwarden.storage.base import ApplicationEvent, Repository

SCHEMA_VERSION = 2

# Columns added after v1: (name, SQL type). Applied with ALTER TABLE on open.
_MESSAGE_COLUMNS_V2 = (
    ("classified_by", "TEXT"),
    ("held_reason", "TEXT"),
    ("held_job", "INTEGER NOT NULL DEFAULT 0"),
    ("held_company", "TEXT"),
    ("held_stage", "TEXT"),
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_state (
    user_id TEXT NOT NULL,
    account TEXT NOT NULL,
    cursor TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, account)
);
CREATE TABLE IF NOT EXISTS messages (
    user_id TEXT NOT NULL,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    status TEXT NOT NULL,
    sender_address TEXT,
    sender_name TEXT,
    received_at TEXT,
    tier TEXT,
    gate TEXT,
    category TEXT,
    company TEXT,
    role TEXT,
    stage TEXT,
    action_required INTEGER,
    deadline TEXT,
    summary TEXT,
    processed_at TEXT NOT NULL,
    PRIMARY KEY (user_id, account, message_id)
);
CREATE INDEX IF NOT EXISTS messages_received ON messages (user_id, received_at);
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    company TEXT NOT NULL,
    company_key TEXT NOT NULL,
    role TEXT,
    role_key TEXT NOT NULL,
    current_stage TEXT NOT NULL,
    last_update TEXT NOT NULL,
    source_message_ids TEXT NOT NULL,
    domains TEXT NOT NULL DEFAULT '[]',
    UNIQUE (user_id, company_key, role_key)
);
CREATE TABLE IF NOT EXISTS application_events (
    user_id TEXT NOT NULL,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (user_id, application_id, message_id)
);
"""


class StoreError(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.UTC).isoformat()


class SQLCipherRepository(Repository):
    def __init__(self, path: Path, key_hex: str) -> None:
        ensure_private_dir(path.parent)
        if path.exists():
            check_private(path)
        else:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._path = path
        self._db = sqlcipher3.connect(str(path), isolation_level=None)
        if not all(c in "0123456789abcdef" for c in key_hex) or len(key_hex) != 64:
            raise StoreError("malformed database key")
        self._db.execute(f"PRAGMA key = \"x'{key_hex}'\"")
        version = self._db.execute("PRAGMA cipher_version").fetchone()
        if not version or not version[0]:
            raise StoreError("SQLite library is not SQLCipher; refusing to store data unencrypted")
        try:
            self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlcipher3.DatabaseError:
            raise StoreError("cannot decrypt the database (wrong or missing key in keyring)") from None
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(_SCHEMA)
        self._migrate()
        for suffix in ("-journal", "-wal", "-shm"):
            side = Path(str(path) + suffix)
            if side.exists():
                os.chmod(side, 0o600)

    def _migrate(self) -> None:
        existing = {r[1] for r in self._db.execute("PRAGMA table_info(messages)")}
        for name, sql_type in _MESSAGE_COLUMNS_V2:
            if name not in existing:
                self._db.execute(f"ALTER TABLE messages ADD COLUMN {name} {sql_type}")
        self._db.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    @classmethod
    def open(cls, path: Path, secrets_store: SecretStore, user_id: str) -> SQLCipherRepository:
        key_name = SecretKeys.db_key(user_id)
        key = secrets_store.get(key_name)
        if key is None:
            if path.exists() and path.stat().st_size > 0:
                raise StoreError(
                    f"{path} exists but its key is missing from the keyring; "
                    "restore the key or delete the file to start fresh"
                )
            key = secrets.token_hex(32)
            secrets_store.set(key_name, key)
        return cls(path, key)

    def close(self) -> None:
        self._db.close()

    # -- sync state ---------------------------------------------------------

    def get_sync_cursor(self, user_id: str, account: str) -> str | None:
        row = self._db.execute(
            "SELECT cursor FROM sync_state WHERE user_id = ? AND account = ?", (user_id, account)
        ).fetchone()
        return row[0] if row else None

    def set_sync_cursor(self, user_id: str, account: str, cursor: str) -> None:
        self._db.execute(
            "INSERT INTO sync_state (user_id, account, cursor, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (user_id, account) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at",
            (user_id, account, cursor, _now()),
        )

    # -- messages -----------------------------------------------------------

    def is_processed(self, user_id: str, account: str, message_id: str) -> bool:
        row = self._db.execute(
            "SELECT status FROM messages WHERE user_id = ? AND account = ? AND message_id = ?",
            (user_id, account, message_id),
        ).fetchone()
        return bool(row) and row[0] != MessageStatus.PENDING

    def save_email_meta(self, meta: EmailMeta) -> None:
        c = meta.classification
        sensitive = meta.gate is GateDecision.SENSITIVE
        self._db.execute(
            "INSERT INTO messages (user_id, account, message_id, status, sender_address, sender_name, "
            "received_at, tier, gate, category, company, role, stage, action_required, deadline, summary, processed_at, "
            "classified_by, held_reason, held_job, held_company, held_stage) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (user_id, account, message_id) DO UPDATE SET "
            "status = excluded.status, sender_address = excluded.sender_address, sender_name = excluded.sender_name, "
            "received_at = excluded.received_at, tier = excluded.tier, gate = excluded.gate, "
            "category = excluded.category, company = excluded.company, role = excluded.role, stage = excluded.stage, "
            "action_required = excluded.action_required, deadline = excluded.deadline, summary = excluded.summary, "
            "processed_at = excluded.processed_at, classified_by = excluded.classified_by, "
            "held_reason = excluded.held_reason, held_job = excluded.held_job, "
            "held_company = excluded.held_company, held_stage = excluded.held_stage "
            "WHERE messages.status = 'pending'",
            (
                meta.user_id,
                meta.account,
                meta.message_id,
                meta.status.value,
                None if sensitive else meta.sender_address,
                meta.sender_name[:200],
                _iso(meta.received_at),
                meta.tier.value,
                meta.gate.value,
                c.category.value if c else None,
                c.company if c else None,
                c.role if c else None,
                c.stage.value if c and c.stage else None,
                int(c.action_required) if c else None,
                c.deadline.isoformat() if c and c.deadline else None,
                c.summary if c else None,
                _now(),
                meta.classified_by,
                meta.held_reason if sensitive else None,
                int(meta.held_job),
                meta.held_company if sensitive else None,
                meta.held_stage.value if sensitive and meta.held_stage else None,
            ),
        )

    def mark_pending(self, user_id: str, account: str, message_ids: list[str]) -> None:
        now = _now()
        self._db.executemany(
            "INSERT OR IGNORE INTO messages (user_id, account, message_id, status, processed_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            [(user_id, account, mid, now) for mid in message_ids],
        )

    def list_pending(self, user_id: str, account: str, limit: int) -> list[str]:
        rows = self._db.execute(
            "SELECT message_id FROM messages WHERE user_id = ? AND account = ? AND status = 'pending' "
            "ORDER BY processed_at LIMIT ?",
            (user_id, account, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def list_email_meta(self, user_id: str, since: dt.datetime | None = None) -> list[EmailMeta]:
        sql = (
            "SELECT account, message_id, status, sender_address, sender_name, received_at, tier, gate, "
            "category, company, role, stage, action_required, deadline, summary, "
            "classified_by, held_reason, held_job, held_company, held_stage "
            "FROM messages WHERE user_id = ? AND status != 'pending'"
        )
        args: list[object] = [user_id]
        if since is not None:
            sql += " AND received_at >= ?"
            args.append(_iso(since))
        out = []
        for r in self._db.execute(sql + " ORDER BY received_at DESC", args).fetchall():
            classification = None
            if r[8] is not None:
                classification = Classification.model_validate_json(
                    json.dumps(
                        {
                            "category": r[8], "company": r[9], "role": r[10], "stage": r[11],
                            "action_required": bool(r[12]), "deadline": r[13], "summary": r[14] or "",
                        }
                    )
                )
            out.append(
                EmailMeta(
                    user_id=user_id, account=r[0], message_id=r[1], status=MessageStatus(r[2]),
                    sender_address=r[3], sender_name=r[4] or "", received_at=dt.datetime.fromisoformat(r[5]),
                    tier=Tier(r[6]), gate=GateDecision(r[7]), classification=classification,
                    classified_by=r[15], held_reason=r[16], held_job=bool(r[17]), held_company=r[18],
                    held_stage=Stage(r[19]) if r[19] else None,
                )
            )
        return out

    # -- applications -------------------------------------------------------

    def _row_to_app(self, user_id: str, r: tuple) -> Application:
        return Application(
            user_id=user_id,
            company=r[1],
            role=r[2],
            current_stage=Stage(r[3]),
            last_update=dt.datetime.fromisoformat(r[4]),
            source_message_ids=tuple(json.loads(r[5])),
        )

    _APP_COLS = "id, company, role, current_stage, last_update, source_message_ids"

    def find_application(self, user_id: str, company_key_: str, role_key_: str) -> Application | None:
        rows = self._db.execute(
            f"SELECT {self._APP_COLS}, role_key FROM applications WHERE user_id = ? AND company_key = ? "
            "ORDER BY last_update DESC",
            (user_id, company_key_),
        ).fetchall()
        if not rows:
            return None
        if role_key_:
            exact = [r for r in rows if r[6] == role_key_]
            if exact:
                return self._row_to_app(user_id, exact[0])
            untitled = [r for r in rows if r[6] == ""]
            return self._row_to_app(user_id, untitled[0]) if untitled else None
        return self._row_to_app(user_id, rows[0])

    def upsert_application(
        self,
        app: Application,
        *,
        event_stage: Stage,
        account: str,
        message_id: str,
        occurred_at: dt.datetime,
        domain: str | None,
    ) -> None:
        ckey, rkey = company_key(app.company), role_key(app.role)
        row = self._db.execute(
            "SELECT id, domains FROM applications WHERE user_id = ? AND company_key = ? AND (role_key = ? OR role_key = '') "
            "ORDER BY role_key DESC LIMIT 1",
            (app.user_id, ckey, rkey),
        ).fetchone()
        ids_json = json.dumps(list(app.source_message_ids))
        self._db.execute("BEGIN")
        try:
            if row is None:
                cur = self._db.execute(
                    "INSERT INTO applications (user_id, company, company_key, role, role_key, current_stage, "
                    "last_update, source_message_ids, domains) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (app.user_id, app.company, ckey, app.role, rkey, app.current_stage.value,
                     _iso(app.last_update), ids_json, json.dumps([domain] if domain else [])),
                )
                app_id = cur.lastrowid
            else:
                app_id, domains = row[0], set(json.loads(row[1]))
                if domain:
                    domains.add(domain)
                self._db.execute(
                    "UPDATE applications SET role = ?, role_key = ?, current_stage = ?, last_update = ?, "
                    "source_message_ids = ?, domains = ? WHERE id = ?",
                    (app.role, rkey, app.current_stage.value, _iso(app.last_update), ids_json,
                     json.dumps(sorted(domains)), app_id),
                )
            self._db.execute(
                "INSERT OR IGNORE INTO application_events (user_id, application_id, account, message_id, stage, occurred_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (app.user_id, app_id, account, message_id, event_stage.value, _iso(occurred_at)),
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def list_applications(self, user_id: str) -> list[Application]:
        rows = self._db.execute(
            f"SELECT {self._APP_COLS} FROM applications WHERE user_id = ? ORDER BY last_update DESC", (user_id,)
        ).fetchall()
        return [self._row_to_app(user_id, r) for r in rows]

    def application_history(self, user_id: str, company: str, role: str | None) -> list[ApplicationEvent]:
        rows = self._db.execute(
            "SELECT e.stage, e.message_id, e.occurred_at FROM application_events e "
            "JOIN applications a ON a.id = e.application_id "
            "WHERE a.user_id = ? AND a.company_key = ? AND a.role_key = ? ORDER BY e.occurred_at",
            (user_id, company_key(company), role_key(role)),
        ).fetchall()
        return [ApplicationEvent(Stage(r[0]), r[1], dt.datetime.fromisoformat(r[2])) for r in rows]

    def application_domains(self, user_id: str) -> set[str]:
        out: set[str] = set()
        for (domains,) in self._db.execute("SELECT domains FROM applications WHERE user_id = ?", (user_id,)):
            out.update(json.loads(domains))
        return out

    # -- lifecycle ----------------------------------------------------------

    def delete_account_data(self, user_id: str, account: str) -> None:
        self._db.execute("BEGIN")
        try:
            self._db.execute("DELETE FROM messages WHERE user_id = ? AND account = ?", (user_id, account))
            self._db.execute("DELETE FROM sync_state WHERE user_id = ? AND account = ?", (user_id, account))
            self._db.execute(
                "DELETE FROM application_events WHERE user_id = ? AND account = ?", (user_id, account)
            )
            self._db.execute(
                "DELETE FROM applications WHERE user_id = ? AND id NOT IN "
                "(SELECT application_id FROM application_events WHERE user_id = ?)",
                (user_id, user_id),
            )
            for (app_id,) in self._db.execute("SELECT id FROM applications WHERE user_id = ?", (user_id,)).fetchall():
                remaining = [
                    r[0] for r in self._db.execute(
                        "SELECT message_id FROM application_events WHERE application_id = ? ORDER BY occurred_at",
                        (app_id,),
                    )
                ]
                self._db.execute(
                    "UPDATE applications SET source_message_ids = ? WHERE id = ?", (json.dumps(remaining), app_id)
                )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("VACUUM")
