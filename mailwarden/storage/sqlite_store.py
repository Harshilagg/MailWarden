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
    JobPost,
    StoredJob,
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

SCHEMA_VERSION = 7

# Columns added after v1: (name, SQL type). Applied with ALTER TABLE on open.
_MESSAGE_COLUMNS_V2 = (
    ("classified_by", "TEXT"),
    ("held_reason", "TEXT"),
    ("held_job", "INTEGER NOT NULL DEFAULT 0"),
    ("held_company", "TEXT"),
    ("held_stage", "TEXT"),
    ("dismissed_at", "TEXT"),
    ("urgent_since", "TEXT"),
    ("held_deadline", "TEXT"),
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
CREATE TABLE IF NOT EXISTS job_postings (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    title TEXT NOT NULL,
    company TEXT,
    location TEXT,
    link TEXT,
    sender TEXT NOT NULL,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    dismissed_at TEXT,
    UNIQUE (user_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS job_postings_recent ON job_postings (user_id, received_at);
CREATE TABLE IF NOT EXISTS job_sightings (
    user_id TEXT NOT NULL,
    job_id INTEGER NOT NULL REFERENCES job_postings(id) ON DELETE CASCADE,
    source_type TEXT,
    source_name TEXT,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    link TEXT,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (user_id, job_id, message_id)
);
CREATE TABLE IF NOT EXISTS user_state (
    user_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    period_start TEXT NOT NULL,
    body_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS digests_user ON digests (user_id, generated_at);
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
        self._db.execute("PRAGMA busy_timeout = 5000")  # dashboard and scheduled runs share the file
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
        if "urgent_since" not in existing:
            self._pin_currently_urgent()
        self._migrate_jobs()
        self._db.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    _JOB_COLUMNS_V6 = (
        ("listing_details", "TEXT"), ("jd_status", "TEXT"), ("jd_reason", "TEXT"), ("jd_source", "TEXT"),
        ("jd_text", "TEXT"), ("jd_fetched_at", "TEXT"), ("score", "REAL"), ("score_level", "TEXT"),
        ("score_json", "TEXT"), ("score_hash", "TEXT"), ("scored_at", "TEXT"),
        ("source_type", "TEXT"), ("source_name", "TEXT"),
    )

    def _migrate_jobs(self) -> None:
        existing = {r[1] for r in self._db.execute("PRAGMA table_info(job_postings)")}
        needs_v7 = "source_type" not in existing
        if needs_v7 and self._db.execute("SELECT count(*) FROM job_postings").fetchone()[0]:
            self._backup("before-v7")
        for name, sql_type in self._JOB_COLUMNS_V6:
            if name not in existing:
                self._db.execute(f"ALTER TABLE job_postings ADD COLUMN {name} {sql_type}")
        if needs_v7:
            self._rekey_jobs_v7()

    def _backup(self, tag: str) -> None:
        """Copy the (encrypted) database file before a migration that merges rows."""
        import shutil

        target = self._path.with_name(f"{self._path.name}.{tag}.bak")
        if not target.exists():
            shutil.copy2(self._path, target)
            os.chmod(target, 0o600)

    def _rekey_jobs_v7(self) -> None:
        """Tidy titles/companies, record sources and sightings, re-key and merge duplicates."""
        from mailwarden.core.job_alerts import dedup_key
        from mailwarden.core.models import JobPost
        from mailwarden.core.sources import classify_source, display_company, split_title_location

        rows = self._db.execute(
            "SELECT j.id, j.user_id, j.title, j.company, j.location, j.link, j.sender, j.account, j.message_id, "
            "j.received_at, j.jd_status, j.score, m.sender_address FROM job_postings j LEFT JOIN messages m "
            "ON m.user_id = j.user_id AND m.account = j.account AND m.message_id = j.message_id "
            "ORDER BY j.received_at, j.id").fetchall()
        keep: dict[tuple[str, str], tuple] = {}
        self._db.execute("BEGIN")
        try:
            for (jid, uid, title, company, location, link, sender, account, mid, received, jd_status, score,
                 address) in rows:
                title2, location2 = split_title_location(title, location)
                company2 = display_company(company) if company else None
                stype, sname = classify_source(address, sender)
                key = dedup_key(JobPost(title=title2[:200] if len(title2) >= 2 else title, company=company2,
                                        location=location2, link=link), sender)
                self._db.execute(
                    "UPDATE job_postings SET title = ?, company = ?, location = ?, source_type = ?, source_name = ?, "
                    "dedup_key = ? WHERE id = ?",
                    (title2 if len(title2) >= 2 else title, company2, location2, stype, sname, f"tmp:{jid}", jid))
                self._db.execute(
                    "INSERT OR IGNORE INTO job_sightings (user_id, job_id, source_type, source_name, account, "
                    "message_id, link, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (uid, jid, stype, sname, account, mid, link, received))
                current = keep.get((uid, key))
                if current is None:
                    keep[(uid, key)] = (jid, jd_status, score)
                    continue
                # Duplicate: keep the row with a JD, else a score, else the older one; move sightings.
                cur_id, cur_jd, cur_score = current
                winner, loser = (jid, cur_id) if (jd_status == "ok", score is not None) > (cur_jd == "ok",
                                                                                           cur_score is not None) \
                    else (cur_id, jid)
                self._db.execute("UPDATE OR IGNORE job_sightings SET job_id = ? WHERE job_id = ?", (winner, loser))
                self._db.execute("DELETE FROM job_postings WHERE id = ?", (loser,))
                keep[(uid, key)] = (winner, *((jd_status, score) if winner == jid else (cur_jd, cur_score)))
            # A copy with no city joins the same company+title that has one (the earliest).
            for (uid, key) in [k for k in keep if k[1].startswith("c:") and k[1].endswith("|l:")]:
                siblings = sorted((k for k in keep if k[0] == uid and k[1] != key and k[1].startswith(key)),
                                  key=lambda k: keep[k][0])
                if siblings:
                    winner, loser = keep[siblings[0]][0], keep.pop((uid, key))[0]
                    self._db.execute("UPDATE OR IGNORE job_sightings SET job_id = ? WHERE job_id = ?", (winner, loser))
                    self._db.execute("DELETE FROM job_postings WHERE id = ?", (loser,))
            for (uid, key), (jid, _, _) in keep.items():
                self._db.execute("UPDATE job_postings SET dedup_key = ? WHERE id = ?", (key, jid))
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def _pin_currently_urgent(self) -> None:
        """v5 migration: pin everything that is urgent right now, so nothing drops out later."""
        from mailwarden.core.overview import urgent_by_rules

        users = [r[0] for r in self._db.execute("SELECT DISTINCT user_id FROM messages")]
        for user_id in users:
            for m in self.list_email_meta(user_id):
                if not m.dismissed and urgent_by_rules(m):
                    self._db.execute(
                        "UPDATE messages SET urgent_since = processed_at WHERE user_id = ? AND account = ? AND message_id = ?",
                        (user_id, m.account, m.message_id),
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
            "classified_by, held_reason, held_job, held_company, held_stage, urgent_since, held_deadline, dismissed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (user_id, account, message_id) DO UPDATE SET "
            "status = excluded.status, sender_address = excluded.sender_address, sender_name = excluded.sender_name, "
            "received_at = excluded.received_at, tier = excluded.tier, gate = excluded.gate, "
            "category = excluded.category, company = excluded.company, role = excluded.role, stage = excluded.stage, "
            "action_required = excluded.action_required, deadline = excluded.deadline, summary = excluded.summary, "
            "processed_at = excluded.processed_at, classified_by = excluded.classified_by, "
            "held_reason = excluded.held_reason, held_job = excluded.held_job, "
            "held_company = excluded.held_company, held_stage = excluded.held_stage, "
            "urgent_since = COALESCE(messages.urgent_since, excluded.urgent_since), "
            "held_deadline = excluded.held_deadline, dismissed_at = COALESCE(messages.dismissed_at, excluded.dismissed_at) "
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
                _iso(meta.urgent_since) if meta.urgent_since else None,
                meta.held_deadline.isoformat() if sensitive and meta.held_deadline else None,
                _now() if meta.dismissed else None,
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
        if since is None:
            return self._list(user_id, "", [])
        return self._list(user_id, "AND received_at >= ?", [_iso(since)])

    def _list(self, user_id: str, where: str, extra: list[object]) -> list[EmailMeta]:
        sql = (
            "SELECT account, message_id, status, sender_address, sender_name, received_at, tier, gate, "
            "category, company, role, stage, action_required, deadline, summary, "
            "classified_by, held_reason, held_job, held_company, held_stage, dismissed_at, urgent_since, held_deadline "
            "FROM messages WHERE user_id = ? AND status != 'pending'"
        )
        sql += " " + where
        args: list[object] = [user_id, *extra]
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
                    held_stage=Stage(r[19]) if r[19] else None, dismissed=r[20] is not None,
                    urgent_since=dt.datetime.fromisoformat(r[21]) if r[21] else None,
                    held_deadline=dt.date.fromisoformat(r[22]) if r[22] else None,
                )
            )
        return out

    def get_email_meta(self, user_id: str, account: str, message_id: str) -> EmailMeta | None:
        for meta in self._list(user_id, "AND account = ? AND message_id = ?", [account, message_id]):
            return meta
        return None

    def dismiss(self, user_id: str, account: str, message_id: str) -> bool:
        cur = self._db.execute(
            "UPDATE messages SET dismissed_at = ? WHERE user_id = ? AND account = ? AND message_id = ?",
            (_now(), user_id, account, message_id),
        )
        return cur.rowcount > 0

    def delete_message(self, user_id: str, account: str, message_id: str) -> None:
        self._db.execute("DELETE FROM messages WHERE user_id = ? AND account = ? AND message_id = ?",
                         (user_id, account, message_id))
        self._db.execute("DELETE FROM job_sightings WHERE user_id = ? AND account = ? AND message_id = ?",
                         (user_id, account, message_id))
        self._db.execute("DELETE FROM job_postings WHERE user_id = ? AND account = ? AND message_id = ?",
                         (user_id, account, message_id))

    # -- job alerts ---------------------------------------------------------

    def _find_job_key(self, user_id: str, key: str) -> tuple[int, str] | None:
        """Exact key, else the same company+title with an unknown city (either side)."""
        from mailwarden.core.job_alerts import key_without_location

        row = self._db.execute("SELECT id, dedup_key FROM job_postings WHERE user_id = ? AND dedup_key = ?",
                               (user_id, key)).fetchone()
        if row:
            return row[0], row[1]
        base = key_without_location(key)
        if base is None:
            return None
        if key == base:  # this sighting has no city: attach to any city of the same job
            row = self._db.execute(
                "SELECT id, dedup_key FROM job_postings WHERE user_id = ? AND substr(dedup_key, 1, ?) = ? "
                "ORDER BY received_at LIMIT 1", (user_id, len(base), base)).fetchone()
        else:  # this sighting has a city: fill it into a city-less row of the same job
            row = self._db.execute("SELECT id, dedup_key FROM job_postings WHERE user_id = ? AND dedup_key = ?",
                                   (user_id, base)).fetchone()
        return (row[0], row[1]) if row else None

    def save_jobs(self, user_id: str, *, account: str, message_id: str, sender: str,
                  received_at: dt.datetime, posts: list[JobPost], keys: list[str],
                  source_type: str | None = None, source_name: str | None = None) -> int:
        new = 0
        for post, key in zip(posts, keys, strict=True):
            found = self._find_job_key(user_id, key)
            if found:
                job_id, old_key = found
                # Same job seen via another alert: keep the first sighting, fill gaps only.
                self._db.execute(
                    "UPDATE job_postings SET link = COALESCE(link, ?), location = COALESCE(location, ?), "
                    "listing_details = COALESCE(listing_details, ?), dedup_key = ? WHERE id = ?",
                    (post.link, post.location, post.details, key if old_key.endswith("|l:") else old_key, job_id),
                )
            else:
                cur = self._db.execute(
                    "INSERT INTO job_postings (user_id, dedup_key, title, company, location, link, sender, account, "
                    "message_id, received_at, listing_details, source_type, source_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (user_id, key, post.title, post.company, post.location, post.link, sender[:200], account,
                     message_id, _iso(received_at), post.details, source_type, source_name),
                )
                job_id = cur.lastrowid
                new += 1
            self._db.execute(
                "INSERT OR IGNORE INTO job_sightings (user_id, job_id, source_type, source_name, account, message_id, "
                "link, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, job_id, source_type, source_name, account, message_id, post.link, _iso(received_at)),
            )
        return new

    _JOB_SELECT = ("SELECT id, title, company, location, link, sender, account, message_id, received_at, dismissed_at, "
                   "listing_details, jd_status, jd_reason, jd_source, jd_text, jd_fetched_at, score, score_level, score_json, "
                   "score_hash, source_type, source_name FROM job_postings")

    def _row_to_job(self, user_id: str, r: tuple) -> StoredJob:
        detail = json.loads(r[18]) if r[18] else {}
        return StoredJob(
            id=r[0], user_id=user_id, title=r[1], company=r[2], location=r[3], link=r[4], sender=r[5],
            account=r[6], message_id=r[7], received_at=dt.datetime.fromisoformat(r[8]), dismissed=r[9] is not None,
            details=r[10], jd_status=r[11], jd_reason=r[12], jd_source=r[13], jd_text=r[14],
            jd_fetched_at=dt.datetime.fromisoformat(r[15]) if r[15] else None, score=r[16], score_level=r[17],
            matched_skills=tuple(detail.get("matched_skills", ())), missing_skills=tuple(detail.get("missing_skills", ())),
            evidence=tuple((e["project"], tuple(e.get("skills", ()))) for e in detail.get("evidence", ())),
            best_project=detail.get("best_project"), why=detail.get("why"), score_hash=r[19],
            source_type=r[20], source_name=r[21],
            also_on=tuple(n for n in self._sightings(user_id, r[0]) if n and n != r[21]),
        )

    def _sightings(self, user_id: str, job_id: int) -> list[str]:
        rows = self._db.execute(
            "SELECT source_name, min(seen_at) FROM job_sightings WHERE user_id = ? AND job_id = ? "
            "GROUP BY source_name ORDER BY min(seen_at), min(rowid)", (user_id, job_id)).fetchall()
        return [r[0] for r in rows]

    def list_jobs(self, user_id: str, *, include_dismissed: bool = False, since: dt.datetime | None = None,
                  limit: int = 500) -> list[StoredJob]:
        sql = self._JOB_SELECT + " WHERE user_id = ?"
        args: list[object] = [user_id]
        if not include_dismissed:
            sql += " AND dismissed_at IS NULL"
        if since is not None:
            sql += " AND received_at >= ?"
            args.append(_iso(since))
        sql += " ORDER BY received_at DESC, id DESC LIMIT ?"
        args.append(limit)
        return [self._row_to_job(user_id, r) for r in self._db.execute(sql, args).fetchall()]

    def get_job(self, user_id: str, job_id: int) -> StoredJob | None:
        row = self._db.execute(self._JOB_SELECT + " WHERE user_id = ? AND id = ?", (user_id, job_id)).fetchone()
        return self._row_to_job(user_id, row) if row else None

    def save_jd(self, user_id: str, job_id: int, *, status: str, reason: str | None, source: str | None,
                text: str | None) -> None:
        self._db.execute(
            "UPDATE job_postings SET jd_status = ?, jd_reason = ?, jd_source = ?, jd_text = ?, jd_fetched_at = ? "
            "WHERE user_id = ? AND id = ?",
            (status, reason, source, text, _now(), user_id, job_id),
        )

    def save_score(self, user_id: str, job_id: int, *, score: float, level: str, detail: dict, input_hash: str) -> None:
        self._db.execute(
            "UPDATE job_postings SET score = ?, score_level = ?, score_json = ?, score_hash = ?, scored_at = ? "
            "WHERE user_id = ? AND id = ?",
            (score, level, json.dumps(detail), input_hash, _now(), user_id, job_id),
        )

    def dismiss_job(self, user_id: str, job_id: int) -> bool:
        cur = self._db.execute("UPDATE job_postings SET dismissed_at = ? WHERE user_id = ? AND id = ?",
                               (_now(), user_id, job_id))
        return cur.rowcount > 0

    def get_state(self, user_id: str, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM user_state WHERE user_id = ? AND key = ?", (user_id, key)).fetchone()
        return row[0] if row else None

    def set_state(self, user_id: str, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO user_state (user_id, key, value) VALUES (?, ?, ?) "
            "ON CONFLICT (user_id, key) DO UPDATE SET value = excluded.value",
            (user_id, key, value),
        )

    # -- digests ------------------------------------------------------------

    def save_digest(self, user_id: str, generated_at: dt.datetime, period_start: dt.datetime, body_json: str) -> None:
        self._db.execute(
            "INSERT INTO digests (user_id, generated_at, period_start, body_json) VALUES (?, ?, ?, ?)",
            (user_id, _iso(generated_at), _iso(period_start), body_json),
        )
        # Keep a bounded history.
        self._db.execute(
            "DELETE FROM digests WHERE user_id = ? AND id NOT IN "
            "(SELECT id FROM digests WHERE user_id = ? ORDER BY generated_at DESC LIMIT 60)",
            (user_id, user_id),
        )

    def latest_digest(self, user_id: str) -> tuple[dt.datetime, dt.datetime, str] | None:
        row = self._db.execute(
            "SELECT generated_at, period_start, body_json FROM digests WHERE user_id = ? "
            "ORDER BY generated_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        return dt.datetime.fromisoformat(row[0]), dt.datetime.fromisoformat(row[1]), row[2]

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
            # Digests summarise all accounts; drop them rather than keep stale content.
            self._db.execute("DELETE FROM digests WHERE user_id = ?", (user_id,))
            self._db.execute("DELETE FROM job_sightings WHERE user_id = ? AND account = ?", (user_id, account))
            self._db.execute("DELETE FROM job_postings WHERE user_id = ? AND account = ?", (user_id, account))
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
