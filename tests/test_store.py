import datetime as dt
import os

import pytest

from mailwarden.core.models import (
    Application,
    Category,
    Classification,
    EmailMeta,
    GateDecision,
    MessageStatus,
    Stage,
    Tier,
)
from mailwarden.security.secrets import SecretKeys
from mailwarden.storage.sqlite_store import SQLCipherRepository, StoreError

T0 = dt.datetime(2026, 9, 30, 9, 0, tzinfo=dt.UTC)
C = Classification(category=Category.JOB, company="Acme", role="SWE", stage=Stage.INTERVIEW,
                   action_required=True, deadline=dt.date(2026, 10, 10), summary="Acme interview invite unique-marker-7731")


@pytest.fixture
def repo(tmp_path, secret_store):
    r = SQLCipherRepository.open(tmp_path / "home" / "data" / "mw.db", secret_store, "local")
    yield r
    r.close()


def meta(mid="m1", gate=GateDecision.SAFE, classification=C, **kw):
    return EmailMeta(user_id="local", account="personal", message_id=mid,
                     sender_address=None if gate is GateDecision.SENSITIVE else "hr@acme.com",
                     sender_name="Acme HR", received_at=T0, tier=Tier.DEFAULT, gate=gate,
                     classification=None if gate is GateDecision.SENSITIVE else classification, **kw)


def test_file_is_encrypted_and_private(tmp_path, secret_store):
    path = tmp_path / "home" / "data" / "mw.db"
    r = SQLCipherRepository.open(path, secret_store, "local")
    r.save_email_meta(meta())
    r.close()
    raw = path.read_bytes()
    assert not raw.startswith(b"SQLite format 3")
    assert b"unique-marker-7731" not in raw and b"acme.com" not in raw
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    key = secret_store.get(SecretKeys.db_key("local"))
    assert key and len(key) == 64


def test_wrong_key_cannot_open(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    SQLCipherRepository.open(path, secret_store, "local").close()
    with pytest.raises(StoreError):
        SQLCipherRepository(path, "ab" * 32)


def test_missing_key_for_existing_db_refuses(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    r = SQLCipherRepository.open(path, secret_store, "local")
    r.save_email_meta(meta())
    r.close()
    secret_store.delete(SecretKeys.db_key("local"))
    with pytest.raises(StoreError, match="key is missing"):
        SQLCipherRepository.open(path, secret_store, "local")


def test_loose_db_permissions_refused(tmp_path, secret_store):
    path = tmp_path / "d" / "mw.db"
    SQLCipherRepository.open(path, secret_store, "local").close()
    os.chmod(path, 0o644)
    with pytest.raises(Exception, match="chmod 600"):
        SQLCipherRepository.open(path, secret_store, "local")


def test_schema_has_no_body_or_subject_and_user_id_everywhere(repo):
    db = repo._db
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'meta'")]
    for table in tables:
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        assert "user_id" in cols, table
        assert not cols & {"body", "body_text", "subject", "snippet", "html"}, table


def test_sensitive_row_is_minimal(repo):
    repo.save_email_meta(meta("s1", gate=GateDecision.SENSITIVE))
    row = repo._db.execute("SELECT sender_address, category, summary, sender_name FROM messages").fetchone()
    assert row == (None, None, None, "Acme HR")
    with pytest.raises(ValueError):
        EmailMeta(user_id="local", account="a", message_id="x", sender_address="a@b.com", sender_name="n",
                  received_at=T0, tier=Tier.SENSITIVE, gate=GateDecision.SENSITIVE)


def test_idempotent_and_pending_lifecycle(repo):
    repo.mark_pending("local", "personal", ["m1", "m2"])
    assert repo.list_pending("local", "personal", 10) == ["m1", "m2"]
    assert not repo.is_processed("local", "personal", "m1")
    repo.save_email_meta(meta("m1"))
    assert repo.is_processed("local", "personal", "m1")
    repo.mark_pending("local", "personal", ["m1"])  # never downgrades a processed row
    assert repo.is_processed("local", "personal", "m1")
    repo.save_email_meta(meta("m1", classification=None, status=MessageStatus.UNCLASSIFIED))  # no overwrite
    assert repo.list_email_meta("local")[0].classification == C
    assert repo.list_pending("local", "personal", 10) == ["m2"]


def test_user_isolation(repo):
    repo.save_email_meta(meta())
    repo.set_sync_cursor("local", "personal", "42")
    assert repo.list_email_meta("someone-else") == []
    assert repo.get_sync_cursor("someone-else", "personal") is None


def test_applications_and_history_and_forget(repo):
    app = Application(user_id="local", company="Acme", role="SWE", current_stage=Stage.APPLIED,
                      last_update=T0, source_message_ids=("m1",))
    repo.upsert_application(app, event_stage=Stage.APPLIED, account="personal", message_id="m1",
                            occurred_at=T0, domain="acme.com")
    later = app.model_copy(update={"current_stage": Stage.INTERVIEW, "source_message_ids": ("m1", "m2")})
    repo.upsert_application(later, event_stage=Stage.INTERVIEW, account="work", message_id="m2",
                            occurred_at=T0 + dt.timedelta(days=3), domain=None)
    apps = repo.list_applications("local")
    assert len(apps) == 1 and apps[0].current_stage is Stage.INTERVIEW
    assert [e.stage for e in repo.application_history("local", "Acme", "SWE")] == [Stage.APPLIED, Stage.INTERVIEW]
    assert repo.application_domains("local") == {"acme.com"}

    repo.save_email_meta(meta("m1"))
    repo.set_sync_cursor("local", "personal", "9")
    repo.delete_account_data("local", "personal")
    assert repo.list_email_meta("local") == [] and repo.get_sync_cursor("local", "personal") is None
    apps = repo.list_applications("local")  # still referenced by the 'work' account
    assert len(apps) == 1 and apps[0].source_message_ids == ("m2",)
    repo.delete_account_data("local", "work")
    assert repo.list_applications("local") == []
