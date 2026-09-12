"""tests/test_archive.py — JSONL archive: dedup, search, decrypt_failed handling."""
from __future__ import annotations

import json

from mcp_agent_mail.archive import EmailArchive

UID = "12345"


def make_archive(tmp_project):
    root, env = tmp_project
    return EmailArchive(type("Cfg", (), {"archive_path": env["ARCHIVE_PATH"]})())


def sample_email(**over):
    base = {
        "uid": UID,
        "folder": "INBOX",
        "sender": "alice@example.com",
        "to": "agent@example.com",
        "subject": "Hello",
        "date": "2026-01-01 10:00",
        "body": "some plaintext body",
        "attachments": [{"filename": "a.pdf", "content_type": "application/pdf", "size": 42}],
        "decrypt_failed": False,
    }
    base.update(over)
    return base


class TestRecord:
    def test_records_and_retrieves(self, tmp_project):
        ar = make_archive(tmp_project)
        assert ar.record(sample_email()) is True
        got = ar.get(UID)
        assert got["body"] == "some plaintext body"
        assert got["attachments"][0]["filename"] == "a.pdf"

    def test_dedupe_by_uid(self, tmp_project):
        ar = make_archive(tmp_project)
        assert ar.record(sample_email()) is True
        assert ar.record(sample_email(subject="Different")) is False
        assert ar.get(UID)["subject"] == "Hello"

    def test_rejects_missing_uid(self, tmp_project):
        ar = make_archive(tmp_project)
        assert ar.record(sample_email(uid="")) is False

    def test_decrypt_failed_stores_empty_body_but_keeps_metadata(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email(body="", decrypt_failed=True))
        got = ar.get(UID)
        assert got["decrypt_failed"] is True
        assert got["body"] == ""
        assert got["subject"] == "Hello"

    def test_archive_stores_full_body_beyond_read_cap(self, tmp_project):
        ar = make_archive(tmp_project)
        big = "x" * 3000
        ar.record(sample_email(body=big))
        assert len(ar.get(UID)["body"]) == 3000

    def test_new_archive_instance_sees_previous_writes(self, tmp_project):
        root, env = tmp_project
        ar = make_archive(tmp_project)
        ar.record(sample_email(body="persisted"))
        ar2 = EmailArchive(type("Cfg", (), {"archive_path": env["ARCHIVE_PATH"]})())
        assert ar2.get(UID)["body"] == "persisted"
        assert ar2.record(sample_email(subject="dup")) is False


class TestSearch:
    def test_search_matches_subject(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email(subject="Quarterly Report"))
        hits = ar.search("quarterly")
        assert len(hits) == 1
        assert hits[0]["subject"] == "Quarterly Report"

    def test_search_matches_body_case_insensitive(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email(body="Meeting at 4pm in Berlin"))
        hits = ar.search("berlin")
        assert len(hits) == 1

    def test_search_matches_sender(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email(sender="carol@example.com"))
        hits = ar.search("carol")
        assert len(hits) == 1

    def test_search_returns_metadata_not_bodies(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email(subject="Secret Subject", body="hidden body text"))
        hits = ar.search("hidden")
        assert "body" not in hits[0]

    def test_no_match_returns_empty(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email())
        assert ar.search("zzzznothing") == []

    def test_empty_query_returns_empty(self, tmp_project):
        ar = make_archive(tmp_project)
        ar.record(sample_email())
        assert ar.search("") == []

    def test_limit_respected(self, tmp_project):
        ar = make_archive(tmp_project)
        for i in range(5):
            ar.record(sample_email(uid=str(1000 + i), subject="common word"))
        hits = ar.search("common", limit=3)
        assert len(hits) == 3


class TestSimpleArchive:
    def test_file_created_jsonl(self, tmp_project):
        root, env = tmp_project
        ar = make_archive(tmp_project)
        ar.record(sample_email())
        path = env["ARCHIVE_PATH"]
        with open(path, encoding="utf-8") as f:
            line = f.readline().strip()
        obj = json.loads(line)
        assert obj["uid"] == UID
        assert isinstance(obj["attachments"], list)
