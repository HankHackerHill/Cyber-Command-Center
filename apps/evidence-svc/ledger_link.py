"""Service-owned evidence links backed by the authoritative finding and ledger."""

import os
import re
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from uuid import UUID

import psycopg

from store import ArtifactStore


class MissingEvidence(LookupError):
    """The three references do not identify an intact, same-engagement link."""


class AmbiguousFinding(LookupError):
    """The caller must specify which engagement owns the intended finding."""


class LinkIndex:
    def __init__(self, root: Path, database_url: str, store: ArtifactStore) -> None:
        self._index = root.absolute() / "evidence-links.sqlite3"
        self._database_url = database_url
        self._store = store
        # SQLite otherwise creates its main database using 0666 and the
        # process umask. It derives journal/WAL permissions from this file.
        try:
            fd = os.open(self._index, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        with closing(self._open_index()) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS evidence_links (
                    engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL, record_hash TEXT NOT NULL,
                    PRIMARY KEY (engagement_id, finding_id, sha256, record_hash)
                ) WITHOUT ROWID
            """)

    def _open_index(self) -> sqlite3.Connection:
        # ArtifactStore owns a directory tree without untrusted writers.
        # Reject unsafe files restored into it before SQLite opens them.
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = self._index.with_name(self._index.name + suffix)
            try:
                attributes = path.lstat()
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if (
                not stat.S_ISREG(attributes.st_mode) or attributes.st_mode & 0o077
                or attributes.st_uid != os.geteuid() or attributes.st_nlink != 1
            ):
                raise PermissionError("Unsafe evidence metadata file")
        return sqlite3.connect(self._index)

    def link(
        self, finding_id: str, sha256: str, record_hash: str, engagement_id: UUID | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", record_hash) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise MissingEvidence("Invalid evidence reference")
        with psycopg.connect(self._database_url) as conn:
            conn.read_only = True
            # record_hash is not UNIQUE in MS0. Do not guess which ledger row
            # the caller meant, even when only one owner contains this finding.
            rows = conn.execute(
                """SELECT l.engagement_id, EXISTS (
                           SELECT 1 FROM findings f WHERE f.engagement_id = l.engagement_id AND f.id = %s
                       )
                   FROM immutable_audit_log l
                   WHERE l.record_hash = %s AND (%s::uuid IS NULL OR l.engagement_id = %s)
                   LIMIT 2""",
                (finding_id, record_hash, engagement_id, engagement_id),
            ).fetchall()
        if len(rows) != 1 or not rows[0][1] or not self._store.verified(sha256):
            raise MissingEvidence("Finding, ledger record and artifact do not form a valid link")
        with closing(self._open_index()) as db, db:
            db.execute(
                """INSERT INTO evidence_links (engagement_id, finding_id, sha256, record_hash)
                   VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                (str(rows[0][0]), finding_id, sha256, record_hash),
            )

    def _candidates(self, finding_id: str, engagement_id: UUID | None) -> list[str]:
        with psycopg.connect(self._database_url) as conn:
            conn.read_only = True
            conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            owners = conn.execute(
                """SELECT engagement_id FROM findings
                   WHERE id = %s AND (%s::uuid IS NULL OR engagement_id = %s) LIMIT 2""",
                (finding_id, engagement_id, engagement_id),
            ).fetchall()
            if not owners:
                return []
            if len(owners) > 1:
                raise AmbiguousFinding("Specify engagement_id for this finding ID")
            owner = owners[0][0]
            with closing(self._open_index()) as db:
                links = db.execute(
                    """SELECT sha256, record_hash FROM evidence_links
                       WHERE engagement_id = ? AND finding_id = ?""",
                    (str(owner), finding_id),
                ).fetchall()
            if not links:
                return []
            hashes = list({record_hash for _, record_hash in links})
            rows = conn.execute(
                """SELECT record_hash FROM immutable_audit_log
                   WHERE engagement_id = %s AND record_hash = ANY(%s::char(64)[])
                   GROUP BY record_hash HAVING count(*) = 1""",
                (owner, hashes),
            ).fetchall()
            live = {row[0] for row in rows}
        return sorted({digest for digest, record_hash in links if record_hash in live})

    def artifacts(self, finding_id: str, engagement_id: UUID | None = None) -> list[str]:
        return [
            digest for digest in self._candidates(finding_id, engagement_id)
            if self._store.verified(digest)
        ]

    def has_linked_evidence(self, finding_id: str, engagement_id: UUID | None = None) -> bool:
        return any(self._store.verified(digest) for digest in self._candidates(finding_id, engagement_id))
