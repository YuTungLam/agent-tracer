"""Run-scoped durable memory for offline provider-propagation pilots.

The caller chooses one SQLite database path per run.  The store records the
controller-assigned run and record identities, rejects overwrites, and binds a
later read to the exact committed version and content digest.  It performs no
network calls or sink actions; its only side effect is the caller-requested
SQLite file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3

from .utils import sha256_text


PROVIDER_MEMORY_SCHEMA_VERSION = "provider-memory-v1"
_MAX_CONTENT_BYTES = 2_000
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_METADATA_TABLE = "provider_memory_metadata"
_RECORDS_TABLE = "provider_memory_records"


class ProviderMemoryError(RuntimeError):
    """Base class for explicit, fail-closed provider-memory failures."""


class ProviderMemoryValidationError(ProviderMemoryError):
    """A caller supplied an invalid run, record, version, hash, or path."""


class ProviderMemorySchemaError(ProviderMemoryError):
    """The persisted database has an unexpected or malformed schema."""


class ProviderMemoryIntegrityError(ProviderMemoryError):
    """Persisted content no longer matches its committed identity."""


class ProviderMemoryNotFoundError(ProviderMemoryError):
    """The controller-requested memory record does not exist."""


class ProviderMemoryConflictError(ProviderMemoryError):
    """A write would replace an already committed controller record."""


@dataclass(frozen=True)
class ProviderMemoryRecord:
    """One immutable record returned at both the write and read boundaries."""

    record_id: str
    version: int
    content: str
    content_sha256: str


class SQLiteRunMemoryStore:
    """A deterministic SQLite store bound to one caller-declared run."""

    def __init__(self, database_path: str | Path, *, run_id: str) -> None:
        self._run_id = _validated_identifier(run_id, label="run_id")
        self._database_path = _validated_database_path(database_path)
        self._connection: sqlite3.Connection | None = None

        try:
            connection = sqlite3.connect(
                str(self._database_path),
                timeout=5.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            self._connection = connection
            self._initialize_or_validate()
        except ProviderMemoryError:
            self.close()
            raise
        except sqlite3.DatabaseError as exc:
            self.close()
            raise ProviderMemorySchemaError(
                "Provider memory database could not be opened or validated"
            ) from exc

    @property
    def database_path(self) -> Path:
        return self._database_path

    @property
    def run_id(self) -> str:
        return self._run_id

    def __enter__(self) -> SQLiteRunMemoryStore:
        self._require_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the local database connection; repeated closes are harmless."""

        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def write(self, record_id: str, content: str) -> ProviderMemoryRecord:
        """Commit a controller-fixed record once and return its version/hash."""

        resolved_record_id = _validated_identifier(record_id, label="record_id")
        resolved_content = _validated_content(content)
        content_sha256 = sha256_text(resolved_content)
        connection = self._validated_connection()

        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                f"SELECT record_id FROM {_RECORDS_TABLE} LIMIT 1",
            ).fetchone()
            if existing is not None:
                raise ProviderMemoryConflictError(
                    "Provider memory database already contains its single "
                    "controller record; refusing an additional write or overwrite"
                )
            connection.execute(
                f"""
                INSERT INTO {_RECORDS_TABLE}
                    (record_id, version, content, content_sha256)
                VALUES (?, ?, ?, ?)
                """,
                (resolved_record_id, 1, resolved_content, content_sha256),
            )
            connection.execute("COMMIT")
        except ProviderMemoryError:
            _rollback_if_active(connection)
            raise
        except sqlite3.DatabaseError as exc:
            _rollback_if_active(connection)
            raise ProviderMemoryIntegrityError(
                "Provider memory write failed closed"
            ) from exc

        return ProviderMemoryRecord(
            record_id=resolved_record_id,
            version=1,
            content=resolved_content,
            content_sha256=content_sha256,
        )

    def read(
        self,
        record_id: str,
        *,
        expected_version: int,
        expected_content_sha256: str,
    ) -> ProviderMemoryRecord:
        """Read only when persisted and controller-expected identities agree."""

        resolved_record_id = _validated_identifier(record_id, label="record_id")
        resolved_version = _validated_version(expected_version)
        resolved_hash = _validated_sha256(
            expected_content_sha256,
            label="expected_content_sha256",
        )
        connection = self._validated_connection()

        try:
            row = connection.execute(
                f"""
                SELECT record_id, version, content, content_sha256
                FROM {_RECORDS_TABLE}
                WHERE record_id = ?
                """,
                (resolved_record_id,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise ProviderMemoryIntegrityError(
                "Provider memory read failed closed"
            ) from exc

        if row is None:
            raise ProviderMemoryNotFoundError(
                f"Unknown provider memory record {resolved_record_id!r}"
            )

        record = _record_from_row(row)
        actual_hash = sha256_text(record.content)
        if actual_hash != record.content_sha256:
            raise ProviderMemoryIntegrityError(
                f"Provider memory record {resolved_record_id!r} failed "
                "persisted content hash validation"
            )
        if record.version != resolved_version:
            raise ProviderMemoryIntegrityError(
                f"Provider memory record {resolved_record_id!r} has version "
                f"{record.version}, expected {resolved_version}"
            )
        if record.content_sha256 != resolved_hash:
            raise ProviderMemoryIntegrityError(
                f"Provider memory record {resolved_record_id!r} has an "
                "unexpected content hash"
            )
        return record

    def _initialize_or_validate(self) -> None:
        connection = self._require_open()
        try:
            objects = _user_schema_objects(connection)
            if not objects:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    f"""
                    CREATE TABLE {_METADATA_TABLE} (
                        key TEXT PRIMARY KEY NOT NULL,
                        value TEXT NOT NULL
                    ) STRICT
                    """
                )
                connection.execute(
                    f"""
                    CREATE TABLE {_RECORDS_TABLE} (
                        record_id TEXT PRIMARY KEY NOT NULL,
                        version INTEGER NOT NULL CHECK (version = 1),
                        content TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL
                            CHECK (
                                length(content_sha256) = 64
                                AND content_sha256 NOT GLOB '*[^0-9a-f]*'
                            )
                    ) STRICT
                    """
                )
                connection.executemany(
                    f"INSERT INTO {_METADATA_TABLE} (key, value) VALUES (?, ?)",
                    (
                        ("run_id", self._run_id),
                        ("schema_version", PROVIDER_MEMORY_SCHEMA_VERSION),
                    ),
                )
                connection.execute("COMMIT")
            self._validate_schema_and_metadata(connection)
        except ProviderMemoryError:
            _rollback_if_active(connection)
            raise
        except sqlite3.DatabaseError as exc:
            _rollback_if_active(connection)
            raise ProviderMemorySchemaError(
                "Provider memory schema initialization or validation failed"
            ) from exc

    def _validated_connection(self) -> sqlite3.Connection:
        connection = self._require_open()
        self._validate_schema_and_metadata(connection)
        return connection

    def _validate_schema_and_metadata(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        objects = _user_schema_objects(connection)
        expected_objects = {
            ("table", _METADATA_TABLE),
            ("table", _RECORDS_TABLE),
        }
        if objects != expected_objects:
            raise ProviderMemorySchemaError(
                "Provider memory database contains missing or unknown schema objects"
            )

        expected_columns = {
            _METADATA_TABLE: (
                ("key", "TEXT", 1, 1),
                ("value", "TEXT", 1, 0),
            ),
            _RECORDS_TABLE: (
                ("record_id", "TEXT", 1, 1),
                ("version", "INTEGER", 1, 0),
                ("content", "TEXT", 1, 0),
                ("content_sha256", "TEXT", 1, 0),
            ),
        }
        for table, expected in expected_columns.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            observed = tuple(
                (
                    str(row["name"]),
                    str(row["type"]).upper(),
                    int(row["notnull"]),
                    int(row["pk"]),
                )
                for row in rows
            )
            if observed != expected:
                raise ProviderMemorySchemaError(
                    f"Provider memory table {table!r} has unknown or changed fields"
                )

        rows = connection.execute(
            f"SELECT key, value FROM {_METADATA_TABLE} ORDER BY key"
        ).fetchall()
        metadata = {str(row["key"]): str(row["value"]) for row in rows}
        expected_keys = {"run_id", "schema_version"}
        if set(metadata) != expected_keys or len(rows) != len(expected_keys):
            raise ProviderMemorySchemaError(
                "Provider memory metadata contains missing or unknown fields"
            )
        if metadata["schema_version"] != PROVIDER_MEMORY_SCHEMA_VERSION:
            raise ProviderMemorySchemaError(
                "Provider memory schema version is unsupported"
            )
        if metadata["run_id"] != self._run_id:
            raise ProviderMemoryIntegrityError(
                "Provider memory database belongs to a different run"
            )

        record_count_row = connection.execute(
            f"SELECT COUNT(*) AS record_count FROM {_RECORDS_TABLE}"
        ).fetchone()
        record_count = (
            record_count_row["record_count"]
            if record_count_row is not None
            else None
        )
        if type(record_count) is not int or not 0 <= record_count <= 1:
            raise ProviderMemoryIntegrityError(
                "Provider memory database must contain at most one "
                "controller record per run"
            )

    def _require_open(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ProviderMemoryValidationError("Provider memory store is closed")
        return self._connection


def _validated_database_path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise ProviderMemoryValidationError(
            "database_path must be a filesystem string or Path"
        )
    if isinstance(value, str) and (not value or value == ":memory:"):
        raise ProviderMemoryValidationError(
            "database_path must identify a durable filesystem database"
        )
    path = Path(value).resolve()
    if path.exists() and path.is_dir():
        raise ProviderMemoryValidationError(
            "database_path must not identify a directory"
        )
    if not path.parent.is_dir():
        raise ProviderMemoryValidationError(
            "database_path parent directory must already exist"
        )
    return path


def _validated_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ProviderMemoryValidationError(
            f"{label} must be a safe 1-80 character identifier"
        )
    return value


def _validated_content(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ProviderMemoryValidationError(
            "Provider memory content must be a non-empty string"
        )
    if len(value.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise ProviderMemoryValidationError(
            f"Provider memory content must be at most {_MAX_CONTENT_BYTES:,} bytes"
        )
    return value


def _validated_version(value: object) -> int:
    if type(value) is not int or value != 1:
        raise ProviderMemoryValidationError(
            "expected_version must be the integer 1 for immutable run memory"
        )
    return value


def _validated_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise ProviderMemoryValidationError(
            f"{label} must be a lowercase 64-character SHA-256 digest"
        )
    return value


def _record_from_row(row: sqlite3.Row) -> ProviderMemoryRecord:
    record_id = row["record_id"]
    version = row["version"]
    content = row["content"]
    content_sha256 = row["content_sha256"]
    if not isinstance(record_id, str) or _SAFE_IDENTIFIER.fullmatch(record_id) is None:
        raise ProviderMemoryIntegrityError(
            "Persisted provider memory record_id is invalid"
        )
    if type(version) is not int or version != 1:
        raise ProviderMemoryIntegrityError(
            "Persisted provider memory version is invalid"
        )
    if not isinstance(content, str) or not content:
        raise ProviderMemoryIntegrityError(
            "Persisted provider memory content is invalid"
        )
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise ProviderMemoryIntegrityError(
            "Persisted provider memory content exceeds the size limit"
        )
    if (
        not isinstance(content_sha256, str)
        or _SHA256_HEX.fullmatch(content_sha256) is None
    ):
        raise ProviderMemoryIntegrityError(
            "Persisted provider memory content hash is invalid"
        )
    return ProviderMemoryRecord(
        record_id=record_id,
        version=version,
        content=content,
        content_sha256=content_sha256,
    )


def _user_schema_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = connection.execute(
        """
        SELECT type, name
        FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    return {(str(row["type"]), str(row["name"])) for row in rows}


def _rollback_if_active(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.execute("ROLLBACK")
