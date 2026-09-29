from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from tool_output_lab.provider_memory import (
    PROVIDER_MEMORY_SCHEMA_VERSION,
    ProviderMemoryConflictError,
    ProviderMemoryIntegrityError,
    ProviderMemoryNotFoundError,
    ProviderMemorySchemaError,
    ProviderMemoryValidationError,
    SQLiteRunMemoryStore,
)
from tool_output_lab.utils import sha256_text


class SQLiteRunMemoryStoreTests(unittest.TestCase):
    def test_record_survives_close_and_reopen_in_a_new_context(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run-001.sqlite3"
            first = SQLiteRunMemoryStore(database_path, run_id="run-001")
            written = first.write(
                "controller-record-001",
                "CONTROLLED_ATTACK_RECORD:CANARY-T001",
            )
            first.close()

            second = SQLiteRunMemoryStore(database_path, run_id="run-001")
            read = second.read(
                written.record_id,
                expected_version=written.version,
                expected_content_sha256=written.content_sha256,
            )
            second.close()

            self.assertEqual(read, written)
            self.assertEqual(written.version, 1)
            self.assertEqual(
                written.content_sha256,
                sha256_text(written.content),
            )
            self.assertEqual(
                set(Path(directory).iterdir()),
                {database_path},
            )

    def test_database_path_is_bound_to_exactly_one_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run.sqlite3"
            with SQLiteRunMemoryStore(database_path, run_id="run-001") as store:
                store.write("record-001", "public summary")

            with self.assertRaisesRegex(
                ProviderMemoryIntegrityError,
                "different run",
            ):
                SQLiteRunMemoryStore(database_path, run_id="run-002")

    def test_controller_record_cannot_be_overwritten_or_read_unknown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run.sqlite3"
            with SQLiteRunMemoryStore(database_path, run_id="run-001") as store:
                written = store.write("record-001", "public summary")
                with self.assertRaisesRegex(
                    ProviderMemoryConflictError,
                    "additional write or overwrite",
                ):
                    store.write("record-001", "replacement")
                with self.assertRaisesRegex(
                    ProviderMemoryConflictError,
                    "additional write or overwrite",
                ):
                    store.write("record-002", "second controller record")
                with self.assertRaisesRegex(
                    ProviderMemoryNotFoundError,
                    "Unknown",
                ):
                    store.read(
                        "record-002",
                        expected_version=1,
                        expected_content_sha256=written.content_sha256,
                    )

    def test_extra_injected_record_is_rejected_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run.sqlite3"
            with SQLiteRunMemoryStore(database_path, run_id="run-001") as store:
                store.write("record-001", "public summary")

            injected_content = "injected second record"
            with closing(sqlite3.connect(database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO provider_memory_records
                            (record_id, version, content, content_sha256)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            "record-injected",
                            1,
                            injected_content,
                            sha256_text(injected_content),
                        ),
                    )

            with self.assertRaisesRegex(
                ProviderMemoryIntegrityError,
                "at most one controller record",
            ):
                SQLiteRunMemoryStore(database_path, run_id="run-001")

    def test_persisted_content_or_hash_tampering_fails_closed(self) -> None:
        cases = {
            "content": (
                "UPDATE provider_memory_records SET content = ?",
                ("tampered summary",),
                "persisted content hash",
            ),
            "hash": (
                "UPDATE provider_memory_records SET content_sha256 = ?",
                ("0" * 64,),
                "persisted content hash|unexpected content hash",
            ),
        }
        for label, (statement, arguments, message) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(
                    prefix="provider-memory-"
                ) as directory:
                    database_path = Path(directory) / "run.sqlite3"
                    with SQLiteRunMemoryStore(
                        database_path,
                        run_id="run-001",
                    ) as store:
                        written = store.write("record-001", "public summary")

                    with closing(sqlite3.connect(database_path)) as connection:
                        with connection:
                            connection.execute(statement, arguments)

                    with SQLiteRunMemoryStore(
                        database_path,
                        run_id="run-001",
                    ) as reopened:
                        with self.assertRaisesRegex(
                            ProviderMemoryIntegrityError,
                            message,
                        ):
                            reopened.read(
                                written.record_id,
                                expected_version=written.version,
                                expected_content_sha256=written.content_sha256,
                            )

    def test_expected_version_and_hash_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run.sqlite3"
            with SQLiteRunMemoryStore(database_path, run_id="run-001") as store:
                written = store.write("record-001", "public summary")

                with self.assertRaisesRegex(
                    ProviderMemoryValidationError,
                    "expected_version",
                ):
                    store.read(
                        written.record_id,
                        expected_version=2,
                        expected_content_sha256=written.content_sha256,
                    )
                with self.assertRaisesRegex(
                    ProviderMemoryIntegrityError,
                    "unexpected content hash",
                ):
                    store.read(
                        written.record_id,
                        expected_version=1,
                        expected_content_sha256="0" * 64,
                    )

    def test_persisted_version_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            database_path = Path(directory) / "run.sqlite3"
            with SQLiteRunMemoryStore(database_path, run_id="run-001") as store:
                written = store.write("record-001", "public summary")

            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute("PRAGMA ignore_check_constraints = ON")
                with connection:
                    connection.execute(
                        "UPDATE provider_memory_records SET version = 2"
                    )

            with SQLiteRunMemoryStore(
                database_path,
                run_id="run-001",
            ) as reopened:
                with self.assertRaisesRegex(
                    ProviderMemoryIntegrityError,
                    "Persisted provider memory version is invalid",
                ):
                    reopened.read(
                        written.record_id,
                        expected_version=written.version,
                        expected_content_sha256=written.content_sha256,
                    )

    def test_unknown_schema_or_metadata_fields_fail_closed(self) -> None:
        cases = {
            "column": (
                "ALTER TABLE provider_memory_records ADD COLUMN injected TEXT",
                (),
                "unknown or changed fields",
            ),
            "metadata": (
                "INSERT INTO provider_memory_metadata (key, value) VALUES (?, ?)",
                ("unknown_field", "unexpected"),
                "metadata contains missing or unknown fields",
            ),
            "table": (
                "CREATE TABLE unexpected_table (value TEXT)",
                (),
                "missing or unknown schema objects",
            ),
        }
        for label, (statement, arguments, message) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(
                    prefix="provider-memory-"
                ) as directory:
                    database_path = Path(directory) / "run.sqlite3"
                    with SQLiteRunMemoryStore(
                        database_path,
                        run_id="run-001",
                    ) as store:
                        store.write("record-001", "public summary")

                    with closing(sqlite3.connect(database_path)) as connection:
                        with connection:
                            connection.execute(statement, arguments)

                    with self.assertRaisesRegex(
                        ProviderMemorySchemaError,
                        message,
                    ):
                        SQLiteRunMemoryStore(database_path, run_id="run-001")

    def test_invalid_inputs_and_closed_store_fail_without_creating_extra_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-memory-") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                ProviderMemoryValidationError,
                "durable filesystem database",
            ):
                SQLiteRunMemoryStore(":memory:", run_id="run-001")
            with self.assertRaisesRegex(
                ProviderMemoryValidationError,
                "parent directory",
            ):
                SQLiteRunMemoryStore(
                    root / "missing" / "run.sqlite3",
                    run_id="run-001",
                )

            database_path = root / "run.sqlite3"
            store = SQLiteRunMemoryStore(database_path, run_id="run-001")
            store.close()
            with self.assertRaisesRegex(
                ProviderMemoryValidationError,
                "closed",
            ):
                store.write("record-001", "public summary")

            with closing(sqlite3.connect(database_path)) as connection:
                metadata = dict(
                    connection.execute(
                        "SELECT key, value FROM provider_memory_metadata"
                    ).fetchall()
                )
            self.assertEqual(
                metadata,
                {
                    "run_id": "run-001",
                    "schema_version": PROVIDER_MEMORY_SCHEMA_VERSION,
                },
            )
            self.assertEqual(set(root.iterdir()), {database_path})


if __name__ == "__main__":
    unittest.main()
