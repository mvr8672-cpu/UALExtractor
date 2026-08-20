from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ualextractor.compare_output import InputFileMetadata
from ualextractor.compare_semantic import compare_timestamp_texts, semantic_identity_key
from ualextractor.compare_semantic_io import iterate_semantic_records


@dataclass(frozen=True)
class SemanticCoverageSqliteResult:
    sqlite_db_path: Path
    sqlite_db_size_bytes: int
    ual_index_reused: bool
    ual_index_build_seconds: float
    compare_seconds: float
    ual_index_distinct_identities: int
    reference_records: int
    ualextractor_records: int
    reference_valid_records: int
    ualextractor_valid_records: int
    reference_invalid_records: int
    ualextractor_invalid_records: int
    reference_distinct_identities: int
    duplicate_reference_identity_groups: int
    covered_reference_occurrences: int
    missing_reference_occurrences: int
    ual_additional_occurrences_for_reference_identities: int
    strict_semantic_matches: int = 0
    context_present_message_different_occurrences: int = 0
    representation_difference_occurrences: int = 0
    invalid_reference_occurrences: int = 0
    ual_additional_occurrences: int = 0
    timestamp_status_exact: int = 0
    timestamp_status_precision_normalized_match: int = 0
    timestamp_status_different: int = 0
    timestamp_status_unknown_not_comparable: int = 0
    timestamp_status_not_paired_multiplicity: int = 0
    normalization_rules: tuple[str, ...] = ()

    @property
    def coverage_percentage(self) -> float:
        if self.reference_records == 0:
            return 100.0
        return (self.covered_reference_occurrences / self.reference_records) * 100.0

    @property
    def pass_semantic_coverage(self) -> bool:
        return self.missing_reference_occurrences == 0 and self.reference_invalid_records == 0

    @property
    def result_model(self) -> dict[str, int]:
        return {
            "STRICT_SEMANTIC_MATCH": int(self.strict_semantic_matches or self.covered_reference_occurrences),
            "MISSING_REFERENCE_OCCURRENCE": int(self.missing_reference_occurrences),
            "REPRESENTATION_DIFFERENCE_CONTEXT_PRESENT": int(
                self.context_present_message_different_occurrences
                or self.representation_difference_occurrences
            ),
            "INVALID_REFERENCE": int(self.reference_invalid_records or self.invalid_reference_occurrences),
            "UAL_ADDITIONAL": int(
                self.ual_additional_occurrences_for_reference_identities
                or self.ual_additional_occurrences
            ),
        }


def run_semantic_coverage_sqlite(
    *,
    reference_input: InputFileMetadata,
    ualextractor_input: InputFileMetadata,
    reference_format_override: str | None,
    ualextractor_format_override: str | None,
    sqlite_db_path: Path,
) -> SemanticCoverageSqliteResult:
    sqlite_db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(sqlite_db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        _init_schema(conn)

        ual_reused, ual_build_seconds, ual_total, ual_valid, ual_invalid = _ensure_ual_index(
            conn=conn,
            input_meta=ualextractor_input,
            format_override=ualextractor_format_override,
        )

        compare_start = time.perf_counter()
        ref_total, ref_valid, ref_invalid = _build_reference_counts(
            conn=conn,
            input_meta=reference_input,
            format_override=reference_format_override,
        )
        summary = _calculate_coverage(conn)
        compare_seconds = time.perf_counter() - compare_start

        db_size = sqlite_db_path.stat().st_size if sqlite_db_path.exists() else 0
        normalization_rules = (
            "identity fields: message, basename(process), normalized pid, subsystem, category",
            "process normalization: absolute path is normalized to basename for identity and normalized-equal comparison",
            "nullable text normalization: empty string and null normalize to missing for optional fields",
            "timestamp is secondary diagnostics only and not part of semantic identity",
        )
        return SemanticCoverageSqliteResult(
            sqlite_db_path=sqlite_db_path,
            sqlite_db_size_bytes=db_size,
            ual_index_reused=ual_reused,
            ual_index_build_seconds=ual_build_seconds,
            compare_seconds=compare_seconds,
            ual_index_distinct_identities=summary["ual_index_distinct_identities"],
            reference_records=ref_total,
            ualextractor_records=ual_total,
            reference_valid_records=ref_valid,
            ualextractor_valid_records=ual_valid,
            reference_invalid_records=ref_invalid,
            ualextractor_invalid_records=ual_invalid,
            reference_distinct_identities=summary["reference_distinct_identities"],
            duplicate_reference_identity_groups=summary["duplicate_reference_identity_groups"],
            covered_reference_occurrences=summary["covered_reference_occurrences"],
            missing_reference_occurrences=summary["missing_reference_occurrences"],
            ual_additional_occurrences_for_reference_identities=summary[
                "ual_additional_occurrences_for_reference_identities"
            ],
            strict_semantic_matches=summary["strict_semantic_matches"],
            context_present_message_different_occurrences=summary["context_present_message_different_occurrences"],
            representation_difference_occurrences=summary["representation_difference_occurrences"],
            invalid_reference_occurrences=summary["invalid_reference_occurrences"],
            ual_additional_occurrences=summary["ual_additional_occurrences"],
            timestamp_status_exact=summary["timestamp_status_exact"],
            timestamp_status_precision_normalized_match=summary[
                "timestamp_status_precision_normalized_match"
            ],
            timestamp_status_different=summary["timestamp_status_different"],
            timestamp_status_unknown_not_comparable=summary[
                "timestamp_status_unknown_not_comparable"
            ],
            timestamp_status_not_paired_multiplicity=summary[
                "timestamp_status_not_paired_multiplicity"
            ],
            normalization_rules=normalization_rules,
        )
    finally:
        conn.close()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ual_counts (
            message TEXT NOT NULL,
            process_basename TEXT,
            pid INTEGER NOT NULL,
            subsystem TEXT,
            category TEXT,
            count INTEGER NOT NULL,
            rep_timestamp TEXT,
            PRIMARY KEY (message, process_basename, pid, subsystem, category)
        );

        CREATE TABLE IF NOT EXISTS ual_invalid (
            source_row_number INTEGER NOT NULL,
            invalid_reason TEXT,
            invalid_field TEXT,
            invalid_detail TEXT
        );

        CREATE TABLE IF NOT EXISTS ref_counts (
            message TEXT NOT NULL,
            process_basename TEXT,
            pid INTEGER NOT NULL,
            subsystem TEXT,
            category TEXT,
            count INTEGER NOT NULL,
            rep_timestamp TEXT,
            PRIMARY KEY (message, process_basename, pid, subsystem, category)
        );

        CREATE TABLE IF NOT EXISTS ref_invalid (
            source_row_number INTEGER NOT NULL,
            invalid_reason TEXT,
            invalid_field TEXT,
            invalid_detail TEXT
        );
        """
    )


def _get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def _set_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def _ensure_ual_index(
    *,
    conn: sqlite3.Connection,
    input_meta: InputFileMetadata,
    format_override: str | None,
) -> tuple[bool, float, int, int, int]:
    expected = {
        "ual_input_path": str(input_meta.path.resolve()),
        "ual_input_sha256": input_meta.sha256,
        "ual_input_size": str(input_meta.size_bytes),
        "ual_input_format": input_meta.detected_format,
    }
    reusable = all(_get_meta(conn, key) == value for key, value in expected.items())
    if reusable:
        total = int(_get_meta(conn, "ual_total_records") or "0")
        valid = int(_get_meta(conn, "ual_valid_records") or "0")
        invalid = int(_get_meta(conn, "ual_invalid_records") or "0")
        return True, 0.0, total, valid, invalid

    build_start = time.perf_counter()
    conn.execute("DELETE FROM ual_counts")
    conn.execute("DELETE FROM ual_invalid")

    total = 0
    valid = 0
    invalid = 0
    _, records = iterate_semantic_records(
        path=input_meta.path,
        side="ualextractor",
        format_override=format_override,
    )
    for record in records:
        total += 1
        if not record.is_valid:
            invalid += 1
            conn.execute(
                "INSERT INTO ual_invalid(source_row_number, invalid_reason, invalid_field, invalid_detail) VALUES(?, ?, ?, ?)",
                (
                    record.source_record_number,
                    record.invalid_reason,
                    record.invalid_field,
                    record.invalid_detail,
                ),
            )
            continue

        valid += 1
        key = semantic_identity_key(record)
        assert key is not None
        conn.execute(
            """
            INSERT INTO ual_counts(message, process_basename, pid, subsystem, category, count, rep_timestamp)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(message, process_basename, pid, subsystem, category) DO UPDATE SET
                count = count + 1,
                rep_timestamp = COALESCE(ual_counts.rep_timestamp, excluded.rep_timestamp)
            """,
            (*key, record.timestamp_text),
        )
        if total % 50_000 == 0:
            conn.commit()

    for key, value in expected.items():
        _set_meta(conn, key, value)
    _set_meta(conn, "ual_total_records", total)
    _set_meta(conn, "ual_valid_records", valid)
    _set_meta(conn, "ual_invalid_records", invalid)
    conn.commit()
    return False, time.perf_counter() - build_start, total, valid, invalid


def _build_reference_counts(
    *,
    conn: sqlite3.Connection,
    input_meta: InputFileMetadata,
    format_override: str | None,
) -> tuple[int, int, int]:
    conn.execute("DELETE FROM ref_counts")
    conn.execute("DELETE FROM ref_invalid")
    conn.commit()

    total = 0
    valid = 0
    invalid = 0
    _, records = iterate_semantic_records(
        path=input_meta.path,
        side="reference",
        format_override=format_override,
    )
    for record in records:
        total += 1
        if not record.is_valid:
            invalid += 1
            conn.execute(
                "INSERT INTO ref_invalid(source_row_number, invalid_reason, invalid_field, invalid_detail) VALUES(?, ?, ?, ?)",
                (
                    record.source_record_number,
                    record.invalid_reason,
                    record.invalid_field,
                    record.invalid_detail,
                ),
            )
            continue

        valid += 1
        key = semantic_identity_key(record)
        assert key is not None
        conn.execute(
            """
            INSERT INTO ref_counts(message, process_basename, pid, subsystem, category, count, rep_timestamp)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(message, process_basename, pid, subsystem, category) DO UPDATE SET
                count = count + 1,
                rep_timestamp = COALESCE(ref_counts.rep_timestamp, excluded.rep_timestamp)
            """,
            (*key, record.timestamp_text),
        )
        if total % 20_000 == 0:
            conn.commit()
    conn.commit()
    return total, valid, invalid


def _calculate_coverage(conn: sqlite3.Connection) -> dict[str, int]:
    reference_distinct_identities = int(conn.execute("SELECT COUNT(*) FROM ref_counts").fetchone()[0])
    duplicate_reference_identity_groups = int(
        conn.execute("SELECT COUNT(*) FROM ref_counts WHERE count > 1").fetchone()[0]
    )
    ual_index_distinct_identities = int(conn.execute("SELECT COUNT(*) FROM ual_counts").fetchone()[0])

    covered_total = 0
    missing_total = 0
    additional_total = 0
    strict_match_total = 0
    context_present_diagnostic_total = 0
    representation_difference_total = 0
    ual_additional_total = 0
    ts_exact = 0
    ts_precision = 0
    ts_diff = 0
    ts_unknown = 0
    ts_not_paired = 0
    exact_match_by_identity: dict[tuple[str | None, str | None, int, str | None, str | None], int] = {}
    context_message_difference_by_identity: dict[tuple[str | None, str | None, int, str | None, str | None], int] = {}

    query = """
        SELECT
            r.count AS reference_count,
            COALESCE(u.count, 0) AS ual_count,
            r.rep_timestamp AS reference_timestamp,
            u.rep_timestamp AS ual_timestamp,
            r.message,
            r.process_basename,
            r.pid,
            r.subsystem,
            r.category
        FROM ref_counts r
        LEFT JOIN ual_counts u
            ON r.message = u.message
           AND ((r.process_basename = u.process_basename) OR (r.process_basename IS NULL AND u.process_basename IS NULL))
           AND r.pid = u.pid
           AND ((r.subsystem = u.subsystem) OR (r.subsystem IS NULL AND u.subsystem IS NULL))
           AND ((r.category = u.category) OR (r.category IS NULL AND u.category IS NULL))
    """
    for row in conn.execute(query):
        exact_key = (
            row[4],
            row[5],
            int(row[6]),
            row[7],
            row[8],
        )
        exact_match_by_identity[exact_key] = min(int(row[0]), int(row[1]))

    context_query = """
        SELECT
            r.message,
            r.process_basename,
            r.pid,
            r.subsystem,
            r.category,
            r.count,
            COUNT(DISTINCT u.message) AS different_message_candidates
        FROM ref_counts r
        LEFT JOIN ual_counts u
            ON ((r.process_basename = u.process_basename) OR (r.process_basename IS NULL AND u.process_basename IS NULL))
           AND r.pid = u.pid
           AND ((r.subsystem = u.subsystem) OR (r.subsystem IS NULL AND u.subsystem IS NULL))
           AND ((r.category = u.category) OR (r.category IS NULL AND u.category IS NULL))
           AND r.message <> u.message
        GROUP BY r.message, r.process_basename, r.pid, r.subsystem, r.category, r.count
    """
    for row in conn.execute(context_query):
        context_key = (row[0], row[1], int(row[2]), row[3], row[4])
        ref_count = int(row[5])
        different_count = int(row[6] or 0)
        if different_count > 0:
            context_message_difference_by_identity[context_key] = max(ref_count - exact_match_by_identity.get(context_key, 0), 0)

    for row in conn.execute(query):
        ref_count = int(row[0])
        ual_count = int(row[1])
        covered = min(ref_count, ual_count)
        missing = max(ref_count - ual_count, 0)
        additional = max(ual_count - ref_count, 0)
        covered_total += covered
        missing_total += missing
        additional_total += additional
        strict_match_total += covered

        identity_key = (row[4], row[5], int(row[6]), row[7], row[8])
        if context_message_difference_by_identity.get(identity_key, 0) > 0:
            context_present_diagnostic_total += context_message_difference_by_identity[identity_key]
            representation_difference_total += context_message_difference_by_identity[identity_key]

        if ual_count > 0:
            ual_additional_total += additional

        if covered == 0:
            continue
        if ref_count == 1 and ual_count == 1:
            status = compare_timestamp_texts(row[2], row[3])
            if status == "exact":
                ts_exact += 1
            elif status == "precision_normalized_match":
                ts_precision += 1
            elif status == "different":
                ts_diff += 1
            else:
                ts_unknown += 1
        else:
            ts_not_paired += covered

    return {
        "reference_distinct_identities": reference_distinct_identities,
        "duplicate_reference_identity_groups": duplicate_reference_identity_groups,
        "ual_index_distinct_identities": ual_index_distinct_identities,
        "covered_reference_occurrences": covered_total,
        "missing_reference_occurrences": missing_total,
        "ual_additional_occurrences_for_reference_identities": additional_total,
        "strict_semantic_matches": strict_match_total,
        "context_present_message_different_occurrences": context_present_diagnostic_total,
        "representation_difference_occurrences": representation_difference_total,
        "invalid_reference_occurrences": 0,
        "ual_additional_occurrences": ual_additional_total,
        "timestamp_status_exact": ts_exact,
        "timestamp_status_precision_normalized_match": ts_precision,
        "timestamp_status_different": ts_diff,
        "timestamp_status_unknown_not_comparable": ts_unknown,
        "timestamp_status_not_paired_multiplicity": ts_not_paired,
    }
