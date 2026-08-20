from __future__ import annotations

import csv
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from ualextractor.compare_output import InputFileMetadata
from ualextractor.compare_semantic_sqlite import SemanticCoverageSqliteResult

OUTPUT_FILENAMES = (
    "semantic_coverage_summary.txt",
    "semantic_coverage_summary.json",
    "semantic_identity_multiplicity.csv",
    "semantic_missing_identities.csv",
    "semantic_reference_invalid.csv",
    "semantic_ualextractor_invalid.csv",
)


def _normalize_csv_value(value: Any) -> Any:
    if value is None:
        return ""
    return value


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _normalize_csv_value(row.get(key, "")) for key in fields})


_IDENTITY_FIELDS = [
    "message",
    "process_basename",
    "pid",
    "subsystem",
    "category",
    "reference_count",
    "ual_count",
    "covered_count",
    "missing_count",
    "additional_ual_count",
]


def _identity_row_iter(conn: sqlite3.Connection):
    query = """
        SELECT
            r.message,
            r.process_basename,
            r.pid,
            r.subsystem,
            r.category,
            r.count AS reference_count,
            COALESCE(u.count, 0) AS ual_count
        FROM ref_counts r
        LEFT JOIN ual_counts u
            ON r.message = u.message
           AND ((r.process_basename = u.process_basename) OR (r.process_basename IS NULL AND u.process_basename IS NULL))
           AND r.pid = u.pid
           AND ((r.subsystem = u.subsystem) OR (r.subsystem IS NULL AND u.subsystem IS NULL))
           AND ((r.category = u.category) OR (r.category IS NULL AND u.category IS NULL))
        ORDER BY r.message, r.process_basename, r.pid, r.subsystem, r.category
    """
    for row in conn.execute(query):
        reference_count = int(row[5])
        ual_count = int(row[6])
        covered = min(reference_count, ual_count)
        missing = max(reference_count - ual_count, 0)
        additional = max(ual_count - reference_count, 0)
        yield {
            "message": row[0],
            "process_basename": row[1],
            "pid": row[2],
            "subsystem": row[3],
            "category": row[4],
            "reference_count": reference_count,
            "ual_count": ual_count,
            "covered_count": covered,
            "missing_count": missing,
            "additional_ual_count": additional,
        }


def _build_invalid_rows(conn: sqlite3.Connection, table_name: str) -> list[dict[str, Any]]:
    rows = []
    for row in conn.execute(
        f"SELECT source_row_number, invalid_reason, invalid_field, invalid_detail FROM {table_name} ORDER BY source_row_number"
    ):
        rows.append(
            {
                "source_row_number": row[0],
                "invalid_reason": row[1],
                "invalid_field": row[2],
                "invalid_detail": row[3],
            }
        )
    return rows


def _summary_json(
    *,
    result: SemanticCoverageSqliteResult,
    reference_input: InputFileMetadata,
    ualextractor_input: InputFileMetadata,
) -> dict[str, Any]:
    return {
        "reference_input": {
            "path": str(reference_input.path.resolve()),
            "format": reference_input.detected_format,
            "size_bytes": reference_input.size_bytes,
            "sha256": reference_input.sha256,
        },
        "ualextractor_input": {
            "path": str(ualextractor_input.path.resolve()),
            "format": ualextractor_input.detected_format,
            "size_bytes": ualextractor_input.size_bytes,
            "sha256": ualextractor_input.sha256,
        },
        "sqlite_index": {
            "path": str(result.sqlite_db_path),
            "size_bytes": result.sqlite_db_size_bytes,
            "reused": result.ual_index_reused,
            "build_seconds": round(result.ual_index_build_seconds, 6),
            "distinct_ual_identities": result.ual_index_distinct_identities,
        },
        "counts": {
            "reference_records": result.reference_records,
            "ualextractor_records": result.ualextractor_records,
            "reference_valid_records": result.reference_valid_records,
            "ualextractor_valid_records": result.ualextractor_valid_records,
            "reference_invalid_records": result.reference_invalid_records,
            "ualextractor_invalid_records": result.ualextractor_invalid_records,
            "reference_distinct_identities": result.reference_distinct_identities,
            "duplicate_reference_identity_groups": result.duplicate_reference_identity_groups,
            "covered_reference_occurrences": result.covered_reference_occurrences,
            "missing_reference_occurrences": result.missing_reference_occurrences,
            "strict_semantic_matches": result.strict_semantic_matches,
            "context_present_message_different_occurrences": result.context_present_message_different_occurrences,
            "representation_difference_occurrences": result.representation_difference_occurrences,
            "ual_additional_occurrences_for_reference_identities": result.ual_additional_occurrences_for_reference_identities,
            "coverage_percentage": round(result.coverage_percentage, 6),
        },
        "result_model": {
            "STRICT_SEMANTIC_MATCH": int(result.result_model["STRICT_SEMANTIC_MATCH"]),
            "MISSING_REFERENCE_OCCURRENCE": int(result.result_model["MISSING_REFERENCE_OCCURRENCE"]),
            "REPRESENTATION_DIFFERENCE_CONTEXT_PRESENT": int(
                result.result_model["REPRESENTATION_DIFFERENCE_CONTEXT_PRESENT"]
            ),
            "INVALID_REFERENCE": int(result.result_model["INVALID_REFERENCE"]),
            "UAL_ADDITIONAL": int(result.result_model["UAL_ADDITIONAL"]),
        },
        "timestamp_status_counts": {
            "exact": result.timestamp_status_exact,
            "precision_normalized_match": result.timestamp_status_precision_normalized_match,
            "different": result.timestamp_status_different,
            "unknown_not_comparable": result.timestamp_status_unknown_not_comparable,
            "not_paired_multiplicity": result.timestamp_status_not_paired_multiplicity,
        },
        "normalization_rules": list(result.normalization_rules),
        "compare_seconds": round(result.compare_seconds, 6),
        "pass": result.pass_semantic_coverage,
    }


def _summary_text(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    ts = summary["timestamp_status_counts"]
    sqlite_index = summary["sqlite_index"]
    lines = [
        "[Semantic coverage comparison]",
        "UALExtractor semantic multiplicity coverage validation",
        "",
        "[Result model]",
        f"STRICT_SEMANTIC_MATCH = {counts['strict_semantic_matches']}",
        f"MISSING_REFERENCE_OCCURRENCE = {counts['missing_reference_occurrences']}",
        f"REPRESENTATION_DIFFERENCE_CONTEXT_PRESENT = {counts['context_present_message_different_occurrences']}",
        f"INVALID_REFERENCE = {counts['reference_invalid_records']}",
        f"UAL_ADDITIONAL = {counts['ual_additional_occurrences_for_reference_identities']}",
        "",
        "[Reference coverage]",
        f"reference_records = {counts['reference_records']}",
        f"reference_valid_records = {counts['reference_valid_records']}",
        f"reference_invalid_records = {counts['reference_invalid_records']}",
        f"reference_distinct_identities = {counts['reference_distinct_identities']}",
        f"duplicate_reference_identity_groups = {counts['duplicate_reference_identity_groups']}",
        f"covered_reference_occurrences = {counts['covered_reference_occurrences']}",
        f"missing_reference_occurrences = {counts['missing_reference_occurrences']}",
        f"coverage_percentage = {counts['coverage_percentage']:.6f}",
        "",
        "[UALExtractor]",
        f"ualextractor_records = {counts['ualextractor_records']}",
        f"ualextractor_valid_records = {counts['ualextractor_valid_records']}",
        f"ualextractor_invalid_records = {counts['ualextractor_invalid_records']}",
        f"ual_additional_occurrences_for_reference_identities = {counts['ual_additional_occurrences_for_reference_identities']}",
        "",
        "[Timestamp diagnostics]",
        f"exact = {ts['exact']}",
        f"precision_normalized_match = {ts['precision_normalized_match']}",
        f"different = {ts['different']}",
        f"unknown_not_comparable = {ts['unknown_not_comparable']}",
        f"not_paired_multiplicity = {ts['not_paired_multiplicity']}",
        "",
        "[SQLite index]",
        f"path = {sqlite_index['path']}",
        f"size_bytes = {sqlite_index['size_bytes']}",
        f"reused = {'YES' if sqlite_index['reused'] else 'NO'}",
        f"build_seconds = {sqlite_index['build_seconds']:.6f}",
        f"distinct_ual_identities = {sqlite_index['distinct_ual_identities']}",
        "",
        "[Validation]",
        f"PASS = {'YES' if summary['pass'] else 'NO'}",
        "PASS criterion: TOTAL_REFERENCE_MISSING == 0 and REFERENCE_INVALID == 0",
        "UALExtractor additional occurrences do not fail semantic coverage.",
        "",
        "Sprint 11 acceptance principle: compare shared semantic information, not limitations of historical log show --style compact output.",
    ]
    return "\n".join(lines) + "\n"


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_file() or path.is_symlink():
        path.unlink()
        return
    shutil.rmtree(path)


def _publish_staged_directory(*, staging_dir: Path, final_dir: Path, replace_existing: bool) -> None:
    if not final_dir.exists():
        os.replace(staging_dir, final_dir)
        return
    if not replace_existing:
        raise FileExistsError(f"semantic coverage output directory already exists: {final_dir}")
    backup_dir = Path(
        tempfile.mkdtemp(prefix=f".{final_dir.name}.old.", dir=str(final_dir.parent))
    )
    backup_dir.rmdir()
    os.replace(final_dir, backup_dir)
    try:
        os.replace(staging_dir, final_dir)
    except OSError:
        os.replace(backup_dir, final_dir)
        raise
    _remove_tree(backup_dir)


def write_semantic_coverage_package(
    *,
    result: SemanticCoverageSqliteResult,
    reference_input: InputFileMetadata,
    ualextractor_input: InputFileMetadata,
    destination_dir: Path,
    replace_existing: bool = False,
) -> dict[str, Path]:
    final_dir = destination_dir.resolve()
    if final_dir == reference_input.path.resolve() or final_dir == ualextractor_input.path.resolve():
        raise ValueError("destination directory must not match either input file")
    if final_dir.exists() and not final_dir.is_dir():
        raise FileExistsError(f"semantic coverage output directory already exists: {final_dir}")
    if final_dir.exists() and not replace_existing:
        raise FileExistsError(f"semantic coverage output directory already exists: {final_dir}")
    final_dir.parent.mkdir(parents=True, exist_ok=True)

    staging_dir = Path(tempfile.mkdtemp(prefix=f".{final_dir.name}.tmp.", dir=str(final_dir.parent)))
    published = False
    try:
        conn = sqlite3.connect(str(result.sqlite_db_path))
        try:
            ref_invalid_rows = _build_invalid_rows(conn, "ref_invalid")
            ual_invalid_rows = _build_invalid_rows(conn, "ual_invalid")
            identity_all_path = staging_dir / "semantic_identity_multiplicity.csv"
            identity_missing_path = staging_dir / "semantic_missing_identities.csv"
            with identity_all_path.open("w", encoding="utf-8", newline="") as all_handle, identity_missing_path.open("w", encoding="utf-8", newline="") as missing_handle:
                all_writer = csv.DictWriter(all_handle, fieldnames=_IDENTITY_FIELDS)
                missing_writer = csv.DictWriter(missing_handle, fieldnames=_IDENTITY_FIELDS)
                all_writer.writeheader()
                missing_writer.writeheader()
                for row in _identity_row_iter(conn):
                    normalized = {
                        key: _normalize_csv_value(row.get(key, "")) for key in _IDENTITY_FIELDS
                    }
                    all_writer.writerow(normalized)
                    if int(row["missing_count"]) > 0:
                        missing_writer.writerow(normalized)
        finally:
            conn.close()

        _write_csv(
            staging_dir / "semantic_reference_invalid.csv",
            ["source_row_number", "invalid_reason", "invalid_field", "invalid_detail"],
            ref_invalid_rows,
        )
        _write_csv(
            staging_dir / "semantic_ualextractor_invalid.csv",
            ["source_row_number", "invalid_reason", "invalid_field", "invalid_detail"],
            ual_invalid_rows,
        )

        summary = _summary_json(
            result=result,
            reference_input=reference_input,
            ualextractor_input=ualextractor_input,
        )
        (staging_dir / "semantic_coverage_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging_dir / "semantic_coverage_summary.txt").write_text(
            _summary_text(summary),
            encoding="utf-8",
        )

        _publish_staged_directory(
            staging_dir=staging_dir,
            final_dir=final_dir,
            replace_existing=replace_existing,
        )
        published = True
        return {name: final_dir / name for name in OUTPUT_FILENAMES}
    finally:
        if not published and staging_dir.exists():
            _remove_tree(staging_dir)
