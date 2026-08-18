from __future__ import annotations

import csv
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ualextractor.compare import (
    ComparisonResult,
    CanonicalComparisonRecord,
    ExactMatchPair,
    FieldDifferencePair,
    InputFormat,
)

MATCH_FIELDS = [
    "left_row_number",
    "right_row_number",
    "match_classification",
    "left_original_timestamp",
    "right_original_timestamp",
    "left_epoch_ns",
    "right_epoch_ns",
    "process",
    "pid",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
]

DIFFERENCE_FIELDS = [
    "left_row_number",
    "right_row_number",
    "match_classification",
    "left_original_timestamp",
    "right_original_timestamp",
    "left_epoch_ns",
    "right_epoch_ns",
    "process",
    "pid",
    "differing_fields",
    "left_subsystem",
    "right_subsystem",
    "left_category",
    "right_category",
    "left_event_type",
    "right_event_type",
    "left_log_type",
    "right_log_type",
    "left_message",
    "right_message",
]

LEFT_ONLY_FIELDS = [
    "side",
    "source_row_number",
    "classification",
    "original_timestamp",
    "epoch_ns",
    "process",
    "pid",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
    "component",
    "source_trace_path",
]

INVALID_FIELDS = [
    "side",
    "source_row_number",
    "classification",
    "invalid_reason",
    "invalid_field",
    "invalid_detail",
    "original_timestamp",
    "process",
    "original_pid",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
    "component",
    "source_trace_path",
]

OUTPUT_FILENAMES = (
    "comparison_summary.txt",
    "comparison_matches.csv",
    "comparison_left_only.csv",
    "comparison_right_only.csv",
    "comparison_differences.csv",
    "comparison_invalid.csv",
)


@dataclass(frozen=True)
class InputFileMetadata:
    path: Path
    detected_format: str
    size_bytes: int
    sha256: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_value(value: Any) -> Any:
    if value is None:
        return ""
    return value


def _write_csv_rows(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _normalize_value(row.get(key, "")) for key in fieldnames})


def _exact_match_rows(result: ComparisonResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pair in result.exact_matches:
        left = pair.left
        right = pair.right
        rows.append(
            {
                "left_row_number": left.source_record_number,
                "right_row_number": right.source_record_number,
                "match_classification": "EXACT_MATCH",
                "left_original_timestamp": left.original_timestamp_text or "",
                "right_original_timestamp": right.original_timestamp_text or "",
                "left_epoch_ns": left.timestamp_epoch_ns if left.timestamp_epoch_ns is not None else "",
                "right_epoch_ns": right.timestamp_epoch_ns if right.timestamp_epoch_ns is not None else "",
                "process": left.process or right.process or "",
                "pid": left.normalized_pid if left.normalized_pid is not None else "",
                "subsystem": left.subsystem or right.subsystem or "",
                "category": left.category or right.category or "",
                "event_type": left.event_type or right.event_type or "",
                "log_type": left.log_type or right.log_type or "",
                "message": left.message or right.message or "",
            }
        )
    return rows


def _difference_rows(result: ComparisonResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pair in result.field_differences:
        left = pair.left
        right = pair.right
        rows.append(
            {
                "left_row_number": left.source_record_number,
                "right_row_number": right.source_record_number,
                "match_classification": "FIELD_DIFFERENCE",
                "left_original_timestamp": left.original_timestamp_text or "",
                "right_original_timestamp": right.original_timestamp_text or "",
                "left_epoch_ns": left.timestamp_epoch_ns if left.timestamp_epoch_ns is not None else "",
                "right_epoch_ns": right.timestamp_epoch_ns if right.timestamp_epoch_ns is not None else "",
                "process": left.process or right.process or "",
                "pid": left.normalized_pid if left.normalized_pid is not None else "",
                "differing_fields": "|".join(pair.differing_fields),
                "left_subsystem": left.subsystem or "",
                "right_subsystem": right.subsystem or "",
                "left_category": left.category or "",
                "right_category": right.category or "",
                "left_event_type": left.event_type or "",
                "right_event_type": right.event_type or "",
                "left_log_type": left.log_type or "",
                "right_log_type": right.log_type or "",
                "left_message": left.message or "",
                "right_message": right.message or "",
            }
        )
    return rows


def _left_only_rows(result: ComparisonResult) -> list[dict[str, Any]]:
    rows = []
    for record in sorted(result.left_only, key=lambda item: item.source_record_number):
        rows.append(
            {
                "side": "left",
                "source_row_number": record.source_record_number,
                "classification": "LEFT_ONLY",
                "original_timestamp": record.original_timestamp_text or "",
                "epoch_ns": record.timestamp_epoch_ns if record.timestamp_epoch_ns is not None else "",
                "process": record.process or "",
                "pid": record.normalized_pid if record.normalized_pid is not None else "",
                "subsystem": record.subsystem or "",
                "category": record.category or "",
                "event_type": record.event_type or "",
                "log_type": record.log_type or "",
                "message": record.message or "",
                "component": record.component or "",
                "source_trace_path": record.source_trace_path or "",
            }
        )
    return rows


def _right_only_rows(result: ComparisonResult) -> list[dict[str, Any]]:
    rows = []
    for record in sorted(result.right_only, key=lambda item: item.source_record_number):
        rows.append(
            {
                "side": "right",
                "source_row_number": record.source_record_number,
                "classification": "RIGHT_ONLY",
                "original_timestamp": record.original_timestamp_text or "",
                "epoch_ns": record.timestamp_epoch_ns if record.timestamp_epoch_ns is not None else "",
                "process": record.process or "",
                "pid": record.normalized_pid if record.normalized_pid is not None else "",
                "subsystem": record.subsystem or "",
                "category": record.category or "",
                "event_type": record.event_type or "",
                "log_type": record.log_type or "",
                "message": record.message or "",
                "component": record.component or "",
                "source_trace_path": record.source_trace_path or "",
            }
        )
    return rows


def _invalid_rows(result: ComparisonResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in sorted(result.left_invalid, key=lambda item: item.source_record_number):
        rows.append(
            {
                "side": "left",
                "source_row_number": record.source_record_number,
                "classification": "INVALID",
                "invalid_reason": record.invalid_reason or "",
                "invalid_field": record.invalid_field or "",
                "invalid_detail": record.invalid_detail or "",
                "original_timestamp": record.original_timestamp_text or "",
                "process": record.process or "",
                "original_pid": record.original_pid_value if record.original_pid_value is not None else "",
                "subsystem": record.subsystem or "",
                "category": record.category or "",
                "event_type": record.event_type or "",
                "log_type": record.log_type or "",
                "message": record.message or "",
                "component": record.component or "",
                "source_trace_path": record.source_trace_path or "",
            }
        )
    for record in sorted(result.right_invalid, key=lambda item: item.source_record_number):
        rows.append(
            {
                "side": "right",
                "source_row_number": record.source_record_number,
                "classification": "INVALID",
                "invalid_reason": record.invalid_reason or "",
                "invalid_field": record.invalid_field or "",
                "invalid_detail": record.invalid_detail or "",
                "original_timestamp": record.original_timestamp_text or "",
                "process": record.process or "",
                "original_pid": record.original_pid_value if record.original_pid_value is not None else "",
                "subsystem": record.subsystem or "",
                "category": record.category or "",
                "event_type": record.event_type or "",
                "log_type": record.log_type or "",
                "message": record.message or "",
                "component": record.component or "",
                "source_trace_path": record.source_trace_path or "",
            }
        )
    return rows


def _validate_summary_text(result: ComparisonResult) -> str:
    return "PASS" if result.invariants.all_ok else "FAIL"


def _summary_text(
    *,
    result: ComparisonResult,
    left_input: InputFileMetadata,
    right_input: InputFileMetadata,
    output_file_hashes: dict[str, tuple[int, str]],
    start: datetime,
    end: datetime,
) -> str:
    elapsed = (end - start).total_seconds()
    lines = [
        "[Comparison]",
        "UALExtractor comparison",
        f"execution_start = {start.astimezone(timezone.utc).isoformat()}",
        f"execution_end = {end.astimezone(timezone.utc).isoformat()}",
        f"elapsed_seconds = {elapsed:.6f}",
        "",
        "[Left input]",
        f"absolute_path = {left_input.path.resolve()}",
        f"format = {left_input.detected_format}",
        f"size_bytes = {left_input.size_bytes}",
        f"sha256 = {left_input.sha256}",
        "",
        "[Right input]",
        f"absolute_path = {right_input.path.resolve()}",
        f"format = {right_input.detected_format}",
        f"size_bytes = {right_input.size_bytes}",
        f"sha256 = {right_input.sha256}",
        "",
        "Input SHA-256 values authenticate the compared file bytes only; they do not independently authenticate the original evidence.",
        "",
        "[Accounting]",
        f"left_input_records = {result.accounting.left_input_records}",
        f"right_input_records = {result.accounting.right_input_records}",
        f"left_valid_records = {result.accounting.left_valid_records}",
        f"right_valid_records = {result.accounting.right_valid_records}",
        f"left_invalid_records = {result.accounting.left_invalid_records}",
        f"right_invalid_records = {result.accounting.right_invalid_records}",
        f"left_exact_match_records = {result.accounting.left_exact_match_records}",
        f"right_exact_match_records = {result.accounting.right_exact_match_records}",
        f"left_difference_records = {result.accounting.left_difference_records}",
        f"right_difference_records = {result.accounting.right_difference_records}",
        f"left_only_records = {result.accounting.left_only_records}",
        f"right_only_records = {result.accounting.right_only_records}",
        f"left input records: {result.accounting.left_input_records}",
        f"right input records: {result.accounting.right_input_records}",
        f"exact match records: {result.accounting.left_exact_match_records}",
        f"field-difference records: {result.accounting.left_difference_records}",
        f"left-only records: {result.accounting.left_only_records}",
        f"right-only records: {result.accounting.right_only_records}",
        f"left invalid records: {result.accounting.left_invalid_records}",
        f"right invalid records: {result.accounting.right_invalid_records}",
        "",
        "[Duplicate statistics]",
        f"duplicate_key_groups_left = {result.accounting.duplicate_key_groups_left}",
        f"duplicate_key_groups_right = {result.accounting.duplicate_key_groups_right}",
        f"duplicate_records_left = {result.accounting.duplicate_records_left}",
        f"duplicate_records_right = {result.accounting.duplicate_records_right}",
        "",
        "[Validation]",
        f"left_accounting_ok = {'PASS' if result.invariants.left_accounting_ok else 'FAIL'}",
        f"right_accounting_ok = {'PASS' if result.invariants.right_accounting_ok else 'FAIL'}",
        f"left_valid_breakdown_ok = {'PASS' if result.invariants.left_valid_breakdown_ok else 'FAIL'}",
        f"right_valid_breakdown_ok = {'PASS' if result.invariants.right_valid_breakdown_ok else 'FAIL'}",
        f"exact_count_symmetry_ok = {'PASS' if result.invariants.exact_count_symmetry_ok else 'FAIL'}",
        f"difference_count_symmetry_ok = {'PASS' if result.invariants.difference_count_symmetry_ok else 'FAIL'}",
        f"left accounting invariant: {'PASS' if result.invariants.left_accounting_ok else 'FAIL'}",
        f"right accounting invariant: {'PASS' if result.invariants.right_accounting_ok else 'FAIL'}",
        f"left valid-record invariant: {'PASS' if result.invariants.left_valid_breakdown_ok else 'FAIL'}",
        f"right valid-record invariant: {'PASS' if result.invariants.right_valid_breakdown_ok else 'FAIL'}",
        f"left exact count == right exact count: {'PASS' if result.invariants.exact_count_symmetry_ok else 'FAIL'}",
        f"left difference count == right difference count: {'PASS' if result.invariants.difference_count_symmetry_ok else 'FAIL'}",
        f"VALIDATION: {_validate_summary_text(result)}",
        "",
        "[Output integrity]",
    ]
    for filename, (size_bytes, sha256_hex) in output_file_hashes.items():
        if filename == "comparison_summary.txt":
            continue
        lines.append(f"{filename}: size_bytes={size_bytes} sha256={sha256_hex}")
    return "\n".join(lines) + "\n"


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_file() or path.is_symlink():
        path.unlink()
        return
    shutil.rmtree(path)


def _publish_staged_directory(
    *, staging_dir: Path, final_dir: Path, replace_existing: bool
) -> None:
    if not final_dir.exists():
        os.replace(staging_dir, final_dir)
        return
    if not replace_existing:
        raise FileExistsError(f"comparison output directory already exists: {final_dir}")

    backup_dir = Path(
        tempfile.mkdtemp(prefix=f".{final_dir.name}.old.", dir=str(final_dir.parent))
    )
    backup_dir.rmdir()
    os.replace(final_dir, backup_dir)
    try:
        os.replace(staging_dir, final_dir)
    except Exception:
        os.replace(backup_dir, final_dir)
        raise
    _remove_tree(backup_dir)


def write_comparison_package(
    *,
    result: ComparisonResult,
    left_input: InputFileMetadata,
    right_input: InputFileMetadata,
    destination_dir: Path,
    replace_existing: bool = False,
) -> dict[str, Path]:
    final_dir = destination_dir.resolve()
    left_resolved = left_input.path.resolve()
    right_resolved = right_input.path.resolve()
    if final_dir == left_resolved or final_dir == right_resolved:
        raise ValueError("destination directory must not match either input file")
    if final_dir.exists() and not final_dir.is_dir():
        raise FileExistsError(f"comparison output directory already exists: {final_dir}")
    if final_dir.exists() and not replace_existing:
        raise FileExistsError(f"comparison output directory already exists: {final_dir}")
    if not final_dir.parent.exists():
        final_dir.parent.mkdir(parents=True, exist_ok=True)

    staging_dir = Path(
        tempfile.mkdtemp(prefix=f".{final_dir.name}.tmp.", dir=str(final_dir.parent))
    )
    try:
        start = datetime.now(timezone.utc)
        matches_path = staging_dir / "comparison_matches.csv"
        left_only_path = staging_dir / "comparison_left_only.csv"
        right_only_path = staging_dir / "comparison_right_only.csv"
        differences_path = staging_dir / "comparison_differences.csv"
        invalid_path = staging_dir / "comparison_invalid.csv"

        _write_csv_rows(matches_path, MATCH_FIELDS, _exact_match_rows(result))
        _write_csv_rows(differences_path, DIFFERENCE_FIELDS, _difference_rows(result))
        _write_csv_rows(left_only_path, LEFT_ONLY_FIELDS, _left_only_rows(result))
        _write_csv_rows(right_only_path, LEFT_ONLY_FIELDS, _right_only_rows(result))
        _write_csv_rows(invalid_path, INVALID_FIELDS, _invalid_rows(result))

        output_hashes: dict[str, tuple[int, str]] = {}
        for name, path in (
            ("comparison_matches.csv", matches_path),
            ("comparison_left_only.csv", left_only_path),
            ("comparison_right_only.csv", right_only_path),
            ("comparison_differences.csv", differences_path),
            ("comparison_invalid.csv", invalid_path),
        ):
            output_hashes[name] = (path.stat().st_size, file_sha256(path))

        summary_path = staging_dir / "comparison_summary.txt"
        end = datetime.now(timezone.utc)
        summary_text = _summary_text(
            result=result,
            left_input=left_input,
            right_input=right_input,
            output_file_hashes=output_hashes,
            start=start,
            end=end,
        )
        summary_path.write_text(summary_text, encoding="utf-8")

        _publish_staged_directory(
            staging_dir=staging_dir,
            final_dir=final_dir,
            replace_existing=replace_existing,
        )
        package_files = {
            "comparison_summary.txt": final_dir / "comparison_summary.txt",
            "comparison_matches.csv": final_dir / "comparison_matches.csv",
            "comparison_left_only.csv": final_dir / "comparison_left_only.csv",
            "comparison_right_only.csv": final_dir / "comparison_right_only.csv",
            "comparison_differences.csv": final_dir / "comparison_differences.csv",
            "comparison_invalid.csv": final_dir / "comparison_invalid.csv",
        }
        return package_files
    except Exception:
        _remove_tree(staging_dir)
        raise
