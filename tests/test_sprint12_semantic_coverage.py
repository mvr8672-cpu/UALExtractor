from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ualextractor.compare_output import InputFileMetadata
from ualextractor.compare_semantic import normalize_process_basename
from ualextractor.compare_semantic_sqlite import run_semantic_coverage_sqlite
from ualextractor.main import main


def _record(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "timestamp": "2026-05-04T12:00:00.123456789Z",
        "process": "bluetoothd",
        "pid": 123,
        "subsystem": "com.apple.bluetooth",
        "category": "control",
        "event_type": "log",
        "log_type": "default",
        "message": "Device connected",
    }
    row.update(overrides)
    return row


def _write_jsonl(path: Path, rows: list[dict[str, object]], *, encoding: str = "utf-8") -> None:
    with path.open("w", encoding=encoding, newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_csv(path: Path, rows: list[dict[str, object]], *, encoding: str = "utf-8") -> None:
    fieldnames = [
        "timestamp",
        "process",
        "pid",
        "subsystem",
        "category",
        "event_type",
        "log_type",
        "message",
    ]
    with path.open("w", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _meta(path: Path) -> InputFileMetadata:
    payload = path.read_bytes()
    import hashlib

    return InputFileMetadata(
        path=path,
        detected_format="jsonl",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _run_sqlite(
    tmp_path: Path,
    *,
    reference_rows: list[dict[str, object]],
    ual_rows: list[dict[str, object]],
) -> tuple[Path, Path, object]:
    reference = tmp_path / "reference.jsonl"
    ual = tmp_path / "ual.jsonl"
    _write_jsonl(reference, reference_rows)
    _write_jsonl(ual, ual_rows)
    sqlite_index = tmp_path / "semantic.sqlite3"
    result = run_semantic_coverage_sqlite(
        reference_input=_meta(reference),
        ualextractor_input=_meta(ual),
        reference_format_override="jsonl",
        ualextractor_format_override="jsonl",
        sqlite_db_path=sqlite_index,
    )
    return reference, ual, result


def test_multiplicity_r1_u1_full_coverage(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(tmp_path, reference_rows=[_record()], ual_rows=[_record()])
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.pass_semantic_coverage is True


def test_multiplicity_r1_u5_full_coverage_plus_additional(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record()],
        ual_rows=[_record() for _ in range(5)],
    )
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.ual_additional_occurrences_for_reference_identities == 4
    assert result.pass_semantic_coverage is True


def test_multiplicity_r5_u5_full_coverage(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record() for _ in range(5)],
        ual_rows=[_record() for _ in range(5)],
    )
    assert result.covered_reference_occurrences == 5
    assert result.missing_reference_occurrences == 0
    assert result.pass_semantic_coverage is True


def test_multiplicity_r5_u8_full_coverage_plus_additional(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record() for _ in range(5)],
        ual_rows=[_record() for _ in range(8)],
    )
    assert result.covered_reference_occurrences == 5
    assert result.missing_reference_occurrences == 0
    assert result.ual_additional_occurrences_for_reference_identities == 3
    assert result.pass_semantic_coverage is True


def test_multiplicity_r8_u5_missing_occurrences_fail(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record() for _ in range(8)],
        ual_rows=[_record() for _ in range(5)],
    )
    assert result.covered_reference_occurrences == 5
    assert result.missing_reference_occurrences == 3
    assert result.pass_semantic_coverage is False


def test_duplicate_identical_records_not_classified_as_ambiguity(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record() for _ in range(3)],
        ual_rows=[_record() for _ in range(3)],
    )
    assert result.duplicate_reference_identity_groups == 1
    assert result.missing_reference_occurrences == 0
    assert result.pass_semantic_coverage is True


def test_additional_ualextractor_duplicates_do_not_fail(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record() for _ in range(2)],
        ual_rows=[_record() for _ in range(6)],
    )
    assert result.pass_semantic_coverage is True
    assert result.ual_additional_occurrences_for_reference_identities == 4


def test_timestamp_differences_do_not_change_semantic_coverage(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record(timestamp="2026-05-04T12:00:00.123Z")],
        ual_rows=[_record(timestamp="2026-05-04T12:00:00.124Z")],
    )
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.timestamp_status_different == 1
    assert result.pass_semantic_coverage is True


def test_no_timestamp_prefiltering_needed_for_identity_matching(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record(timestamp="2026-05-04T00:00:00.000Z")],
        ual_rows=[_record(timestamp="2026-05-07T12:34:56.789Z")],
    )
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.pass_semantic_coverage is True


def test_deterministic_output(tmp_path: Path) -> None:
    ref_rows = [_record(message="B"), _record(message="A"), _record(message="A")]
    ual_rows = [_record(message="A"), _record(message="B")]
    _, _, result = _run_sqlite(tmp_path, reference_rows=ref_rows, ual_rows=ual_rows)
    assert result.reference_distinct_identities == 2
    assert result.covered_reference_occurrences == 2
    assert result.missing_reference_occurrences == 1


def test_disk_backed_sqlite_path_is_used(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(tmp_path, reference_rows=[_record()], ual_rows=[_record()])
    assert result.sqlite_db_path.exists()
    assert result.sqlite_db_size_bytes > 0


def test_compare_command_reuses_sqlite_index_when_requested(tmp_path: Path) -> None:
    reference = tmp_path / "reference.jsonl"
    ual = tmp_path / "ual.jsonl"
    _write_jsonl(reference, [_record()])
    _write_jsonl(ual, [_record(), _record(message="extra")])
    sqlite_index = tmp_path / "shared-index.sqlite3"

    out1 = tmp_path / "out1"
    exit_1 = main(
        [
            "compare-semantic",
            "--reference",
            str(reference),
            "--ualextractor",
            str(ual),
            "--output",
            str(out1),
            "--sqlite-index",
            str(sqlite_index),
        ]
    )
    assert exit_1 == 0
    summary_1 = json.loads((out1 / "semantic_coverage_summary.json").read_text(encoding="utf-8"))
    assert summary_1["sqlite_index"]["reused"] is False

    out2 = tmp_path / "out2"
    exit_2 = main(
        [
            "compare-semantic",
            "--reference",
            str(reference),
            "--ualextractor",
            str(ual),
            "--output",
            str(out2),
            "--sqlite-index",
            str(sqlite_index),
        ]
    )
    assert exit_2 == 0
    summary_2 = json.loads((out2 / "semantic_coverage_summary.json").read_text(encoding="utf-8"))
    assert summary_2["sqlite_index"]["reused"] is True


def test_existing_sprint11_compare_command_behavior_remains_available(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    _write_jsonl(left, [_record()])
    _write_jsonl(right, [_record()])
    output = tmp_path / "compare-output"
    exit_code = main(
        [
            "compare",
            "--left",
            str(left),
            "--right",
            str(right),
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0
    assert (output / "comparison_summary.txt").exists()


def test_semantic_coverage_accepts_bom_csv_reference(tmp_path: Path) -> None:
    reference = tmp_path / "reference.csv"
    ual = tmp_path / "ual.jsonl"
    _write_csv(
        reference,
        [_record(process="ProcessΩ", message="Device β")],
        encoding="utf-8-sig",
    )
    _write_jsonl(ual, [_record(process="ProcessΩ", message="Device β")])

    result = run_semantic_coverage_sqlite(
        reference_input=_meta(reference),
        ualextractor_input=_meta(ual),
        reference_format_override="csv",
        ualextractor_format_override="jsonl",
        sqlite_db_path=tmp_path / "bom-semantic.sqlite3",
    )
    assert result.pass_semantic_coverage is True
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.reference_invalid_records == 0


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:\\Program Files\\App\\proc.exe", "proc.exe"),
        (r"C:/Program Files/App/proc.exe", "proc.exe"),
        ("/usr/local/bin/proc", "proc"),
        ("proc.exe", "proc.exe"),
        ("proc", "proc"),
        ("例\\proc.exe", "proc.exe"),
        ("例/proc.exe", "proc.exe"),
    ],
)
def test_semantic_process_basename_normalization_is_cross_platform_and_deterministic(
    value: str, expected: str
) -> None:
    assert normalize_process_basename(value) == expected


def test_semantic_compare_matches_windows_absolute_and_bare_process_names(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[
            _record(process="C:\\Program Files\\App\\proc.exe", message="Hallo β"),
            _record(process="proc.exe", message="Tweede regel"),
        ],
        ual_rows=[
            _record(process="proc.exe", message="Hallo β"),
            _record(process="C:\\Somewhere\\proc.exe", message="Tweede regel"),
            _record(process="other.exe", message="extra UAL record"),
        ],
    )
    assert result.reference_records == 2
    assert result.reference_invalid_records == 0
    assert result.ualextractor_records == 3
    assert result.ualextractor_invalid_records == 0
    assert result.strict_semantic_matches == 2
    assert result.missing_reference_occurrences == 0
    assert result.coverage_percentage == 100.0
    assert result.pass_semantic_coverage is True


def test_semantic_coverage_accepts_bom_jsonl_reference_and_ual(tmp_path: Path) -> None:
    reference = tmp_path / "reference.jsonl"
    ual = tmp_path / "ual.jsonl"
    _write_jsonl(
        reference,
        [_record(process="proc.exe", message="Hallo β")],
        encoding="utf-8-sig",
    )
    _write_jsonl(
        ual,
        [_record(process=r"C:\\Somewhere\\proc.exe", message="Hallo β")],
        encoding="utf-8-sig",
    )

    result = run_semantic_coverage_sqlite(
        reference_input=_meta(reference),
        ualextractor_input=_meta(ual),
        reference_format_override="jsonl",
        ualextractor_format_override="jsonl",
        sqlite_db_path=tmp_path / "bom-jsonl-semantic.sqlite3",
    )
    assert result.pass_semantic_coverage is True
    assert result.covered_reference_occurrences == 1
    assert result.missing_reference_occurrences == 0
    assert result.reference_invalid_records == 0
    assert result.ualextractor_invalid_records == 0


def test_context_present_message_difference_is_reported_without_becoming_strict_match(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record(message="Device connected")],
        ual_rows=[_record(message="Device disconnected")],
    )
    assert result.covered_reference_occurrences == 0
    assert result.missing_reference_occurrences == 1
    assert result.context_present_message_different_occurrences == 1
    assert result.result_model["STRICT_SEMANTIC_MATCH"] == 0
    assert result.result_model["MISSING_REFERENCE_OCCURRENCE"] == 1
    assert result.result_model["REPRESENTATION_DIFFERENCE_CONTEXT_PRESENT"] == 1


def test_invalid_reference_records_report_separate_result_model(tmp_path: Path) -> None:
    reference = tmp_path / "reference.jsonl"
    ual = tmp_path / "ual.jsonl"
    _write_jsonl(reference, [{"timestamp": "2026-05-04T12:00:00Z", "process": "bluetoothd", "pid": "bad", "subsystem": "com.apple.bluetooth", "category": "control", "event_type": "log", "log_type": "default", "message": "Device connected"}])
    _write_jsonl(ual, [_record()])
    result = run_semantic_coverage_sqlite(
        reference_input=_meta(reference),
        ualextractor_input=_meta(ual),
        reference_format_override="jsonl",
        ualextractor_format_override="jsonl",
        sqlite_db_path=tmp_path / "invalid.sqlite3",
    )
    assert result.reference_invalid_records == 1
    assert result.result_model["INVALID_REFERENCE"] == 1
    assert result.pass_semantic_coverage is False


def test_exact_message_equality_is_not_fuzzy_or_substring_based(tmp_path: Path) -> None:
    _, _, result = _run_sqlite(
        tmp_path,
        reference_rows=[_record(message="Device connected")],
        ual_rows=[_record(message="Device connected and more")],
    )
    assert result.covered_reference_occurrences == 0
    assert result.missing_reference_occurrences == 1
    assert result.pass_semantic_coverage is False
