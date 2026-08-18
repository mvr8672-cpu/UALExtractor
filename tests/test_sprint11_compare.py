import csv
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ualextractor.compare import ComparisonInvariantResult
from ualextractor.filtering import _parse_timestamp_to_epoch_ns
from ualextractor.main import main


REQUIRED_COMPARE_FIELDS = [
    "timestamp",
    "process",
    "pid",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
]

EXPECTED_COMPARISON_FILES = {
    "comparison_summary.txt",
    "comparison_matches.csv",
    "comparison_left_only.csv",
    "comparison_right_only.csv",
    "comparison_differences.csv",
    "comparison_invalid.csv",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict[str, object]], *, header: list[str] | None = None) -> None:
    if header is None:
        fieldnames = list(REQUIRED_COMPARE_FIELDS)
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    else:
        fieldnames = header
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_jsonl(path: Path, rows: list[object]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _comparison_paths(output_dir: Path) -> dict[str, Path]:
    return {name: output_dir / name for name in EXPECTED_COMPARISON_FILES}


def _assert_expected_package_exists(output_dir: Path) -> dict[str, Path]:
    paths = _comparison_paths(output_dir)
    assert output_dir.is_dir()
    assert {path.name for path in output_dir.iterdir()} == EXPECTED_COMPARISON_FILES
    for path in paths.values():
        assert path.exists()
    return paths


def _compare_args(
    left: Path,
    right: Path,
    *,
    output_dir: Path | None = None,
    downloads: bool = False,
    dry_run: bool = False,
    force: bool = False,
    left_format: str | None = None,
    right_format: str | None = None,
) -> list[str]:
    args = ["compare", "--left", str(left), "--right", str(right)]
    if left_format is not None:
        args.extend(["--left-format", left_format])
    if right_format is not None:
        args.extend(["--right-format", right_format])
    if output_dir is not None:
        args.extend(["--output", str(output_dir)])
    if downloads:
        args.append("--downloads")
    if dry_run:
        args.append("--dry-run")
    if force:
        args.append("--force")
    return args


def _minimal_record(
    *,
    timestamp: str = "2026-05-04T12:00:00.123456701Z",
    process: str = "bluetoothd",
    pid: object = 123,
    subsystem: str = "com.apple.bluetooth",
    category: str = "control",
    event_type: str = "log",
    log_type: str = "default",
    message: str = "Device connected",
    component: str | None = None,
    source_trace_path: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": timestamp,
        "process": process,
        "pid": pid,
        "subsystem": subsystem,
        "category": category,
        "event_type": event_type,
        "log_type": log_type,
        "message": message,
    }
    if component is not None:
        record["component"] = component
    if source_trace_path is not None:
        record["source_trace_path"] = source_trace_path
    return record


def test_compare_reuses_ns_parser_for_equivalent_positive_offset_instants() -> None:
    assert _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456701Z") == _parse_timestamp_to_epoch_ns(
        "2026-05-04T14:00:00.123456701+02:00"
    )


def test_compare_reuses_ns_parser_for_equivalent_negative_offset_instants() -> None:
    assert _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456701Z") == _parse_timestamp_to_epoch_ns(
        "2026-05-04T07:00:00.123456701-05:00"
    )


def test_compare_reuses_ns_parser_for_equivalent_half_hour_offset_instants() -> None:
    assert _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456701Z") == _parse_timestamp_to_epoch_ns(
        "2026-05-04T17:30:00.123456701+05:30"
    )


def test_compare_reuses_ns_parser_distinguishes_one_nanosecond() -> None:
    earlier = _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456700Z")
    later = _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456701Z")
    assert later - earlier == 1


def test_compare_reuses_ns_parser_rejects_malformed_timestamp() -> None:
    with pytest.raises(ValueError, match="invalid timestamp format"):
        _parse_timestamp_to_epoch_ns("2026-05-04 not-a-time")


def test_compare_reuses_ns_parser_rejects_more_than_nine_fractional_digits() -> None:
    with pytest.raises(ValueError, match="fractional precision exceeds 9 digits"):
        _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.1234567891Z")


def test_compare_requires_explicit_output_or_downloads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "either --output DIR or --downloads is required" in captured.err


def test_compare_rejects_output_and_downloads_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right, output_dir=tmp_path / "comparison", downloads=True))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "exactly one of --output DIR or --downloads must be supplied" in captured.err


def test_compare_dry_run_hashes_inputs_reports_formats_and_creates_no_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_jsonl(right, [_minimal_record()])

    assert main(
        _compare_args(
            left,
            right,
            output_dir=output_dir,
            dry_run=True,
            right_format="jsonl",
        )
    ) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"Left input: {left.resolve()}" in captured.err
    assert f"Right input: {right.resolve()}" in captured.err
    assert f"Left size bytes: {left.stat().st_size}" in captured.err
    assert f"Right size bytes: {right.stat().st_size}" in captured.err
    assert f"Left SHA-256: {_sha256(left)}" in captured.err
    assert f"Right SHA-256: {_sha256(right)}" in captured.err
    assert "Left detected format: csv" in captured.err
    assert "Right detected format: jsonl" in captured.err
    assert "Left structural validity: PASS" in captured.err
    assert "Right structural validity: PASS" in captured.err
    assert f"Proposed output directory: {output_dir.resolve()}" in captured.err
    assert not output_dir.exists()


def test_compare_dry_run_rejects_missing_required_csv_column(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    header = [field for field in REQUIRED_COMPARE_FIELDS if field != "message"]
    _write_csv(
        left,
        [{key: value for key, value in _minimal_record().items() if key in header}],
        header=header,
    )
    _write_csv(right, [_minimal_record()])

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right, output_dir=output_dir, dry_run=True))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "missing required column" in captured.err
    assert "message" in captured.err
    assert not output_dir.exists()


def test_compare_dry_run_leaves_inputs_untouched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.jsonl"
    _write_csv(left, [_minimal_record(message="left source text")])
    _write_jsonl(right, [_minimal_record(message="right source text")])
    left_before = left.read_bytes()
    right_before = right.read_bytes()

    assert main(
        _compare_args(
            left,
            right,
            output_dir=tmp_path / "comparison",
            dry_run=True,
            right_format="jsonl",
        )
    ) == 0
    capsys.readouterr()

    assert left.read_bytes() == left_before
    assert right.read_bytes() == right_before


def test_compare_csv_vs_csv_exact_match_writes_expected_package(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    matches = _read_csv_rows(paths["comparison_matches.csv"])
    assert len(matches) == 1
    assert matches[0]["match_classification"] == "EXACT_MATCH"


def test_compare_jsonl_vs_jsonl_exact_match_writes_expected_package(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    _write_jsonl(left, [_minimal_record()])
    _write_jsonl(right, [_minimal_record()])

    assert main(
        _compare_args(
            left,
            right,
            output_dir=output_dir,
            left_format="jsonl",
            right_format="jsonl",
        )
    ) == 0

    paths = _assert_expected_package_exists(output_dir)
    matches = _read_csv_rows(paths["comparison_matches.csv"])
    assert len(matches) == 1


def test_compare_csv_vs_jsonl_exact_match(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_jsonl(right, [_minimal_record()])

    assert main(
        _compare_args(left, right, output_dir=output_dir, right_format="jsonl")
    ) == 0

    paths = _assert_expected_package_exists(output_dir)
    assert len(_read_csv_rows(paths["comparison_matches.csv"])) == 1


def test_compare_treats_missing_required_row_value_as_invalid(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    left_record = _minimal_record()
    left_record.pop("message")
    _write_jsonl(left, [left_record])
    _write_csv(right, [_minimal_record()])

    assert main(
        _compare_args(left, right, output_dir=output_dir, left_format="jsonl")
    ) == 0

    paths = _assert_expected_package_exists(output_dir)
    invalid_rows = _read_csv_rows(paths["comparison_invalid.csv"])
    assert len(invalid_rows) == 1
    assert invalid_rows[0]["side"] == "left"
    assert invalid_rows[0]["invalid_reason"] == "missing_required_value"


def test_compare_treats_empty_string_required_value_as_distinct_invalid(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [{**_minimal_record(), "message": ""}])
    _write_csv(right, [_minimal_record()])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    differences = _read_csv_rows(paths["comparison_differences.csv"])
    assert len(differences) == 1
    assert differences[0]["differing_fields"] == "message"
    assert differences[0]["left_message"] == ""
    assert differences[0]["right_message"] == "Device connected"


def test_compare_preserves_utf8_and_leaves_source_files_unchanged(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    record = _minimal_record(process="例", message='He said "hello"\nβluetooth')
    _write_csv(left, [record])
    _write_csv(right, [record])
    left_before = left.read_bytes()
    right_before = right.read_bytes()

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    matches = _read_csv_rows(paths["comparison_matches.csv"])
    assert matches[0]["process"] == "例"
    assert 'He said "hello"' in matches[0]["message"]
    assert "βluetooth" in matches[0]["message"]
    assert left.read_bytes() == left_before
    assert right.read_bytes() == right_before


def test_compare_preserves_message_case_whitespace_and_unicode_without_normalization(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    left_record = _minimal_record(message="Bluetooth  Device", process="ProcessΩ")
    right_record = _minimal_record(message="bluetooth device", process="ProcessΩ")
    _write_csv(left, [left_record])
    _write_csv(right, [right_record])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    assert _read_csv_rows(paths["comparison_matches.csv"]) == []
    differences = _read_csv_rows(paths["comparison_differences.csv"])
    assert len(differences) == 1
    assert differences[0]["differing_fields"] == "message"
    assert differences[0]["left_message"] == "Bluetooth  Device"
    assert differences[0]["right_message"] == "bluetooth device"
    assert differences[0]["process"] == "ProcessΩ"


def test_compare_excludes_provenance_from_exact_identity(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    _write_csv(
        left,
        [
            _minimal_record(
                component="Persist",
                source_trace_path="/left/tracev3/a.tracev3",
            )
        ],
    )
    _write_jsonl(
        right,
        [
            _minimal_record(
                component="OtherTool",
                source_trace_path="/right/export.jsonl",
            )
        ],
    )

    assert main(
        _compare_args(left, right, output_dir=output_dir, right_format="jsonl")
    ) == 0

    matches = _read_csv_rows(
        _assert_expected_package_exists(output_dir)["comparison_matches.csv"]
    )
    assert len(matches) == 1
    assert matches[0]["match_classification"] == "EXACT_MATCH"


def test_compare_pid_string_with_leading_zeroes_normalizes_to_same_integer(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record(pid=123)])
    _write_csv(right, [_minimal_record(pid="00123")])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    matches = _read_csv_rows(
        _assert_expected_package_exists(output_dir)["comparison_matches.csv"]
    )
    assert len(matches) == 1


@pytest.mark.parametrize(
    ("field_name", "left_value", "right_value"),
    [
        ("message", "Device connected", "Device disconnected"),
        ("process", "bluetoothd", "sharingd"),
        ("pid", 123, 124),
    ],
)
def test_compare_exact_match_key_rejects_differences_in_identity_fields(
    tmp_path: Path,
    field_name: str,
    left_value: object,
    right_value: object,
) -> None:
    left = tmp_path / f"left_{field_name}.csv"
    right = tmp_path / f"right_{field_name}.csv"
    output_dir = tmp_path / f"comparison_{field_name}"
    left_record = _minimal_record(**{field_name: left_value})
    right_record = _minimal_record(**{field_name: right_value})
    _write_csv(left, [left_record])
    _write_csv(right, [right_record])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    assert _read_csv_rows(paths["comparison_matches.csv"]) == []


def test_compare_duplicate_multiplicity_and_counterpart_rows(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    record = _minimal_record()
    _write_csv(left, [record, record, record])
    _write_csv(right, [record, record])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    matches = _read_csv_rows(paths["comparison_matches.csv"])
    left_only = _read_csv_rows(paths["comparison_left_only.csv"])
    assert len(matches) == 2
    assert [row["left_row_number"] for row in matches] == ["1", "2"]
    assert [row["right_row_number"] for row in matches] == ["1", "2"]
    assert len(left_only) == 1
    assert left_only[0]["source_row_number"] == "3"


def test_compare_field_difference_when_timestamp_pid_process_aligns(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record(category="connect")])
    _write_csv(right, [_minimal_record(category="disconnect")])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    differences = _read_csv_rows(
        _assert_expected_package_exists(output_dir)["comparison_differences.csv"]
    )
    assert len(differences) == 1
    assert differences[0]["match_classification"] == "FIELD_DIFFERENCE"
    assert differences[0]["differing_fields"] == "category"
    assert differences[0]["left_row_number"] == "1"
    assert differences[0]["right_row_number"] == "1"


def test_compare_multiple_field_differences_are_reported(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record(category="connect", log_type="default")])
    _write_csv(right, [_minimal_record(category="disconnect", log_type="error")])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    differences = _read_csv_rows(
        _assert_expected_package_exists(output_dir)["comparison_differences.csv"]
    )
    assert len(differences) == 1
    assert differences[0]["differing_fields"] == "category|log_type"


def test_compare_ambiguous_difference_candidates_remain_side_only(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    timestamp = "2026-05-04T12:00:00.123456701Z"
    _write_csv(
        left,
        [
            _minimal_record(timestamp=timestamp, message="left-A"),
            _minimal_record(timestamp=timestamp, message="left-B"),
        ],
    )
    _write_csv(
        right,
        [
            _minimal_record(timestamp=timestamp, message="right-A"),
            _minimal_record(timestamp=timestamp, message="right-B"),
        ],
    )

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    assert _read_csv_rows(paths["comparison_differences.csv"]) == []
    assert len(_read_csv_rows(paths["comparison_left_only.csv"])) == 2
    assert len(_read_csv_rows(paths["comparison_right_only.csv"])) == 2


def test_compare_invalid_rows_are_emitted_and_counted(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_jsonl(
        left,
        [
            _minimal_record(timestamp="not-a-timestamp"),
            ["not", "an", "object"],
        ],
    )
    _write_csv(right, [_minimal_record()])

    assert main(
        _compare_args(left, right, output_dir=output_dir, left_format="jsonl")
    ) == 0

    paths = _assert_expected_package_exists(output_dir)
    invalid_rows = _read_csv_rows(paths["comparison_invalid.csv"])
    summary_text = paths["comparison_summary.txt"].read_text(encoding="utf-8")
    assert len(invalid_rows) == 2
    assert "left invalid records: 2" in summary_text
    assert "left input records: 2" in summary_text


def test_compare_empty_jsonl_files_produce_zero_record_package(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    left.write_text("", encoding="utf-8")
    right.write_text("", encoding="utf-8")

    assert main(
        _compare_args(
            left,
            right,
            output_dir=output_dir,
            left_format="jsonl",
            right_format="jsonl",
        )
    ) == 0

    paths = _assert_expected_package_exists(output_dir)
    summary_text = paths["comparison_summary.txt"].read_text(encoding="utf-8")
    assert "left input records: 0" in summary_text
    assert "right input records: 0" in summary_text
    assert _read_csv_rows(paths["comparison_matches.csv"]) == []


def test_compare_header_only_csv_files_produce_zero_record_package(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [])
    _write_csv(right, [])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    summary_text = paths["comparison_summary.txt"].read_text(encoding="utf-8")
    assert "left input records: 0" in summary_text
    assert "right input records: 0" in summary_text
    assert _read_csv_rows(paths["comparison_matches.csv"]) == []


def test_compare_zero_matches_and_all_matches_accounting(tmp_path: Path) -> None:
    left_zero = tmp_path / "left_zero.csv"
    right_zero = tmp_path / "right_zero.csv"
    zero_output = tmp_path / "comparison_zero"
    _write_csv(left_zero, [_minimal_record(message="left only", process="left-only-proc")])
    _write_csv(
        right_zero, [_minimal_record(message="right only", process="right-only-proc")]
    )

    assert main(_compare_args(left_zero, right_zero, output_dir=zero_output)) == 0

    zero_summary = _assert_expected_package_exists(zero_output)[
        "comparison_summary.txt"
    ].read_text(encoding="utf-8")
    assert "exact match records: 0" in zero_summary
    assert "left-only records: 1" in zero_summary
    assert "right-only records: 1" in zero_summary

    left_all = tmp_path / "left_all.csv"
    right_all = tmp_path / "right_all.csv"
    all_output = tmp_path / "comparison_all"
    _write_csv(left_all, [_minimal_record(), _minimal_record(message="second")])
    _write_csv(right_all, [_minimal_record(), _minimal_record(message="second")])

    assert main(_compare_args(left_all, right_all, output_dir=all_output)) == 0

    all_summary = _assert_expected_package_exists(all_output)[
        "comparison_summary.txt"
    ].read_text(encoding="utf-8")
    assert "exact match records: 2" in all_summary
    assert "left-only records: 0" in all_summary
    assert "right-only records: 0" in all_summary


def test_compare_summary_reports_per_side_accounting_invariants(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output_dir = tmp_path / "comparison"
    _write_jsonl(
        left,
        [
            _minimal_record(message="exact"),
            _minimal_record(message="difference-left", category="alpha"),
            _minimal_record(message="left-only", process="left-only-proc"),
            {**_minimal_record(pid=""), "pid": ""},
        ],
    )
    _write_jsonl(
        right,
        [
            _minimal_record(message="exact"),
            _minimal_record(message="difference-left", category="beta"),
            _minimal_record(message="right-only", process="right-only-proc"),
            ["not", "an", "object"],
        ],
    )

    assert main(
        _compare_args(
            left,
            right,
            output_dir=output_dir,
            left_format="jsonl",
            right_format="jsonl",
        )
    ) == 0

    summary_text = _assert_expected_package_exists(output_dir)[
        "comparison_summary.txt"
    ].read_text(encoding="utf-8")
    assert "left input records: 4" in summary_text
    assert "right input records: 4" in summary_text
    assert "exact match records: 1" in summary_text
    assert "field-difference records: 1" in summary_text
    assert "left-only records: 1" in summary_text
    assert "right-only records: 1" in summary_text
    assert "left invalid records: 1" in summary_text
    assert "right invalid records: 1" in summary_text
    assert "left accounting invariant: PASS" in summary_text
    assert "right accounting invariant: PASS" in summary_text
    assert "left exact count == right exact count: PASS" in summary_text
    assert "left difference count == right difference count: PASS" in summary_text


def test_compare_output_headers_and_derived_epoch_ns_fields(tmp_path: Path) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    record = _minimal_record(timestamp="2026-05-04T14:00:00.123456701+02:00")
    _write_csv(left, [record])
    _write_csv(right, [record])

    assert main(_compare_args(left, right, output_dir=output_dir)) == 0

    paths = _assert_expected_package_exists(output_dir)
    matches = _read_csv_rows(paths["comparison_matches.csv"])
    fieldnames = list(matches[0].keys())
    assert "left_epoch_ns" in fieldnames
    assert "right_epoch_ns" in fieldnames
    assert "left_original_timestamp" in fieldnames
    assert "right_original_timestamp" in fieldnames
    assert matches[0]["left_original_timestamp"] == record["timestamp"]
    assert matches[0]["right_original_timestamp"] == record["timestamp"]
    assert matches[0]["left_epoch_ns"] == matches[0]["right_epoch_ns"]
    assert "epoch_ns" not in left.read_text(encoding="utf-8")
    assert "epoch_ns" not in right.read_text(encoding="utf-8")


def test_compare_dry_run_rejects_structurally_invalid_csv_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    left.write_text(
        ",".join(REQUIRED_COMPARE_FIELDS) + "\n"
        '2026-05-04T12:00:00.123456701Z,bluetoothd,123,subsys,cat,log,default,"unterminated\n',
        encoding="utf-8",
    )
    _write_csv(right, [_minimal_record()])

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right, output_dir=output_dir, dry_run=True))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "structural validity" in captured.err
    assert "FAIL" in captured.err


def test_compare_output_must_not_overwrite_either_source_input_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right, output_dir=left))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "output directory must not overwrite an input file" in captured.err


def test_compare_output_safety_rejects_existing_package_without_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])
    output_dir.mkdir()
    (output_dir / "comparison_summary.txt").write_text("stale", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(_compare_args(left, right, output_dir=output_dir))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "comparison output directory already exists" in captured.err
    assert "Use --force to overwrite." in captured.err


def test_compare_force_allows_existing_package_to_be_overwritten(
    tmp_path: Path,
) -> None:
    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])
    output_dir.mkdir()
    stale = output_dir / "comparison_summary.txt"
    stale.write_text("stale", encoding="utf-8")

    assert main(_compare_args(left, right, output_dir=output_dir, force=True)) == 0

    paths = _assert_expected_package_exists(output_dir)
    assert paths["comparison_summary.txt"].read_text(encoding="utf-8") != "stale"


def test_compare_downloads_uses_directory_level_collision_naming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ualextractor.forensic as forensic

    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])
    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    date_part = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    first_dir = tmp_path / "Downloads" / f"UALExtractor_compare_left_right_{date_part}"
    first_dir.mkdir(parents=True)

    assert main(_compare_args(left, right, downloads=True)) == 0

    second_dir = tmp_path / "Downloads" / f"UALExtractor_compare_left_right_{date_part}_2"
    _assert_expected_package_exists(second_dir)


def test_compare_invariant_failure_returns_non_zero_and_writes_fail_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ualextractor.main as main_module

    left = tmp_path / "left.csv"
    right = tmp_path / "right.csv"
    output_dir = tmp_path / "comparison"
    _write_csv(left, [_minimal_record()])
    _write_csv(right, [_minimal_record()])

    real_compare_record_sets = main_module.compare_record_sets

    def _force_invariant_failure(left_records, right_records):
        result = real_compare_record_sets(left_records, right_records)
        return replace(
            result,
            invariants=ComparisonInvariantResult(
                left_accounting_ok=False,
                right_accounting_ok=result.invariants.right_accounting_ok,
                left_valid_breakdown_ok=result.invariants.left_valid_breakdown_ok,
                right_valid_breakdown_ok=result.invariants.right_valid_breakdown_ok,
                exact_count_symmetry_ok=result.invariants.exact_count_symmetry_ok,
                difference_count_symmetry_ok=result.invariants.difference_count_symmetry_ok,
            ),
        )

    monkeypatch.setattr(main_module, "compare_record_sets", _force_invariant_failure)

    assert main(_compare_args(left, right, output_dir=output_dir)) == 1

    summary_text = _assert_expected_package_exists(output_dir)[
        "comparison_summary.txt"
    ].read_text(encoding="utf-8")
    assert "left accounting invariant: FAIL" in summary_text
    assert "VALIDATION: FAIL" in summary_text
