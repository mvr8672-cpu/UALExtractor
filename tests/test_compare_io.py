from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ualextractor.compare import exact_match_key
from ualextractor.compare_io import CompareInputError, detect_input_format, read_compare_input


def _base_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "timestamp": "2026-05-04T12:00:00.123456701Z",
        "process": "bluetoothd",
        "pid": 123,
        "subsystem": "com.apple.bluetooth",
        "category": "control",
        "event_type": "log",
        "log_type": "default",
        "message": "Device connected",
    }
    record.update(overrides)
    return record


def _write_csv(
    path: Path,
    rows: list[dict[str, object]],
    header: list[str] | None = None,
    *,
    encoding: str = "utf-8",
) -> None:
    if header is None:
        header = [
            "timestamp",
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
    with path.open("w", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_jsonl(path: Path, rows: list[object], *, encoding: str = "utf-8") -> None:
    with path.open("w", encoding=encoding, newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_detect_input_format_extensions_and_overrides(tmp_path: Path) -> None:
    assert detect_input_format(tmp_path / "a.csv") == "csv"
    assert detect_input_format(tmp_path / "a.jsonl") == "jsonl"
    assert detect_input_format(tmp_path / "a.ndjson") == "jsonl"
    assert detect_input_format(tmp_path / "a.any", "csv") == "csv"
    assert detect_input_format(tmp_path / "a.any", "ndjson") == "jsonl"


def test_detect_input_format_rejects_unsupported(tmp_path: Path) -> None:
    with pytest.raises(CompareInputError, match="Unsupported input format"):
        detect_input_format(tmp_path / "a.json")
    with pytest.raises(CompareInputError, match="Unsupported input format override"):
        detect_input_format(tmp_path / "a.csv", "json")


def test_csv_and_jsonl_canonical_equivalence_and_provenance_exclusion(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "left.csv"
    jsonl_path = tmp_path / "right.jsonl"
    _write_csv(
        csv_path,
        [
            _base_record(
                timestamp="2026-05-04T14:00:00.123456701+02:00",
                pid="00123",
                component="Persist",
                source_trace_path="/a/trace.tracev3",
            )
        ],
    )
    _write_jsonl(
        jsonl_path,
        [
            _base_record(
                pid=123,
                component="OtherSource",
                source_trace_path="/b/export.jsonl",
            )
        ],
    )

    left = read_compare_input(path=csv_path, side="left")
    right = read_compare_input(path=jsonl_path, side="right")
    assert left.source_format == "csv"
    assert right.source_format == "jsonl"
    assert left.records[0].is_valid is True
    assert right.records[0].is_valid is True
    assert left.records[0].original_timestamp_text == "2026-05-04T14:00:00.123456701+02:00"
    assert right.records[0].original_timestamp_text == "2026-05-04T12:00:00.123456701Z"
    assert left.records[0].component == "Persist"
    assert right.records[0].component == "OtherSource"
    assert exact_match_key(left.records[0]) == exact_match_key(right.records[0])


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_jsonl_input_accepts_utf8_with_and_without_bom_and_preserves_unicode(
    tmp_path: Path, encoding: str
) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _base_record(
                process="ProcessΩ",
                message="Tweede regel β",
            )
        ],
        encoding=encoding,
    )

    result = read_compare_input(path=jsonl_path, side="left")
    record = result.records[0]
    assert record.is_valid is True
    assert record.source_record_number == 1
    assert record.process == "ProcessΩ"
    assert record.message == "Tweede regel β"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_csv_input_accepts_utf8_with_and_without_bom_and_preserves_unicode(
    tmp_path: Path, encoding: str
) -> None:
    csv_path = tmp_path / "left.csv"
    _write_csv(
        csv_path,
        [
            _base_record(
                process="ProcessΩ",
                message='Bluetooth  Device "β"',
            )
        ],
        encoding=encoding,
    )

    result = read_compare_input(path=csv_path, side="left")
    record = result.records[0]
    assert record.is_valid is True
    assert record.source_record_number == 1
    assert record.original_timestamp_text == "2026-05-04T12:00:00.123456701Z"
    assert record.process == "ProcessΩ"
    assert record.message == 'Bluetooth  Device "β"'


def test_utf8_case_and_whitespace_are_preserved(tmp_path: Path) -> None:
    csv_path = tmp_path / "left.csv"
    _write_csv(
        csv_path,
        [_base_record(process="ProcessΩ", message='Bluetooth  Device "β"')],
    )

    result = read_compare_input(path=csv_path, side="left")
    record = result.records[0]
    assert record.process == "ProcessΩ"
    assert record.message == 'Bluetooth  Device "β"'


def test_timestamp_invalid_and_precision_overflow_become_invalid_records(
    tmp_path: Path,
) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _base_record(timestamp="not-a-time"),
            _base_record(timestamp="2026-05-04T12:00:00.1234567891Z"),
        ],
    )

    result = read_compare_input(path=jsonl_path, side="left")
    assert len(result.records) == 2
    assert result.records[0].invalid_reason == "invalid_timestamp"
    assert result.records[1].invalid_reason == "invalid_timestamp"


@pytest.mark.parametrize("pid_value", [123, "123", "00123"])
def test_pid_normalization_accepts_decimal_int_forms(
    tmp_path: Path, pid_value: object
) -> None:
    csv_path = tmp_path / f"{pid_value}.csv"
    _write_csv(csv_path, [_base_record(pid=pid_value)])
    record = read_compare_input(path=csv_path, side="left").records[0]
    assert record.is_valid is True
    assert record.normalized_pid == 123


@pytest.mark.parametrize("pid_value", [True, -1, 1.5, "-1", "+1", "1.0", "abc", ""])
def test_invalid_pid_forms_are_rejected(tmp_path: Path, pid_value: object) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    _write_jsonl(jsonl_path, [_base_record(pid=pid_value)])
    record = read_compare_input(path=jsonl_path, side="left").records[0]
    expected_reason = "empty_required_value" if pid_value == "" else "invalid_pid"
    assert record.is_valid is False
    assert record.invalid_reason == expected_reason
    assert record.invalid_field == "pid"


def test_csv_missing_required_column_is_file_level_error(tmp_path: Path) -> None:
    csv_path = tmp_path / "left.csv"
    _write_csv(
        csv_path,
        [_base_record()],
        header=[
            "timestamp",
            "process",
            "pid",
            "subsystem",
            "category",
            "event_type",
            "log_type",
        ],
    )
    with pytest.raises(CompareInputError, match="missing required column"):
        read_compare_input(path=csv_path, side="left")


def test_csv_unterminated_quoted_row_is_file_level_error(tmp_path: Path) -> None:
    csv_path = tmp_path / "left.csv"
    csv_path.write_text(
        ",".join(
            [
                "timestamp",
                "process",
                "pid",
                "subsystem",
                "category",
                "event_type",
                "log_type",
                "message",
            ]
        )
        + "\n"
        + '2026-05-04T12:00:00.123456701Z,bluetoothd,123,subsys,cat,log,default,"unterminated\n',
        encoding="utf-8",
    )

    with pytest.raises(CompareInputError, match="CSV structural validation failed"):
        read_compare_input(path=csv_path, side="left")


def test_missing_required_field_is_distinct_from_empty_text(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    missing = _base_record()
    missing.pop("message")
    empty = _base_record(message="")
    _write_jsonl(jsonl_path, [missing, empty])

    result = read_compare_input(path=jsonl_path, side="left")
    assert result.records[0].invalid_reason == "missing_required_value"
    assert result.records[0].invalid_field == "message"
    assert result.records[1].is_valid is True
    assert result.records[1].message == ""


def test_jsonl_malformed_and_non_object_rows_become_invalid_records(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    with jsonl_path.open("w", encoding="utf-8", newline="") as handle:
        handle.write("{not-json}\n")
        handle.write(json.dumps(["not", "object"]) + "\n")

    result = read_compare_input(path=jsonl_path, side="left")
    assert len(result.records) == 2
    assert result.records[0].invalid_reason == "invalid_json"
    assert result.records[1].invalid_reason == "invalid_structure"


def test_jsonl_row_number_uses_physical_line_numbers(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "left.jsonl"
    with jsonl_path.open("w", encoding="utf-8", newline="") as handle:
        handle.write("\n")
        handle.write(json.dumps(_base_record()) + "\n")
        handle.write(json.dumps(_base_record(message="second")) + "\n")

    result = read_compare_input(path=jsonl_path, side="left")
    assert [record.source_record_number for record in result.records] == [2, 3]


def test_exact_key_excludes_component_and_source_trace_path(tmp_path: Path) -> None:
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    _write_csv(
        left_path,
        [_base_record(component="Persist", source_trace_path="/left/a.tracev3")],
    )
    _write_csv(
        right_path,
        [_base_record(component="Special", source_trace_path="/right/b.tracev3")],
    )

    left_record = read_compare_input(path=left_path, side="left").records[0]
    right_record = read_compare_input(path=right_path, side="right").records[0]
    assert exact_match_key(left_record) == exact_match_key(right_record)
