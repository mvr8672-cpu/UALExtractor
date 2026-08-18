import csv
import hashlib
from pathlib import Path

import pytest

from ualextractor.compare import (
    ComparisonAccounting,
    ComparisonInvariantResult,
    ComparisonResult,
    canonicalize_record,
    compare_record_sets,
)
from ualextractor.compare_output import InputFileMetadata, write_comparison_package


def _record(side, row_number, *, timestamp="2024-01-01T00:00:00Z", pid="42", process="proc", subsystem="sys", category="cat", event_type="evt", log_type="json", message="hello", component="cmp", source_trace_path="trace.log"):
    return canonicalize_record(
        side=side,
        source_path=Path(f"/{side}.csv"),
        source_format="csv",
        source_record_number=row_number,
        original_record={
            "timestamp": timestamp,
            "pid": pid,
            "process": process,
            "subsystem": subsystem,
            "category": category,
            "event_type": event_type,
            "log_type": log_type,
            "message": message,
            "component": component,
            "source_trace_path": source_trace_path,
        },
    )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_package_generation_and_summary_contains_invariants(tmp_path):
    left = [
        _record("left", 1, message="hello"),
        _record("left", 2, message="left_only", process="proc_left_only"),
    ]
    right = [
        _record("right", 1, message="hello"),
        _record("right", 2, message="right_only", process="proc_right_only"),
    ]
    result = compare_record_sets(left, right)

    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_bytes(b"a,b\n1,2\n")
    right_path.write_bytes(b"a,b\n1,2\n")

    left_meta = InputFileMetadata(
        path=left_path,
        detected_format="csv",
        size_bytes=left_path.stat().st_size,
        sha256=_sha256_bytes(left_path.read_bytes()),
    )
    right_meta = InputFileMetadata(
        path=right_path,
        detected_format="csv",
        size_bytes=right_path.stat().st_size,
        sha256=_sha256_bytes(right_path.read_bytes()),
    )

    before_left = left_path.read_bytes()
    before_right = right_path.read_bytes()

    output_dir = tmp_path / "comparison_output"
    files = write_comparison_package(
        result=result,
        left_input=left_meta,
        right_input=right_meta,
        destination_dir=output_dir,
    )

    assert sorted(files) == [
        "comparison_differences.csv",
        "comparison_invalid.csv",
        "comparison_left_only.csv",
        "comparison_matches.csv",
        "comparison_right_only.csv",
        "comparison_summary.txt",
    ]

    assert left_path.read_bytes() == before_left
    assert right_path.read_bytes() == before_right

    matches_rows = list(csv.DictReader(files["comparison_matches.csv"].open("r", encoding="utf-8", newline="")))
    assert len(matches_rows) == 1
    assert matches_rows[0]["match_classification"] == "EXACT_MATCH"
    assert matches_rows[0]["message"] == "hello"

    left_only_rows = list(csv.DictReader(files["comparison_left_only.csv"].open("r", encoding="utf-8", newline="")))
    assert len(left_only_rows) == 1
    assert left_only_rows[0]["classification"] == "LEFT_ONLY"

    right_only_rows = list(csv.DictReader(files["comparison_right_only.csv"].open("r", encoding="utf-8", newline="")))
    assert len(right_only_rows) == 1
    assert right_only_rows[0]["classification"] == "RIGHT_ONLY"

    summary_text = files["comparison_summary.txt"].read_text(encoding="utf-8")
    assert "UALExtractor comparison" in summary_text
    assert "[Output integrity]" in summary_text
    assert "VALIDATION: PASS" in summary_text
    assert "left_input_records = 2" in summary_text
    assert "sha256 =" in summary_text
    assert "comparison_matches.csv: size_bytes=" in summary_text


def test_zero_record_csvs_still_have_headers(tmp_path):
    result = compare_record_sets([], [])
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_bytes(b"a\n")
    right_path.write_bytes(b"a\n")

    output_dir = tmp_path / "empty_package"
    write_comparison_package(
        result=result,
        left_input=InputFileMetadata(
            path=left_path,
            detected_format="csv",
            size_bytes=left_path.stat().st_size,
            sha256=_sha256_bytes(left_path.read_bytes()),
        ),
        right_input=InputFileMetadata(
            path=right_path,
            detected_format="csv",
            size_bytes=right_path.stat().st_size,
            sha256=_sha256_bytes(right_path.read_bytes()),
        ),
        destination_dir=output_dir,
    )

    expected_headers = {
        "comparison_matches.csv": "left_row_number,right_row_number,match_classification,left_original_timestamp,right_original_timestamp,left_epoch_ns,right_epoch_ns,process,pid,subsystem,category,event_type,log_type,message",
        "comparison_left_only.csv": "side,source_row_number,classification,original_timestamp,epoch_ns,process,pid,subsystem,category,event_type,log_type,message,component,source_trace_path",
        "comparison_right_only.csv": "side,source_row_number,classification,original_timestamp,epoch_ns,process,pid,subsystem,category,event_type,log_type,message,component,source_trace_path",
        "comparison_differences.csv": "left_row_number,right_row_number,match_classification,left_original_timestamp,right_original_timestamp,left_epoch_ns,right_epoch_ns,process,pid,differing_fields,left_subsystem,right_subsystem,left_category,right_category,left_event_type,right_event_type,left_log_type,right_log_type,left_message,right_message",
        "comparison_invalid.csv": "side,source_row_number,classification,invalid_reason,invalid_field,invalid_detail,original_timestamp,process,original_pid,subsystem,category,event_type,log_type,message,component,source_trace_path",
    }

    for name, header in expected_headers.items():
        path = output_dir / name
        assert path.exists()
        assert path.read_text(encoding="utf-8").splitlines()[0] == header


def test_existing_destination_and_source_collision_are_rejected(tmp_path):
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_text("timestamp,pid,process,subsystem,category,event_type,log_type,message\n2024-01-01T00:00:00Z,42,proc,sys,cat,evt,json,hello\n", encoding="utf-8")
    right_path.write_text("timestamp,pid,process,subsystem,category,event_type,log_type,message\n2024-01-01T00:00:00Z,42,proc,sys,cat,evt,json,hello\n", encoding="utf-8")

    left_meta = InputFileMetadata(
        path=left_path,
        detected_format="csv",
        size_bytes=left_path.stat().st_size,
        sha256=_sha256_bytes(left_path.read_bytes()),
    )
    right_meta = InputFileMetadata(
        path=right_path,
        detected_format="csv",
        size_bytes=right_path.stat().st_size,
        sha256=_sha256_bytes(right_path.read_bytes()),
    )
    result = compare_record_sets([
        canonicalize_record(
            side="left",
            source_path=left_path,
            source_format="csv",
            source_record_number=1,
            original_record={
                "timestamp": "2024-01-01T00:00:00Z",
                "pid": "42",
                "process": "proc",
                "subsystem": "sys",
                "category": "cat",
                "event_type": "evt",
                "log_type": "json",
                "message": "hello",
            },
        )
    ], [
        canonicalize_record(
            side="right",
            source_path=right_path,
            source_format="csv",
            source_record_number=1,
            original_record={
                "timestamp": "2024-01-01T00:00:00Z",
                "pid": "42",
                "process": "proc",
                "subsystem": "sys",
                "category": "cat",
                "event_type": "evt",
                "log_type": "json",
                "message": "hello",
            },
        )
    ])

    with pytest.raises(ValueError):
        write_comparison_package(
            result=result,
            left_input=left_meta,
            right_input=right_meta,
            destination_dir=left_path,
        )

    existing_output = tmp_path / "existing_package"
    existing_output.mkdir()
    with pytest.raises(FileExistsError):
        write_comparison_package(
            result=result,
            left_input=left_meta,
            right_input=right_meta,
            destination_dir=existing_output,
        )


def test_repeated_generation_is_byte_identical(tmp_path):
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_bytes(b"a\n")
    right_path.write_bytes(b"a\n")

    result = compare_record_sets([], [])
    left_meta = InputFileMetadata(path=left_path, detected_format="csv", size_bytes=left_path.stat().st_size, sha256=_sha256_bytes(left_path.read_bytes()))
    right_meta = InputFileMetadata(path=right_path, detected_format="csv", size_bytes=right_path.stat().st_size, sha256=_sha256_bytes(right_path.read_bytes()))

    first = write_comparison_package(
        result=result,
        left_input=left_meta,
        right_input=right_meta,
        destination_dir=tmp_path / "first",
    )
    second = write_comparison_package(
        result=result,
        left_input=left_meta,
        right_input=right_meta,
        destination_dir=tmp_path / "second",
    )

    for name in [
        "comparison_matches.csv",
        "comparison_left_only.csv",
        "comparison_right_only.csv",
        "comparison_differences.csv",
        "comparison_invalid.csv",
    ]:
        assert first[name].read_bytes() == second[name].read_bytes()


def test_summary_reports_validation_fail_when_any_invariant_fails(tmp_path):
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_bytes(b"a\n")
    right_path.write_bytes(b"a\n")

    result = ComparisonResult(
        exact_matches=(),
        field_differences=(),
        left_only=(),
        right_only=(),
        left_invalid=(),
        right_invalid=(),
        accounting=ComparisonAccounting(
            left_input_records=1,
            right_input_records=0,
            left_valid_records=0,
            right_valid_records=0,
            left_invalid_records=0,
            right_invalid_records=0,
            left_exact_match_records=0,
            right_exact_match_records=0,
            left_difference_records=0,
            right_difference_records=0,
            left_only_records=0,
            right_only_records=0,
            duplicate_key_groups_left=0,
            duplicate_key_groups_right=0,
            duplicate_records_left=0,
            duplicate_records_right=0,
        ),
        invariants=ComparisonInvariantResult(
            left_accounting_ok=False,
            right_accounting_ok=True,
            left_valid_breakdown_ok=True,
            right_valid_breakdown_ok=True,
            exact_count_symmetry_ok=True,
            difference_count_symmetry_ok=True,
        ),
    )

    files = write_comparison_package(
        result=result,
        left_input=InputFileMetadata(
            path=left_path,
            detected_format="csv",
            size_bytes=left_path.stat().st_size,
            sha256=_sha256_bytes(left_path.read_bytes()),
        ),
        right_input=InputFileMetadata(
            path=right_path,
            detected_format="csv",
            size_bytes=right_path.stat().st_size,
            sha256=_sha256_bytes(right_path.read_bytes()),
        ),
        destination_dir=tmp_path / "validation_fail_package",
    )

    summary_text = files["comparison_summary.txt"].read_text(encoding="utf-8")
    assert "left_accounting_ok = FAIL" in summary_text
    assert "VALIDATION: FAIL" in summary_text


def test_replace_existing_package_directory_overwrites_atomically(tmp_path):
    left_path = tmp_path / "left.csv"
    right_path = tmp_path / "right.csv"
    left_path.write_bytes(b"a\n")
    right_path.write_bytes(b"a\n")

    left_meta = InputFileMetadata(
        path=left_path,
        detected_format="csv",
        size_bytes=left_path.stat().st_size,
        sha256=_sha256_bytes(left_path.read_bytes()),
    )
    right_meta = InputFileMetadata(
        path=right_path,
        detected_format="csv",
        size_bytes=right_path.stat().st_size,
        sha256=_sha256_bytes(right_path.read_bytes()),
    )

    destination_dir = tmp_path / "comparison_output"
    destination_dir.mkdir()
    stale_summary = destination_dir / "comparison_summary.txt"
    stale_summary.write_text("stale", encoding="utf-8")

    files = write_comparison_package(
        result=compare_record_sets([], []),
        left_input=left_meta,
        right_input=right_meta,
        destination_dir=destination_dir,
        replace_existing=True,
    )

    assert files["comparison_summary.txt"].read_text(encoding="utf-8") != "stale"
