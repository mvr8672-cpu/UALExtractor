from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from ualextractor.decoder import RustDecoder
from ualextractor.filtering import (
    FilterSpec,
    _parse_timestamp_to_epoch_ns,
    format_filter_summary,
)
from ualextractor.forensic import (
    auto_output_paths,
    choose_auto_output_descriptor,
    propose_auto_output_paths,
)
from ualextractor.inspector.inspector import Inspector
from ualextractor.main import main
from ualextractor.models import Dataset

pytestmark = pytest.mark.sprint10


def _inspection(tmp_path: Path):
    db = tmp_path / "case" / "db"
    diagnostics = db / "diagnostics"
    highvolume = diagnostics / "HighVolume"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    highvolume.mkdir(parents=True)
    (highvolume / "one.tracev3").write_bytes(b"x")
    (diagnostics / "timesync" / "one.timesync").write_bytes(b"")
    return Inspector().inspect(Dataset(tmp_path / "case", db, diagnostics, db / "uuidtext"))


def _make_process(stdout_lines: list[str], stderr_text: str = "", returncode: int = 0):
    class Process:
        def __init__(self):
            self.stdout = iter(stdout_lines)
            self.stderr = io.StringIO(stderr_text)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    return Process()


def _decode_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict],
    *,
    filter_spec: FilterSpec | None = None,
    output_format: str = "jsonl",
):
    inspection = _inspection(tmp_path)

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(record) + "\n" for record in records], stderr_text="")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    output_path = tmp_path / ("out.csv" if output_format == "csv" else "out.jsonl")
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=output_path,
        output_format=output_format,
        filter_spec=filter_spec,
    )
    return summary, output_path


def _make_dry_run_dataset(root: Path) -> Path:
    db = root / "db"
    diagnostics = db / "diagnostics"
    persist = diagnostics / "Persist"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist.mkdir(parents=True)
    (persist / "one.tracev3").write_bytes(b"x" * 100)
    return root


# A. EXACT NANOSECOND BOUNDARIES
def test_ns_exact_start_is_included() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T12:00:00.123456700Z")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00.123456700Z"}) is True


def test_ns_one_before_start_is_excluded() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T12:00:00.123456700Z")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00.123456699Z"}) is False


def test_ns_one_after_start_is_included() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T12:00:00.123456700Z")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00.123456701Z"}) is True


def test_ns_exact_explicit_end_is_included() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04T12:00:00.123456700Z")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00.123456700Z"}) is True


def test_ns_one_after_explicit_end_is_excluded() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04T12:00:00.123456700Z")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00.123456701Z"}) is False


def test_ns_final_before_next_midnight_is_included_for_date_only_end() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04")
    assert fs.matches({"timestamp": "2026-05-04T23:59:59.999999999Z"}) is True


def test_ns_next_day_midnight_is_excluded_for_date_only_end() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04")
    assert fs.matches({"timestamp": "2026-05-05T00:00:00.000000000Z"}) is False


# B. NANOSECOND REGRESSION
def test_nanosecond_values_differing_beyond_microseconds_must_not_collapse() -> None:
    a = _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456700Z")
    b = _parse_timestamp_to_epoch_ns("2026-05-04T12:00:00.123456701Z")
    assert a != b


def test_cli_time_bound_with_more_than_9_fractional_digits_is_rejected() -> None:
    with pytest.raises(ValueError, match="fractional precision exceeds 9 digits"):
        FilterSpec.from_cli(start="2026-05-04T12:00:00.1234567891Z")


# C. TIMEZONE EQUIVALENCE
def test_timezone_equivalent_utc_and_positive_offset_match_same_instant() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T14:00:00+02:00")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00Z"}) is True


def test_timezone_negative_offset_matches_equivalent_utc_instant() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T07:00:00-05:00")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00Z"}) is True


def test_timezone_non_whole_hour_offset_matches_equivalent_utc_instant() -> None:
    fs = FilterSpec.from_cli(start="2026-05-04T17:30:00+05:30")
    assert fs.matches({"timestamp": "2026-05-04T12:00:00Z"}) is True


# D. RAW/EFFECTIVE TIME REPRESENTATION
def test_time_summary_preserves_raw_start_and_end_and_effective_utc() -> None:
    fs = FilterSpec.from_cli(
        start="2026-05-04T14:00:00+02:00",
        end="2026-05-04T14:15:00+02:00",
    )
    summary = format_filter_summary(fs)
    assert "raw='2026-05-04T14:00:00+02:00'" in summary
    assert "raw='2026-05-04T14:15:00+02:00'" in summary
    assert "2026-05-04T12:00:00" in summary
    assert "2026-05-04T12:15:00" in summary
    assert "inclusive" in summary.lower()


def test_time_summary_date_only_end_uses_exclusive_semantics() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04")
    summary = format_filter_summary(fs)
    assert "exclusive" in summary.lower()


def test_time_summary_explicit_end_uses_inclusive_semantics() -> None:
    fs = FilterSpec.from_cli(end="2026-05-04T12:15:00Z")
    summary = format_filter_summary(fs)
    assert "inclusive" in summary.lower()


# E/F. TIME ACCOUNTING + GENERIC FILTERING
def test_time_accounting_counters_and_invariant_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [
        {"timestamp": "2026-05-04T12:00:00Z", "message": "bluetooth"},
        {"timestamp": "2026-05-04T12:00:02Z", "message": "bluetooth"},
        {"message": "bluetooth"},
        {"timestamp": "not-a-timestamp", "message": "bluetooth"},
    ]
    fs = FilterSpec.from_cli(
        start="2026-05-04T12:00:00Z",
        end="2026-05-04T12:00:01Z",
        message=["bluetooth"],
    )
    summary, _ = _decode_batch(tmp_path, monkeypatch, records, filter_spec=fs)

    assert hasattr(summary, "records_time_matched")
    assert hasattr(summary, "records_time_filtered_out")
    assert hasattr(summary, "records_time_invalid")
    assert hasattr(summary, "records_filter_matched")
    assert hasattr(summary, "records_filter_filtered_out")
    assert summary.records_decoded == (
        summary.records_time_matched
        + summary.records_time_filtered_out
        + summary.records_time_invalid
    )


def test_time_plus_generic_filtering_paths_are_distinguishable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [
        {"timestamp": "2026-05-04T12:00:00Z", "message": "bluetooth match"},
        {"timestamp": "2026-05-04T12:00:00Z", "message": "wifi no-match"},
        {"timestamp": "2026-05-04T13:00:00Z", "message": "bluetooth match"},
        {"timestamp": "bad", "message": "bluetooth match"},
    ]
    fs = FilterSpec.from_cli(
        start="2026-05-04T12:00:00Z",
        end="2026-05-04T12:59:59Z",
        message=["bluetooth"],
    )
    summary, output_path = _decode_batch(tmp_path, monkeypatch, records, filter_spec=fs)
    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    assert summary.records_filter_matched == 1
    assert summary.records_filter_filtered_out == 1
    assert summary.records_time_filtered_out == 1
    assert summary.records_time_invalid == 1


def test_time_accounting_zero_records_in_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [{"timestamp": "2026-05-04T11:59:59Z", "message": "bluetooth"}]
    fs = FilterSpec.from_cli(
        start="2026-05-04T12:00:00Z",
        end="2026-05-04T12:00:01Z",
    )
    summary, _ = _decode_batch(tmp_path, monkeypatch, records, filter_spec=fs)
    assert summary.records_time_matched == 0


def test_time_accounting_invalid_when_record_precision_exceeds_9_digits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [{"timestamp": "2026-05-04T12:00:00.1234567891Z", "message": "m"}]
    fs = FilterSpec.from_cli(
        start="2026-05-04T12:00:00Z",
        end="2026-05-04T12:00:01Z",
    )
    summary, _ = _decode_batch(tmp_path, monkeypatch, records, filter_spec=fs)
    assert summary.records_time_invalid == 1


def test_time_counters_are_zero_when_no_time_window_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [{"timestamp": "2026-05-04T11:59:59Z", "message": "bluetooth"}]
    summary, _ = _decode_batch(tmp_path, monkeypatch, records, filter_spec=FilterSpec.from_cli())
    assert summary.records_time_matched == 0
    assert summary.records_time_filtered_out == 0
    assert summary.records_time_invalid == 0


# G. OUTPUT SCHEMA REGRESSION
def test_csv_schema_remains_exact_and_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [{"timestamp": "2026-05-04T12:00:00.123456701Z", "process": "p", "pid": 1, "message": "m"}]
    _, out_csv = _decode_batch(
        tmp_path,
        monkeypatch,
        records,
        filter_spec=None,
        output_format="csv",
    )
    rows = list(csv.reader(io.StringIO(out_csv.read_text(encoding="utf-8"))))
    assert rows[0] == [
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


def test_jsonl_schema_adds_no_comparison_fields_and_preserves_timestamp_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_timestamp = "2026-05-04T12:00:00.123456701Z"
    records = [{"timestamp": original_timestamp, "process": "p", "pid": 1, "message": "m"}]
    _, out_jsonl = _decode_batch(tmp_path, monkeypatch, records, filter_spec=None, output_format="jsonl")
    payload = json.loads(out_jsonl.read_text(encoding="utf-8").strip())
    assert payload["timestamp"] == original_timestamp
    assert "normalized_timestamp_utc" not in payload
    assert "original_timestamp" not in payload
    assert "comparison_key" not in payload


# H. VALIDATION REPORT
def test_validation_report_contains_time_window_section_and_time_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "case"
    db = root / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist = diagnostics / "Persist"
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")

    records = [{"timestamp": "2026-05-04T12:00:00Z", "message": "bluetooth"}]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records], stderr_text="")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    out_file = tmp_path / "out.jsonl"
    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--output",
            str(out_file),
            "--start",
            "2026-05-04T12:00:00Z",
            "--end",
            "2026-05-04T12:15:00Z",
        ]
    )
    assert rc == 0
    report = out_file.with_name(out_file.stem + "_validation.txt")
    text = report.read_text(encoding="utf-8")
    assert "[Time window]" in text
    assert "Examiner start:" in text
    assert "Effective UTC start:" in text
    assert "Start semantics:" in text
    assert "Examiner end:" in text
    assert "Effective UTC end:" in text
    assert "End semantics:" in text
    assert "records_time_matched" in text
    assert "records_time_filtered_out" in text
    assert "records_time_invalid" in text


# I. DRY RUN
def test_dry_run_reports_raw_effective_semantics_and_decode_stage_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "proposed.csv"

    def popen_sentinel(*args, **kwargs):
        raise AssertionError("decoder must not start in dry-run")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen_sentinel)

    original_open = Path.open

    def guarded_open(self, *args, **kwargs):
        if self.suffix == ".tracev3":
            raise AssertionError("trace content must not be opened during dry-run")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--format",
            "csv",
            "--output",
            str(output_path),
            "--start",
            "2026-05-04T14:00:00+02:00",
            "--end",
            "2026-05-04",
            "--dry-run",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not output_path.exists()
    assert "2026-05-04T14:00:00+02:00" in captured.err
    assert "inclusive" in captured.err.lower()
    assert "exclusive" in captured.err.lower()
    assert "record-level time membership" in captured.err.lower()
    assert "after decoding" in captured.err.lower()


# J. NAMING
def test_descriptor_priority_and_fallback_rules_for_timewindow_and_output() -> None:
    assert choose_auto_output_descriptor(FilterSpec.from_cli(message=["m"])) == "m"
    assert choose_auto_output_descriptor(FilterSpec.from_cli(contains=["c"])) == "c"
    assert choose_auto_output_descriptor(FilterSpec.from_cli(process=["p"])) == "p"
    assert (
        choose_auto_output_descriptor(
            FilterSpec.from_cli(start="2026-05-04T12:00:00Z", end="2026-05-04T12:15:00Z")
        )
        == "timewindow"
    )
    assert choose_auto_output_descriptor(FilterSpec.from_cli()) == "output"


def test_unfiltered_export_falls_back_to_output_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    import ualextractor.forensic as forensic

    class _FrozenDateTime:
        @staticmethod
        def now(tz=None):
            from datetime import datetime, timezone

            return datetime(2026, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)
    descriptor = choose_auto_output_descriptor(FilterSpec.from_cli())
    proposed, _ = propose_auto_output_paths(Path("/tmp/aael1871nl"), descriptor, "csv")
    assert proposed.parent.name.endswith("_output_2026-01-01")


def test_dry_run_and_normal_decode_share_descriptor_logic_for_timewindow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ualextractor.forensic as forensic

    class _FrozenDateTime:
        @staticmethod
        def now(tz=None):
            from datetime import datetime, timezone

            return datetime(2026, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)

    fs = FilterSpec.from_cli(start="2026-05-04T12:00:00Z", end="2026-05-04T12:15:00Z")
    descriptor = choose_auto_output_descriptor(fs)
    dry_out, _ = propose_auto_output_paths(tmp_path / "aael1871nl", descriptor, "csv")
    out_path, _ = auto_output_paths(tmp_path / "aael1871nl", descriptor, "csv")
    assert dry_out == out_path
    assert "timewindow" in dry_out.name
