import csv
import io
import json
from pathlib import Path

import pytest

from ualextractor.decoder import RustDecoder
from ualextractor.filtering import FilterSpec
from ualextractor.inspector.inspector import Inspector
from ualextractor.models import Dataset


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


def test_decode_csv_single_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    inspection = _inspection(tmp_path)
    payload = {
        "timestamp": "2026-08-11T10:00:00Z",
        "process": "example",
        "pid": 42,
        "subsystem": "com.example",
        "category": "test",
        "log_type": "Info",
        "event_type": "Log",
        "message": "hello, world",
    }

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(payload) + "\n"], stderr_text="diag\n")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    out_file = tmp_path / "out.csv"
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_file,
        output_format="csv",
    )

    assert summary.total_records == 1
    # read CSV and validate header and one row
    text = out_file.read_text(encoding="utf-8")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
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
    assert rows[1][0] == payload["timestamp"]
    assert rows[1][1] == payload["process"]
    assert rows[1][2] == str(payload["pid"]) 
    assert rows[1][7] == payload["message"]


def test_decode_csv_commas_quotes_newlines_and_unicode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    inspection = _inspection(tmp_path)
    payloads = [
        {
            "timestamp": "2026-08-11T10:00:00Z",
            "process": "example",
            "pid": 1,
            "subsystem": None,
            "category": None,
            "log_type": "Info",
            "event_type": "Log",
            "message": "Line with, comma",
        },
        {
            "timestamp": "2026-08-11T10:00:01Z",
            "process": "例",
            "pid": None,
            "subsystem": "sub",
            "category": "cat",
            "log_type": "Info",
            "event_type": "Log",
            "message": 'He said "hello"\nnew line',
        },
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(item) + "\n" for item in payloads])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    out_file = tmp_path / "out.csv"
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_file,
        output_format="csv",
    )

    assert summary.total_records == 2
    text = out_file.read_text(encoding="utf-8")
    # parse with csv to ensure proper quoting handling
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    assert rows[0][0] == "timestamp"
    # second row message contains comma preserved
    assert rows[1][7] == payloads[0]["message"]
    # third row message preserved including quote and newline (csv parser returns embedded newline as literal)
    assert "He said \"hello\"" in rows[2][7]
    assert "new line" in rows[2][7]
    # unicode process
    assert rows[2][1] == "例"


def test_csv_stdout_no_diagnostics_and_streaming(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    inspection = _inspection(tmp_path)
    payloads = [
        {"timestamp": "2026-08-11T10:00:00Z", "process": "p", "pid": 1, "message": "m"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(item) + "\n" for item in payloads], stderr_text="diag\n")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    # call decode_batch with output_path None to write to stdout
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=None,
        output_format="csv",
    )

    captured = capsys.readouterr()
    # stdout contains CSV header and one row, stderr contains diagnostics
    assert "timestamp,process" in captured.out
    assert "diag" in captured.err


def test_csv_and_jsonl_matched_counts_equal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    inspection = _inspection(tmp_path)
    records = [
        {"timestamp": "2026-05-02T05:00:00Z", "process": "SpringBoard", "pid": 123, "message": "m"},
        {"timestamp": "2026-05-02T05:00:01Z", "process": "Other", "pid": 456, "message": "n"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    out_json = tmp_path / "out.jsonl"
    out_csv = tmp_path / "out.csv"
    summary_json = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_json,
        output_format="jsonl",
        filter_spec=FilterSpec.from_cli(process=["SpringBoard"]),
    )

    summary_csv = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_csv,
        output_format="csv",
        filter_spec=FilterSpec.from_cli(process=["SpringBoard"]),
    )

    assert summary_json.records_matched == summary_csv.records_matched
    # parse CSV and ensure number of data rows equals records_matched
    text = out_csv.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    # header + data rows
    assert len(rows) - 1 == summary_csv.records_matched


def test_csv_header_only_for_zero_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    inspection = _inspection(tmp_path)

    def popen(command, stdout, stderr, text):
        return _make_process([], stderr_text="")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    out_csv = tmp_path / "out.csv"
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_csv,
        output_format="csv",
    )

    text = out_csv.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
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
    # no data rows
    assert len(rows) == 1


def test_decode_csv_missing_process_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # payload missing process key should produce empty CSV process field
    inspection = _inspection(tmp_path)
    payload = {
        "timestamp": "2026-08-11T10:00:00Z",
        # process intentionally omitted
        "pid": 99,
        "subsystem": "s",
        "category": "c",
        "log_type": "Info",
        "event_type": "Log",
        "message": "no process here",
    }

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(payload) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    out_file = tmp_path / "out_missing_process.csv"
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=out_file,
        output_format="csv",
    )

    assert summary.total_records == 1
    text = out_file.read_text(encoding="utf-8")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    # header present
    assert rows[0][1] == "process"
    # data row has empty process field
    assert rows[1][1] == ""
    # pid preserved
    assert rows[1][2] == str(payload["pid"]) 
    # provenance present
    assert rows[1][8] != ""
    assert rows[1][9] != ""
