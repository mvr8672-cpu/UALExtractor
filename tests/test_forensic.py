import csv
import hashlib
import io
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ualextractor.forensic import auto_output_paths, validate_output_provenance
from ualextractor.main import main
from ualextractor.decoder import RustDecoder
from ualextractor.inspector.inspector import Inspector
from ualextractor.models import Dataset


def _inspection(tmp_path: Path):
    db = tmp_path / "case" / "db"
    diagnostics = db / "diagnostics"
    highvolume = diagnostics / "HighVolume"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    highvolume.mkdir()
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


class _FrozenDateTime:
    @staticmethod
    def now(tz=None):
        return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _make_persist_dataset(root: Path) -> Path:
    db = root / "db"
    diagnostics = db / "diagnostics"
    persist = diagnostics / "Persist"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")
    return root


def _write_csv_rows(path: Path, header: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def test_validation_report_and_sha256(tmp_path: Path, monkeypatch, capsys):
    # create small synthetic dataset
    root = tmp_path / "aael1871nl"
    db = root / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist = diagnostics / "Persist"
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")

    # make decoder emit two JSONL records
    records = [
        {"timestamp": "2026-01-01T00:00:00Z", "process": "a", "pid": 1, "message": "bluetooth here"},
        {"timestamp": "2026-01-01T00:00:01Z", "process": "b", "pid": 2, "message": "bluetooth also"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records], stderr_text="diag\n")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    out_file = tmp_path / "out.jsonl"
    # run via main so report is generated
    rc = main([
        "decode",
        str(root),
        "--component",
        "Persist",
        "--decoder",
        "helper",
        "--output",
        str(out_file),
    ])
    assert rc == 0
    # report path
    report = out_file.with_name(out_file.stem + "_validation.txt")
    assert report.exists()

    # verify sha256 in report matches file
    data = out_file.read_bytes()
    expected_hash = hashlib.sha256(data).hexdigest()
    text = report.read_text(encoding="utf-8")
    assert "SHA-256:" in text
    assert expected_hash in text
    # VALIDATION: PASS
    assert "VALIDATION: PASS" in text


def test_progress_to_stderr_and_no_stdout_contamination(tmp_path: Path, monkeypatch, capsys):
    # synthetic dataset
    root = tmp_path / "case"
    db = root / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist = diagnostics / "Persist"
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")

    records = [
        {"timestamp": "2026-01-01T00:00:00Z", "process": "a", "pid": 1, "message": "bluetooth"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records], stderr_text="diag\n")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    # run with stdout (no output file) and format jsonl
    rc = main([
        "decode",
        str(root),
        "--component",
        "Persist",
        "--decoder",
        "helper",
    ])
    captured = capsys.readouterr()
    assert rc == 0
    # stdout should contain JSONL record(s)
    assert "bluetooth" in captured.out
    # stderr should contain progress markers (decoded=)
    assert "decoded=" in captured.err or "decoded=" in captured.err
    # ensure progress text not in stdout
    assert "decoded=" not in captured.out


def test_auto_output_paths_uses_extraction_directory_layout(tmp_path: Path, monkeypatch):
    import ualextractor.forensic as forensic

    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)

    output_path, report_path = auto_output_paths(
        tmp_path / "aael1871nl",
        "bluetooth",
        "csv",
    )

    extraction_dir = tmp_path / "Downloads" / "UALExtractor_aael1871nl_bluetooth_2026-01-01"
    assert extraction_dir.is_dir()
    assert output_path == extraction_dir / "aael1871nl_bluetooth_2026-01-01.csv"
    assert report_path == extraction_dir / "aael1871nl_bluetooth_2026-01-01_validation.txt"


def test_downloads_auto_naming_and_collision(tmp_path: Path, monkeypatch):
    import ualextractor.forensic as forensic

    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)

    # synthetic dataset
    root = tmp_path / "aael1871nl"
    db = root / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist = diagnostics / "Persist"
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")

    records = [
        {"timestamp": "2026-01-01T00:00:00Z", "process": "a", "pid": 1, "message": "bluetooth"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    # first run should create files without suffix
    rc1 = main([
        "decode",
        str(root),
        "--component",
        "Persist",
        "--decoder",
        "helper",
        "--downloads",
        "--contains",
        "bluetooth",
    ])
    assert rc1 == 0
    extraction1 = tmp_path / "Downloads" / "UALExtractor_aael1871nl_bluetooth_2026-01-01"
    out1 = extraction1 / "aael1871nl_bluetooth_2026-01-01.jsonl"
    rep1 = extraction1 / "aael1871nl_bluetooth_2026-01-01_validation.txt"
    assert extraction1.is_dir()
    assert out1.exists()
    assert rep1.exists()

    # second run should create suffixed files
    rc2 = main([
        "decode",
        str(root),
        "--component",
        "Persist",
        "--decoder",
        "helper",
        "--downloads",
        "--contains",
        "bluetooth",
    ])
    assert rc2 == 0
    extraction2 = tmp_path / "Downloads" / "UALExtractor_aael1871nl_bluetooth_2026-01-01_2"
    out2 = extraction2 / "aael1871nl_bluetooth_2026-01-01.jsonl"
    rep2 = extraction2 / "aael1871nl_bluetooth_2026-01-01_validation.txt"
    assert extraction2.is_dir()
    assert out2.exists()
    assert rep2.exists()


def test_validate_output_provenance_passes_for_complete_jsonl(tmp_path: Path) -> None:
    output = tmp_path / "out.jsonl"
    output.write_text(
        json.dumps(
            {
                "message": "bluetooth",
                "component": "Persist",
                "source_trace_path": "/tmp/persist.tracev3",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = validate_output_provenance(output, "jsonl")

    assert result.component_ok is True
    assert result.source_trace_path_ok is True
    assert result.ok is True


def test_validate_output_provenance_passes_for_complete_csv(tmp_path: Path) -> None:
    output = tmp_path / "out.csv"
    _write_csv_rows(
        output,
        [
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
        ],
        [
            [
                "2026-01-01T00:00:00Z",
                "bluetoothd",
                "1",
                "com.example",
                "cat",
                "Log",
                "Info",
                "bluetooth message",
                "Persist",
                "/tmp/persist.tracev3",
            ]
        ],
    )

    result = validate_output_provenance(output, "csv")

    assert result.component_ok is True
    assert result.source_trace_path_ok is True
    assert result.ok is True


@pytest.mark.parametrize(
    ("output_format", "content_writer", "expected_component_ok", "expected_source_ok"),
    [
        (
            "jsonl",
            lambda path: path.write_text(
                json.dumps({"source_trace_path": "/tmp/persist.tracev3"}) + "\n",
                encoding="utf-8",
            ),
            False,
            True,
        ),
        (
            "jsonl",
            lambda path: path.write_text(
                json.dumps(
                    {"component": "", "source_trace_path": "/tmp/persist.tracev3"}
                )
                + "\n",
                encoding="utf-8",
            ),
            False,
            True,
        ),
        (
            "jsonl",
            lambda path: path.write_text(
                json.dumps({"component": "Persist"}) + "\n",
                encoding="utf-8",
            ),
            True,
            False,
        ),
        (
            "jsonl",
            lambda path: path.write_text(
                json.dumps({"component": "Persist", "source_trace_path": ""}) + "\n",
                encoding="utf-8",
            ),
            True,
            False,
        ),
        (
            "csv",
            lambda path: _write_csv_rows(
                path,
                [
                    "timestamp",
                    "process",
                    "pid",
                    "subsystem",
                    "category",
                    "event_type",
                    "log_type",
                    "message",
                    "source_trace_path",
                ],
                [["", "", "", "", "", "", "", "bluetooth", "/tmp/persist.tracev3"]],
            ),
            False,
            True,
        ),
        (
            "csv",
            lambda path: _write_csv_rows(
                path,
                [
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
                ],
                [["", "", "", "", "", "", "", "bluetooth", "", "/tmp/persist.tracev3"]],
            ),
            False,
            True,
        ),
        (
            "csv",
            lambda path: _write_csv_rows(
                path,
                [
                    "timestamp",
                    "process",
                    "pid",
                    "subsystem",
                    "category",
                    "event_type",
                    "log_type",
                    "message",
                    "component",
                ],
                [["", "", "", "", "", "", "", "bluetooth", "Persist"]],
            ),
            True,
            False,
        ),
        (
            "csv",
            lambda path: _write_csv_rows(
                path,
                [
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
                ],
                [["", "", "", "", "", "", "", "bluetooth", "Persist", ""]],
            ),
            True,
            False,
        ),
    ],
    ids=[
        "jsonl-missing-component",
        "jsonl-empty-component",
        "jsonl-missing-source-trace-path",
        "jsonl-empty-source-trace-path",
        "csv-missing-component-column",
        "csv-empty-component",
        "csv-missing-source-trace-path-column",
        "csv-empty-source-trace-path",
    ],
)
def test_validate_output_provenance_fails_for_missing_or_empty_fields(
    tmp_path: Path,
    output_format: str,
    content_writer,
    expected_component_ok: bool,
    expected_source_ok: bool,
) -> None:
    output = tmp_path / f"out.{output_format}"
    content_writer(output)

    result = validate_output_provenance(output, output_format)

    assert result.component_ok is expected_component_ok
    assert result.source_trace_path_ok is expected_source_ok
    assert result.ok is False


def test_csv_validation_report_regression_complete_provenance_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_persist_dataset(tmp_path / "case")
    records = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "process": "bluetoothd",
            "pid": 1,
            "message": "bluetooth message",
        }
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records], stderr_text="diag\n")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    output = tmp_path / "out.csv"
    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--output",
            str(output),
            "--format",
            "csv",
        ]
    )

    assert rc == 0
    report_text = output.with_name("out_validation.txt").read_text(encoding="utf-8")
    assert "component populated/preserved: PASS" in report_text
    assert "source_trace_path populated/preserved: PASS" in report_text
    assert "VALIDATION: PASS" in report_text


@pytest.mark.parametrize(("output_name", "output_format"), [("out.jsonl", "jsonl"), ("out.csv", "csv")], ids=["jsonl", "csv"])
def test_validation_report_records_timezone_aware_execution_timestamps_and_provenance_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_name: str,
    output_format: str,
) -> None:
    root = _make_persist_dataset(tmp_path / f"case-{output_format}")
    records = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "process": "bluetoothd",
            "pid": 1,
            "message": "bluetooth message",
        }
    ]
    timestamps = [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:05+00:00",
    ]

    def fake_now_iso() -> str:
        return timestamps.pop(0)

    def popen(command, stdout, stderr, text):
        assert timestamps == ["2026-01-01T00:00:05+00:00"]
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.main._now_iso", fake_now_iso)
    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    output = tmp_path / output_name
    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--output",
            str(output),
            "--format",
            output_format,
        ]
    )

    assert rc == 0
    report = output.with_name(output.stem + "_validation.txt").read_text(encoding="utf-8")
    assert "component populated/preserved: PASS" in report
    assert "source_trace_path populated/preserved: PASS" in report
    assert "VALIDATION: PASS" in report
    assert "execution start: unavailable" not in report
    start_text = report.split("execution start: ", 1)[1].splitlines()[0]
    end_text = report.split("execution end: ", 1)[1].splitlines()[0]
    start = datetime.fromisoformat(start_text)
    end = datetime.fromisoformat(end_text)
    assert start.tzinfo is not None
    assert end.tzinfo is not None
    assert end >= start


def test_downloads_access_denied_fails_before_decoder_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    import ualextractor.forensic as forensic

    root = _make_persist_dataset(tmp_path / "case")
    downloads = tmp_path / "Downloads"
    called = False
    original_mkdir = forensic.Path.mkdir

    def fake_mkdir(self, *args, **kwargs):
        if self == downloads:
            raise PermissionError("Operation not permitted")
        return original_mkdir(self, *args, **kwargs)

    def popen(command, stdout, stderr, text):
        nonlocal called
        called = True
        return _make_process([])

    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)
    monkeypatch.setattr(forensic.Path, "mkdir", fake_mkdir)
    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--downloads",
            "--contains",
            "bluetooth",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert called is False
    assert "Downloads output is unavailable" in captured.err
    assert not downloads.exists()


def test_downloads_unwritable_fails_before_decoder_starts_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    import ualextractor.forensic as forensic

    root = _make_persist_dataset(tmp_path / "case")
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    extraction_dir = downloads / "UALExtractor_case_bluetooth_2026-01-01"
    called = False
    original_open = forensic.Path.open

    def fake_open(self, *args, **kwargs):
        if self == extraction_dir / ".ualextractor-write-probe":
            raise PermissionError("Permission denied")
        return original_open(self, *args, **kwargs)

    def popen(command, stdout, stderr, text):
        nonlocal called
        called = True
        return _make_process([])

    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(forensic, "datetime", _FrozenDateTime)
    monkeypatch.setattr(forensic.Path, "open", fake_open)
    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    rc = main(
        [
            "decode",
            str(root),
            "--component",
            "Persist",
            "--decoder",
            "helper",
            "--downloads",
            "--contains",
            "bluetooth",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert called is False
    assert "Downloads output is unavailable" in captured.err
    assert not extraction_dir.exists()
