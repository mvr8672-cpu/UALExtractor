from datetime import datetime, timezone
from pathlib import Path

import io
import json

import pytest

from ualextractor.main import main

try:
    from ualextractor.filtering import format_filter_summary
    _HAS_FORMAT_FILTER_SUMMARY = True
except ImportError:
    _HAS_FORMAT_FILTER_SUMMARY = False
    format_filter_summary = None  # type: ignore[assignment]


def _make_dataset(root: Path, case_name: str = "case") -> Path:
    db_dir = root / case_name / "db"
    (db_dir / "diagnostics").mkdir(parents=True)
    (db_dir / "uuidtext").mkdir()
    return db_dir


def test_inspect_reports_no_dataset(capsys, tmp_path: Path) -> None:
    exit_code = main(["inspect", str(tmp_path)])

    assert exit_code == 0
    assert f"No valid UFED dataset found under: {tmp_path}" in capsys.readouterr().out


def test_inspect_reports_one_dataset(capsys, tmp_path: Path) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "persist").mkdir()
    (db_dir / "trace.tracev3").write_text("trace")

    exit_code = main(["inspect", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Dataset root: {db_dir.parent}" in output
    assert f"db path: {db_dir}" in output
    assert "diagnostics: present" in output
    assert "uuidtext: present" in output
    assert "persist: present" in output
    assert "number of .tracev3 files: 1" in output
    assert "inspection status: COMPLETE" in output


def test_inspect_reports_multiple_datasets(capsys, tmp_path: Path) -> None:
    first_db = _make_dataset(tmp_path, "first-case")
    second_db = _make_dataset(tmp_path, "second-case")

    exit_code = main(["inspect", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Dataset root: {first_db.parent}" in output
    assert f"Dataset root: {second_db.parent}" in output
    assert output.count("inspection status: COMPLETE") == 2


def test_inspect_accepts_paths_containing_spaces(capsys, tmp_path: Path) -> None:
    root = tmp_path / "UFED export with spaces"
    db_dir = _make_dataset(root, "case with spaces")

    exit_code = main(["inspect", str(root)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Dataset root: {db_dir.parent}" in output
    assert f"db path: {db_dir}" in output


def test_inventory_reports_no_dataset(capsys, tmp_path: Path) -> None:
    exit_code = main(["inventory", str(tmp_path)])

    assert exit_code == 0
    assert f"No valid UFED dataset found under: {tmp_path}" in capsys.readouterr().out


def test_inventory_reports_multiple_datasets(capsys, tmp_path: Path) -> None:
    first_db = _make_dataset(tmp_path, "first-case")
    second_db = _make_dataset(tmp_path, "second-case")
    (first_db / "diagnostics" / "Persist").mkdir()
    (second_db / "diagnostics" / "Special").mkdir()

    exit_code = main(["inventory", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Dataset root: {first_db.parent}" in output
    assert f"Dataset root: {second_db.parent}" in output
    assert output.count("overall trace files: 0") == 2


def test_inventory_accepts_paths_containing_spaces(capsys, tmp_path: Path) -> None:
    root = tmp_path / "UFED export with spaces"
    db_dir = _make_dataset(root, "case with spaces")
    (db_dir / "diagnostics" / "Persist").mkdir()
    (db_dir / "diagnostics" / "Persist" / "file.TRACEV3").write_bytes(b"abc")

    exit_code = main(["inventory", str(root)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Dataset root: {db_dir.parent}" in output
    assert "Persist: 1 trace files, 3 bytes" in output


def test_decode_poc_keeps_jsonl_on_stdout_and_diagnostics_on_stderr(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    trace_path = db_dir / "diagnostics" / "HighVolume" / "small.tracev3"
    trace_path.write_bytes(b"x")

    class Result:
        records = ()
        diagnostics = ("missing string reference",)

    monkeypatch.setattr(
        "ualextractor.main.RustDecoder.decode_one",
        lambda self, inspection: Result(),
    )

    assert main(["decode-poc", str(tmp_path), "--decoder", "helper"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "missing string reference\n"


def test_decode_cli_requires_component(capsys, tmp_path: Path) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    trace_path = db_dir / "diagnostics" / "HighVolume" / "small.tracev3"
    trace_path.write_bytes(b"x")

    with pytest.raises(SystemExit):
        main(["decode", str(tmp_path), "--decoder", "helper"])


def test_decode_cli_writes_output_and_prints_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    trace_path = db_dir / "diagnostics" / "HighVolume" / "small.tracev3"
    trace_path.write_bytes(b"x")

    class Summary:
        requested_components = ("HighVolume",)
        traces_attempted = 1
        traces_succeeded = 1
        traces_failed = 0
        total_records = 1
        records_decoded = 1
        records_matched = 1
        records_filtered_out = 0
        records_by_component = {"HighVolume": 1}
        trace_results = (
            type(
                "Result",
                (),
                {
                    "trace_path": trace_path,
                    "component": "HighVolume",
                    "succeeded": True,
                    "record_count": 1,
                    "records_decoded": 1,
                    "records_matched": 1,
                    "records_filtered_out": 0,
                    "diagnostics": (),
                },
            ),
        )
        elapsed_seconds = 0.01

    monkeypatch.setattr(
        "ualextractor.main.RustDecoder.decode_batch",
        lambda self, inspection, components, output_path, force, stop_on_error, filter_spec=None, output_format="jsonl": (
            output_path.write_text(
                '{"component":"HighVolume","source_trace_path":"'
                + str(trace_path)
                + '"}\n',
                encoding="utf-8",
            ),
            Summary(),
        )[1],
    )

    assert main([
        "decode",
        str(tmp_path),
        "--component",
        "HighVolume",
        "--decoder",
        "helper",
        "--output",
        str(tmp_path / "out.jsonl"),
    ]) == 0
    captured = capsys.readouterr()
    assert "Batch decode summary:" in captured.err
    assert "requested components: HighVolume" in captured.err


def test_decode_cli_parses_filter_arguments(tmp_path: Path, monkeypatch) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    (db_dir / "diagnostics" / "HighVolume" / "small.tracev3").write_bytes(b"x")

    seen = {}

    class Summary:
        requested_components = ("HighVolume",)
        traces_attempted = 0
        traces_succeeded = 0
        traces_failed = 0
        total_records = 0
        records_decoded = 0
        records_matched = 0
        records_filtered_out = 0
        records_by_component = {"HighVolume": 0}
        trace_results = ()
        elapsed_seconds = 0.0

    def fake_decode(self, inspection, components, output_path=None, force=False, stop_on_error=False, filter_spec=None, output_format="jsonl"):
        seen["filter_spec"] = filter_spec
        return Summary()

    monkeypatch.setattr("ualextractor.main.RustDecoder.decode_batch", fake_decode)

    assert main([
        "decode",
        str(tmp_path),
        "--component",
        "HighVolume",
        "--decoder",
        "helper",
        "--process",
        "SpringBoard",
        "--process",
        "bluetoothd",
        "--pid",
        "123",
        "--contains",
        "AirPlay",
        "--start",
        "2026-05-02T00:00:00Z",
        "--end",
        "2026-05-02",
    ]) == 0
    filter_spec = seen["filter_spec"]
    assert filter_spec.process == ("springboard", "bluetoothd")
    assert filter_spec.pid == (123,)
    assert filter_spec.contains == ("airplay",)
    assert filter_spec.start == datetime(2026, 5, 2, tzinfo=timezone.utc)
    assert filter_spec.end_is_date_only is True


def test_cli_format_wiring_forwards_format_and_defaults(tmp_path: Path, monkeypatch):
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    (db_dir / "diagnostics" / "HighVolume" / "small.tracev3").write_bytes(b"x")

    seen = {}

    class Summary:
        requested_components = ("HighVolume",)
        traces_attempted = 0
        traces_succeeded = 0
        traces_failed = 0
        total_records = 0
        records_decoded = 0
        records_matched = 0
        records_filtered_out = 0
        records_by_component = {"HighVolume": 0}
        trace_results = ()
        elapsed_seconds = 0.0

    def fake_decode(self, inspection, components, output_path=None, force=False, stop_on_error=False, filter_spec=None, output_format="jsonl"):
        seen["components"] = components
        seen["output_path"] = output_path
        seen["force"] = force
        seen["stop_on_error"] = stop_on_error
        seen["filter_spec"] = filter_spec
        seen["output_format"] = output_format
        return Summary()

    monkeypatch.setattr("ualextractor.main.RustDecoder.decode_batch", fake_decode)

    # explicit --format csv should reach decode_batch as "csv"
    assert main([
        "decode",
        str(tmp_path),
        "--component",
        "HighVolume",
        "--decoder",
        "helper",
        "--format",
        "csv",
    ]) == 0
    assert seen["output_format"] == "csv"
    assert seen["components"] == ["HighVolume"]

    # omission of --format should default to jsonl
    seen.clear()
    assert main([
        "decode",
        str(tmp_path),
        "--component",
        "HighVolume",
        "--decoder",
        "helper",
    ]) == 0
    assert seen["output_format"] == "jsonl"


# ============================================================================
# Sprint 9: --message CLI wiring
# ============================================================================


def test_message_cli_arg_wired_into_filter_spec(tmp_path: Path, monkeypatch) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    (db_dir / "diagnostics" / "HighVolume" / "small.tracev3").write_bytes(b"x")

    seen = {}

    class Summary:
        requested_components = ("HighVolume",)
        traces_attempted = 0
        traces_succeeded = 0
        traces_failed = 0
        total_records = 0
        records_decoded = 0
        records_matched = 0
        records_filtered_out = 0
        records_by_component = {"HighVolume": 0}
        trace_results = ()
        elapsed_seconds = 0.0

    def fake_decode(self, inspection, components, output_path=None, force=False,
                    stop_on_error=False, filter_spec=None, output_format="jsonl"):
        seen["filter_spec"] = filter_spec
        return Summary()

    monkeypatch.setattr("ualextractor.main.RustDecoder.decode_batch", fake_decode)

    assert main([
        "decode", str(tmp_path),
        "--component", "HighVolume",
        "--decoder", "helper",
        "--message", "bluetooth",
        "--message", "wifi",
    ]) == 0

    fs = seen["filter_spec"]
    assert hasattr(fs, "message"), "FilterSpec must have a 'message' attribute"
    assert fs.message == ("bluetooth", "wifi")


def test_message_cli_default_empty_when_not_supplied(tmp_path: Path, monkeypatch) -> None:
    db_dir = _make_dataset(tmp_path)
    (db_dir / "diagnostics" / "HighVolume").mkdir()
    (db_dir / "diagnostics" / "HighVolume" / "small.tracev3").write_bytes(b"x")

    seen = {}

    class Summary:
        requested_components = ("HighVolume",)
        traces_attempted = 0
        traces_succeeded = 0
        traces_failed = 0
        total_records = 0
        records_decoded = 0
        records_matched = 0
        records_filtered_out = 0
        records_by_component = {"HighVolume": 0}
        trace_results = ()
        elapsed_seconds = 0.0

    def fake_decode(self, inspection, components, output_path=None, force=False,
                    stop_on_error=False, filter_spec=None, output_format="jsonl"):
        seen["filter_spec"] = filter_spec
        return Summary()

    monkeypatch.setattr("ualextractor.main.RustDecoder.decode_batch", fake_decode)

    assert main([
        "decode", str(tmp_path),
        "--component", "HighVolume",
        "--decoder", "helper",
    ]) == 0

    fs = seen["filter_spec"]
    assert hasattr(fs, "message")
    assert fs.message == ()


# ============================================================================
# Sprint 9: filter summary in stderr before decode
# ============================================================================


def _make_persist_dataset_main(root: Path) -> Path:
    db = root / "db"
    diagnostics = db / "diagnostics"
    persist = diagnostics / "Persist"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist.mkdir(parents=True)
    (persist / "p.tracev3").write_bytes(b"x")
    return root


def _make_process_main(stdout_lines, stderr_text="", returncode=0):
    class Process:
        def __init__(self):
            self.stdout = iter(stdout_lines)
            self.stderr = io.StringIO(stderr_text)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    return Process()


def test_filter_summary_printed_to_stderr_before_decode(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_persist_dataset_main(tmp_path / "case")
    records = [
        {"timestamp": "2026-01-01T00:00:00Z", "process": "a", "pid": 1,
         "message": "bluetooth session"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process_main([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--contains", "bluetooth",
        "--output", str(tmp_path / "out.jsonl"),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    # The canonical filter summary must appear in stderr
    assert "contains:" in captured.err
    assert "bluetooth" in captured.err
    # It must not appear in stdout
    assert "contains:" not in captured.out


def test_filter_summary_none_case_in_stderr(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_persist_dataset_main(tmp_path / "case")
    records = [
        {"timestamp": "2026-01-01T00:00:00Z", "process": "a", "pid": 1,
         "message": "message"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process_main([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(tmp_path / "out.jsonl"),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "(none)" in captured.err


# ============================================================================
# Sprint 9: --dry-run end-to-end tests
# ============================================================================


def _make_dry_run_dataset(root: Path) -> Path:
    """Create a two-trace Persist dataset for dry-run tests."""
    db = root / "db"
    diagnostics = db / "diagnostics"
    persist = diagnostics / "Persist"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    persist.mkdir(parents=True)
    (persist / "000000000000fedd.tracev3").write_bytes(b"x" * 100)
    (persist / "000000000000fede.tracev3").write_bytes(b"x" * 200)
    return root


def test_dry_run_does_not_start_decoder_subprocess(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    decoder_started = []

    def popen_must_not_be_called(*args, **kwargs):
        decoder_started.append(True)
        raise AssertionError("Popen must not be called during --dry-run")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen_must_not_be_called)

    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    assert rc == 0
    assert decoder_started == [], "Decoder subprocess must not start during dry-run"


def test_dry_run_does_not_create_output_file(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "would_be_output.jsonl"

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Popen must not be called")),
    )

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--dry-run",
    ])
    assert not output_path.exists(), "Dry-run must not create an output file"


def test_dry_run_does_not_create_extraction_directory(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import ualextractor.forensic as forensic

    root = _make_dry_run_dataset(tmp_path / "case")

    # Patch home so Downloads would land in tmp_path
    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--downloads",
        "--dry-run",
    ])
    downloads = tmp_path / "Downloads"
    # Downloads dir itself may or may not exist; what must NOT exist is any
    # UALExtractor extraction directory inside it.
    if downloads.exists():
        extraction_dirs = list(downloads.glob("UALExtractor_*"))
        assert extraction_dirs == [], (
            f"Dry-run must not create extraction directories: {extraction_dirs}"
        )


def test_dry_run_does_not_create_validation_report(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "out.jsonl"

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--dry-run",
    ])
    report_path = tmp_path / "out_validation.txt"
    assert not report_path.exists(), "Dry-run must not create a validation report"


def test_dry_run_stdout_is_empty(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == "", f"stdout must be empty during dry-run, got: {captured.out!r}"


def test_dry_run_stderr_contains_selected_trace_paths(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "000000000000fedd.tracev3" in captured.err
    assert "000000000000fede.tracev3" in captured.err


def test_dry_run_stderr_contains_trace_sizes(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # 100 bytes and 200 bytes (written in _make_dry_run_dataset)
    assert "100" in captured.err
    assert "200" in captured.err


def test_dry_run_stderr_contains_total_bytes(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # total = 100 + 200 = 300
    assert "300" in captured.err


def test_dry_run_reports_selected_component_only(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    # Also add a HighVolume trace that must NOT appear in dry-run
    hv = root / "db" / "diagnostics" / "HighVolume"
    hv.mkdir(parents=True)
    (hv / "hv.tracev3").write_bytes(b"y" * 50)

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "hv.tracev3" not in captured.err


def test_dry_run_deterministic_trace_order(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    fedd_pos = captured.err.find("000000000000fedd.tracev3")
    fede_pos = captured.err.find("000000000000fede.tracev3")
    assert fedd_pos < fede_pos, "Traces must appear in lexicographic path order"


def test_dry_run_reports_active_filter_summary(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--contains", "bluetooth",
        "--message", "session",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "contains:" in captured.err
    assert "bluetooth" in captured.err
    assert "message:" in captured.err
    assert "session" in captured.err


def test_dry_run_reports_no_active_filters(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "(none)" in captured.err


def test_dry_run_reports_dataset_identifier(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # dataset identifier is the root directory name
    assert "case" in captured.err


def test_dry_run_reports_output_format(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--format", "csv",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "csv" in captured.err


def test_dry_run_reports_proposed_downloads_pattern_without_creating_it(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import ualextractor.forensic as forensic

    root = _make_dry_run_dataset(tmp_path / "case")
    monkeypatch.setattr(forensic.Path, "home", staticmethod(lambda: tmp_path))

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--downloads",
        "--contains", "bluetooth",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # Pattern should mention UALExtractor and dataset name
    assert "UALExtractor" in captured.err or "Downloads" in captured.err
    # No extraction directory must be created
    downloads = tmp_path / "Downloads"
    if downloads.exists():
        assert list(downloads.glob("UALExtractor_*")) == []


def test_dry_run_reports_explicit_output_path_without_creating_it(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "proposed.jsonl"

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert str(output_path) in captured.err or "proposed.jsonl" in captured.err
    assert not output_path.exists()


def test_dry_run_reports_existing_output_file_would_need_force(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "existing.jsonl"
    output_path.write_text("existing content", encoding="utf-8")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # Must warn that the file already exists and would require --force
    assert "exist" in captured.err.lower() or "force" in captured.err.lower()


def test_dry_run_does_not_require_force_when_output_exists(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "existing.jsonl"
    output_path.write_text("existing content", encoding="utf-8")

    # dry-run should succeed (exit 0) even without --force
    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--dry-run",
    ])
    assert rc == 0


def test_dry_run_returns_zero_for_zero_selected_traces(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = tmp_path / "case"
    db = root / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    # Only HighVolume traces exist; request Persist
    hv = diagnostics / "HighVolume"
    hv.mkdir(parents=True)
    (hv / "hv.tracev3").write_bytes(b"x")

    rc = main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "0" in captured.err  # 0 traces or 0 bytes


def test_dry_run_states_no_output_is_created(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # The dry-run output must state that no output is created
    err_lower = captured.err.lower()
    assert "no output" in err_lower or "dry run" in err_lower or "dry-run" in err_lower


def test_dry_run_states_force_has_no_effect(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    output_path = tmp_path / "existing.jsonl"
    output_path.write_text("existing", encoding="utf-8")

    main([
        "decode", str(root),
        "--component", "Persist",
        "--decoder", "helper",
        "--output", str(output_path),
        "--force",
        "--dry-run",
    ])
    captured = capsys.readouterr()
    # Must note that --force has no effect / no output created
    err_lower = captured.err.lower()
    assert "force" in err_lower or "no output" in err_lower


def test_dry_run_invalid_filter_fails_before_decoder(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = _make_dry_run_dataset(tmp_path / "case")
    decoder_started = []

    def popen_sentinel(*args, **kwargs):
        decoder_started.append(True)
        raise AssertionError("must not start")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen_sentinel)

    # Invalid time range (start > end) must raise before any decode attempt
    with pytest.raises((ValueError, SystemExit)):
        main([
            "decode", str(root),
            "--component", "Persist",
            "--decoder", "helper",
            "--start", "2026-05-03",
            "--end", "2026-05-02",
            "--dry-run",
        ])
    assert decoder_started == []
