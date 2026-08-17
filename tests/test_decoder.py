import io
import json
from pathlib import Path

import pytest

from ualextractor.decoder import DecoderError, RustDecoder
from ualextractor.filtering import FilterSpec
from ualextractor.inspector.inspector import Inspector
from ualextractor.models import Dataset


def _inspection(tmp_path: Path):
    db = tmp_path / "case" / "db"
    diagnostics = db / "diagnostics"
    highvolume = diagnostics / "HighVolume"
    persist = diagnostics / "Persist"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    highvolume.mkdir()
    persist.mkdir()
    (highvolume / "small.tracev3").write_bytes(b"x")
    (persist / "other.tracev3").write_bytes(b"xx")
    (diagnostics / "timesync" / "one.timesync").write_bytes(b"")
    return Inspector().inspect(Dataset(tmp_path / "case", db, diagnostics, db / "uuidtext"))


def test_decoder_selects_one_smallest_highvolume_or_persist_and_parses_jsonl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)
    payload = {
        "timestamp": "2026-08-11T10:00:00Z",
        "process": "example",
        "pid": 42,
        "subsystem": "com.example",
        "category": "test",
        "log_type": "Info",
        "event_type": "Log",
        "message": "hello",
        "source_trace_path": str(
            tmp_path / "case" / "db" / "diagnostics" / "HighVolume" / "small.tracev3"
        ),
    }

    class Completed:
        returncode = 0
        stdout = json.dumps(payload) + "\n"
        stderr = "decoder diagnostic: missing optional reference\n"

    monkeypatch.setattr("ualextractor.decoder.subprocess.run", lambda *args, **kwargs: Completed())
    result = RustDecoder(tmp_path / "helper").decode_one(inspection)

    assert len(result.records) == 1
    assert result.records[0].message == "hello"
    assert result.diagnostics == ("decoder diagnostic: missing optional reference",)


def test_decoder_prefers_highvolume_when_persist_is_smaller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)
    highvolume = inspection.dataset.db_path / "diagnostics" / "HighVolume"
    persist = inspection.dataset.db_path / "diagnostics" / "Persist"
    (highvolume / "selected.tracev3").write_bytes(b"")
    (persist / "smaller.tracev3").write_bytes(b"x")
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def run(command, **kwargs):
        captured["command"] = command
        return Completed()

    monkeypatch.setattr("ualextractor.decoder.subprocess.run", run)
    result = RustDecoder(tmp_path / "helper").decode_one(inspection)

    assert result.source_trace_path == highvolume / "selected.tracev3"
    assert captured["command"][2] == str(highvolume / "selected.tracev3")


def test_decoder_selection_is_deterministic_for_equal_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)
    highvolume = inspection.dataset.db_path / "diagnostics" / "HighVolume"
    first = highvolume / "a.tracev3"
    second = highvolume / "b.tracev3"
    first.write_bytes(b"")
    second.write_bytes(b"")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.run",
        lambda *args, **kwargs: Completed(),
    )
    result = RustDecoder(tmp_path / "helper").decode_one(inspection)

    assert result.source_trace_path == first


def test_decoder_rejects_malformed_jsonl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)

    class Completed:
        returncode = 0
        stdout = "{not-json}\n"
        stderr = ""

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.run",
        lambda *args, **kwargs: Completed(),
    )

    with pytest.raises(DecoderError, match="invalid JSONL"):
        RustDecoder(tmp_path / "helper").decode_one(inspection)


def test_decoder_rejects_nonzero_exit_and_preserves_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)

    class Completed:
        returncode = 7
        stdout = ""
        stderr = "trace diagnostic: failed to parse\n"

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.run",
        lambda *args, **kwargs: Completed(),
    )

    with pytest.raises(DecoderError, match="status 7: trace diagnostic"):
        RustDecoder(tmp_path / "helper").decode_one(inspection)


def test_decoder_preserves_paths_containing_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path / "UFED export with spaces")
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def run(command, **kwargs):
        captured["command"] = command
        return Completed()

    monkeypatch.setattr("ualextractor.decoder.subprocess.run", run)
    RustDecoder(tmp_path / "helper with spaces").decode_one(inspection)

    command = captured["command"]
    assert str(tmp_path / "UFED export with spaces") in " ".join(command)


def test_decoder_rejects_missing_poc_trace(tmp_path: Path) -> None:
    inspection = _inspection(tmp_path)
    (inspection.dataset.db_path / "diagnostics" / "HighVolume" / "small.tracev3").unlink()
    (inspection.dataset.db_path / "diagnostics" / "Persist" / "other.tracev3").unlink()

    with pytest.raises(DecoderError, match="No HighVolume or Persist"):
        RustDecoder(tmp_path / "helper").decode_one(inspection)


def _make_process(stdout_lines: list[str], stderr_text: str = "", returncode: int = 0):
    class Process:
        def __init__(self):
            self.stdout = iter(stdout_lines)
            self.stderr = io.StringIO(stderr_text)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    return Process()


def test_decode_batch_deterministic_component_and_trace_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "case" / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    order = []

    for component in ["Special", "Persist", "HighVolume", "Signpost"]:
        component_path = diagnostics / component
        component_path.mkdir(parents=True)
        for name in ["b.tracev3", "a.tracev3"]:
            (component_path / name).write_bytes(b"x")

    inspection = Inspector().inspect(Dataset(tmp_path / "case", db, diagnostics, db / "uuidtext"))

    def popen(command, stdout, stderr, text):
        trace_path = Path(command[command.index("--trace") + 1])
        order.append(str(trace_path))
        return _make_process([json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    output_file = tmp_path / "output.jsonl"
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["Persist", "HighVolume", "Signpost"],
        output_path=output_file,
    )

    assert summary.traces_attempted == 6
    assert summary.traces_succeeded == 6
    assert summary.traces_failed == 0
    assert order == [
        str(diagnostics / "HighVolume" / "a.tracev3"),
        str(diagnostics / "HighVolume" / "b.tracev3"),
        str(diagnostics / "Persist" / "a.tracev3"),
        str(diagnostics / "Persist" / "b.tracev3"),
        str(diagnostics / "Signpost" / "a.tracev3"),
        str(diagnostics / "Signpost" / "b.tracev3"),
    ]


def test_decode_batch_filters_components_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "case" / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    (diagnostics / "Persist").mkdir(parents=True)
    (diagnostics / "Special").mkdir(parents=True)
    (diagnostics / "Persist" / "trace.tracev3").write_bytes(b"x")
    (diagnostics / "Special" / "trace.tracev3").write_bytes(b"x")

    inspection = Inspector().inspect(Dataset(tmp_path / "case", db, diagnostics, db / "uuidtext"))
    commands: list[list[str]] = []

    def popen(command, stdout, stderr, text):
        commands.append(command)
        return _make_process([json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["Persist"],
        output_path=tmp_path / "output.jsonl",
    )

    assert summary.traces_attempted == 1
    assert summary.traces_succeeded == 1
    assert summary.traces_failed == 0
    assert Path(commands[0][commands[0].index("--trace") + 1]).name == "trace.tracev3"


def test_decode_batch_empty_requested_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = _inspection(tmp_path)

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["Signpost"],
        output_path=tmp_path / "output.jsonl",
    )

    assert summary.traces_attempted == 0
    assert summary.traces_succeeded == 0
    assert summary.traces_failed == 0
    assert summary.total_records == 0
    assert tmp_path.joinpath("output.jsonl").exists()


def test_decode_batch_zero_record_trace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = _inspection(tmp_path)
    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.Popen",
        lambda *args, **kwargs: _make_process([], returncode=0),
    )

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "output.jsonl",
    )

    assert summary.traces_attempted == 1
    assert summary.traces_succeeded == 1
    assert summary.traces_failed == 0
    assert summary.total_records == 0


def test_decode_batch_malformed_jsonl_marks_trace_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)
    def popen(command, stdout, stderr, text):
        return _make_process([
            json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n",
            "{not-json}\n",
        ], stderr_text="")

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "output.jsonl",
    )

    assert summary.traces_attempted == 1
    assert summary.traces_succeeded == 0
    assert summary.traces_failed == 1
    assert summary.total_records == 1
    assert summary.trace_results[0].diagnostics
    assert "Malformed JSONL" in summary.trace_results[0].diagnostics[0]


def test_decode_batch_failure_isolated_and_continues_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspection = _inspection(tmp_path)
    call_count = 0

    def popen(command, stdout, stderr, text):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _make_process([], stderr_text="error\n", returncode=1)
        return _make_process([json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume", "Persist"],
        output_path=tmp_path / "output.jsonl",
    )

    assert summary.traces_attempted == 2
    assert summary.traces_succeeded == 1
    assert summary.traces_failed == 1
    assert summary.total_records == 1
    assert any(not result.succeeded for result in summary.trace_results)


def test_decode_batch_stop_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = _inspection(tmp_path)
    call_count = 0

    def popen(command, stdout, stderr, text):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _make_process([], stderr_text="error\n", returncode=1)
        return _make_process([json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume", "Persist"],
        output_path=tmp_path / "output.jsonl",
        stop_on_error=True,
    )

    assert summary.traces_attempted == 1
    assert summary.traces_succeeded == 0
    assert summary.traces_failed == 1
    assert summary.total_records == 0


@pytest.mark.parametrize(
    ("output_name", "output_format"),
    [
        ("output.jsonl", "jsonl"),
        ("output.csv", "csv"),
    ],
    ids=["jsonl", "csv"],
)
def test_decode_batch_rejects_existing_output_file_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_name: str, output_format: str
) -> None:
    inspection = _inspection(tmp_path)
    output_file = tmp_path / output_name
    output_file.write_text("existing", encoding="utf-8")

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.Popen",
        lambda *args, **kwargs: _make_process(
            [json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"]
        ),
    )

    with pytest.raises(DecoderError, match="Output file already exists"):
        RustDecoder(tmp_path / "helper").decode_batch(
            inspection,
            ["HighVolume"],
            output_path=output_file,
            output_format=output_format,
        )


@pytest.mark.parametrize(
    ("output_name", "output_format", "expected_snippet"),
    [
        ("output.jsonl", "jsonl", '"timestamp": "2026-08-12T00:00:00Z"'),
        ("output.csv", "csv", "timestamp,process,pid,subsystem,category,event_type,log_type,message,component,source_trace_path"),
    ],
    ids=["jsonl", "csv"],
)
def test_decode_batch_force_overwrites_existing_output_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_name: str,
    output_format: str,
    expected_snippet: str,
) -> None:
    inspection = _inspection(tmp_path)
    output_file = tmp_path / output_name
    output_file.write_text("existing", encoding="utf-8")

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.Popen",
        lambda *args, **kwargs: _make_process(
            [json.dumps({"timestamp": "2026-08-12T00:00:00Z", "process": "example"}) + "\n"]
        ),
    )

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=output_file,
        force=True,
        output_format=output_format,
    )

    assert summary.traces_succeeded == 1
    written = output_file.read_text(encoding="utf-8")
    assert "existing" not in written
    assert expected_snippet in written


@pytest.mark.parametrize(
    ("output_name", "output_format"),
    [
        ("inside-dataset.jsonl", "jsonl"),
        ("inside-dataset.csv", "csv"),
    ],
    ids=["jsonl", "csv"],
)
def test_decode_batch_rejects_output_path_inside_evidence_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_name: str, output_format: str
) -> None:
    inspection = _inspection(tmp_path)
    output_file = inspection.dataset.dataset_root / "exports" / output_name

    monkeypatch.setattr(
        "ualextractor.decoder.subprocess.Popen",
        lambda *args, **kwargs: _make_process(
            [json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"]
        ),
    )

    with pytest.raises(DecoderError, match="Output path must not be inside the evidence dataset"):
        RustDecoder(tmp_path / "helper").decode_batch(
            inspection,
            ["HighVolume"],
            output_path=output_file,
            output_format=output_format,
        )


def test_decode_batch_paths_containing_spaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "UFED export with spaces"
    db = root / "case" / "db"
    diagnostics = db / "diagnostics"
    (db / "uuidtext" / "dsc").mkdir(parents=True)
    (diagnostics / "timesync").mkdir(parents=True)
    hv = diagnostics / "HighVolume"
    hv.mkdir(parents=True)
    trace_path = hv / "trace with spaces.tracev3"
    trace_path.write_bytes(b"x")
    inspection = Inspector().inspect(Dataset(root / "case", db, diagnostics, db / "uuidtext"))
    called = []

    def popen(command, stdout, stderr, text):
        called.append(command)
        return _make_process([json.dumps({"timestamp": "2026-08-12T00:00:00Z"}) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "output.jsonl",
    )

    assert any(str(trace_path) in " ".join(command) for command in called)


def test_decode_batch_filters_with_process_pid_and_contains(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = _inspection(tmp_path)
    records = [
        {
            "timestamp": "2026-05-02T05:00:00Z",
            "process": "SpringBoard",
            "pid": 123,
            "subsystem": "com.apple.bluetooth",
            "category": "AirPlay",
            "event_type": "Log",
            "log_type": "Info",
            "message": "bluetooth session started",
        },
        {
            "timestamp": "2026-05-02T05:00:01Z",
            "process": "bluetoothd",
            "pid": 456,
            "subsystem": "com.apple.networking",
            "category": "WiFi",
            "event_type": "Log",
            "log_type": "Info",
            "message": "different message",
        },
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(records[0]) + "\n", json.dumps(records[1]) + "\n"])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "filtered.jsonl",
        filter_spec=FilterSpec.from_cli(
            process=["SpringBoard", "bluetoothd"],
            pid=[123],
            contains=["AirPlay"],
        ),
    )

    assert summary.traces_attempted == 1
    assert summary.records_decoded == 2
    assert summary.records_matched == 1
    assert summary.records_filtered_out == 1
    assert summary.trace_results[0].records_decoded == 2
    assert summary.trace_results[0].records_matched == 1
    assert summary.trace_results[0].records_filtered_out == 1


def test_decode_batch_time_filters_and_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = _inspection(tmp_path)
    payloads = [
        {"timestamp": "2026-05-02T05:00:00Z", "process": "SpringBoard", "pid": 1, "subsystem": "sub", "category": "cat", "event_type": "Log", "log_type": "Info", "message": "ok"},
        {"timestamp": "2026-05-02T06:00:00Z", "process": "SpringBoard", "pid": 1, "subsystem": "sub", "category": "cat", "event_type": "Log", "log_type": "Info", "message": "ok"},
        {"timestamp": "2026-05-03T00:00:00Z", "process": "SpringBoard", "pid": 1, "subsystem": "sub", "category": "cat", "event_type": "Log", "log_type": "Info", "message": "ok"},
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(item) + "\n" for item in payloads])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)
    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "time.jsonl",
        filter_spec=FilterSpec.from_cli(
            start="2026-05-02T05:00:00Z",
            end="2026-05-02",
        ),
    )

    assert summary.records_matched == 2
    assert summary.records_filtered_out == 1

    summary_2 = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "time_end.jsonl",
        filter_spec=FilterSpec.from_cli(
            end="2026-05-02T06:00:00Z",
        ),
    )
    assert summary_2.records_matched == 2


def test_filter_spec_validates_range_and_timestamp_inputs() -> None:
    with pytest.raises(ValueError, match="invalid"):
        FilterSpec.from_cli(start="2026-05-03", end="2026-05-02")

    with pytest.raises(ValueError, match="timezone-aware"):
        FilterSpec.from_cli(start="2026-05-02T05:00:00")

    with pytest.raises(ValueError, match="timezone-aware"):
        FilterSpec.from_cli(end="2026-05-02T05:00:00")


def test_filter_spec_missing_timestamp_without_time_filter_is_allowed() -> None:
    filter_spec = FilterSpec.from_cli(process=["SpringBoard"])
    assert filter_spec.matches({"process": "SpringBoard"}) is True
    assert filter_spec.matches({"process": "Other"}) is False


def test_filter_spec_missing_timestamp_with_active_time_filter_does_not_match() -> None:
    filter_spec = FilterSpec.from_cli(start="2026-05-02T00:00:00Z")
    assert filter_spec.matches({"process": "SpringBoard"}) is False
    assert filter_spec.matches({"timestamp": "2026-05-02T00:00:00Z", "process": "SpringBoard"}) is True


# ============================================================================
# Sprint 9: decode_batch integration tests for --message filter
# ============================================================================


def test_decode_batch_message_filter_matches_only_message_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--message must match records where the message field contains the term."""
    inspection = _inspection(tmp_path)
    records = [
        {
            "timestamp": "2026-05-02T05:00:00Z",
            "process": "springboard",
            "pid": 1,
            "subsystem": "com.apple.bt",
            "category": "conn",
            "event_type": "Log",
            "log_type": "Info",
            "message": "bluetooth session started",
        },
        {
            "timestamp": "2026-05-02T05:00:01Z",
            "process": "springboard",
            "pid": 2,
            "subsystem": "com.apple.bt",
            "category": "conn",
            "event_type": "Log",
            "log_type": "Info",
            "message": "wifi session started",
        },
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "out.jsonl",
        filter_spec=FilterSpec.from_cli(message=["bluetooth"]),
    )

    assert summary.records_decoded == 2
    assert summary.records_matched == 1
    assert summary.records_filtered_out == 1


def test_decode_batch_message_filter_does_not_match_process_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--message must not match when 'bluetooth' appears only in process, not message."""
    inspection = _inspection(tmp_path)
    records = [
        {
            "timestamp": "2026-05-02T05:00:00Z",
            "process": "bluetoothd",   # term here
            "pid": 1,
            "subsystem": "com.apple.bt",
            "category": "conn",
            "event_type": "Log",
            "log_type": "Info",
            "message": "unrelated message",  # not here
        },
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "out.jsonl",
        filter_spec=FilterSpec.from_cli(message=["bluetooth"]),
    )

    assert summary.records_decoded == 1
    assert summary.records_matched == 0
    assert summary.records_filtered_out == 1


def test_decode_batch_message_filter_combined_with_contains_and_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--message AND --contains: both predicates must pass."""
    inspection = _inspection(tmp_path)
    records = [
        {
            # passes --message "session" AND --contains "bluetooth" (via process)
            "timestamp": "2026-05-02T05:00:00Z",
            "process": "bluetoothd",
            "pid": 1,
            "message": "session started",
        },
        {
            # passes --contains "bluetooth" (via process) but not --message "session"
            "timestamp": "2026-05-02T05:00:01Z",
            "process": "bluetoothd",
            "pid": 2,
            "message": "unrelated",
        },
        {
            # passes --message "session" but not --contains "bluetooth"
            "timestamp": "2026-05-02T05:00:02Z",
            "process": "springboard",
            "pid": 3,
            "message": "session started",
        },
    ]

    def popen(command, stdout, stderr, text):
        return _make_process([json.dumps(r) + "\n" for r in records])

    monkeypatch.setattr("ualextractor.decoder.subprocess.Popen", popen)

    summary = RustDecoder(tmp_path / "helper").decode_batch(
        inspection,
        ["HighVolume"],
        output_path=tmp_path / "out.jsonl",
        filter_spec=FilterSpec.from_cli(message=["session"], contains=["bluetooth"]),
    )

    assert summary.records_decoded == 3
    assert summary.records_matched == 1
    assert summary.records_filtered_out == 2
