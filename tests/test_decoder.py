import json
from pathlib import Path

import pytest

from ualextractor.decoder import DecoderError, RustDecoder
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
