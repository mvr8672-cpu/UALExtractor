from pathlib import Path

import pytest

from ualextractor.main import main


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
        records_by_component = {"HighVolume": 1}
        trace_results = (
            type(
                "Result",
                (),
                {
                    "trace_path": trace_path,
                    "succeeded": True,
                    "record_count": 1,
                    "diagnostics": (),
                },
            ),
        )
        elapsed_seconds = 0.01

    monkeypatch.setattr(
        "ualextractor.main.RustDecoder.decode_batch",
        lambda self, inspection, components, output_path, force, stop_on_error: Summary(),
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
