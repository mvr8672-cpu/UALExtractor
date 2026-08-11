from pathlib import Path

from ualextractor.inspector.inspector import Inspector
from ualextractor.inspector.inspection import InspectionStatus
from ualextractor.models import Dataset


def _make_dataset(db_dir: Path) -> Dataset:
    """Helper to construct a Dataset instance for tests."""
    return Dataset(
        dataset_root=db_dir.parent,
        db_path=db_dir,
        diagnostics_path=(db_dir / "diagnostics") if (db_dir / "diagnostics").exists() else None,
        uuidtext_path=(db_dir / "uuidtext") if (db_dir / "uuidtext").exists() else None,
    )


def test_inspect_complete_dataset_counts_traces_and_detects_folders(tmp_path: Path) -> None:
    db_dir = tmp_path / "case" / "db"
    # create required and optional directories
    (db_dir / "diagnostics").mkdir(parents=True)
    (db_dir / "uuidtext").mkdir()
    (db_dir / "persist").mkdir()
    (db_dir / "highvolume").mkdir()
    (db_dir / "special").mkdir()
    (db_dir / "signpost").mkdir()
    (db_dir / "timesync").mkdir()

    # add trace files (nested)
    (db_dir / "a.tracev3").write_text("x")
    nested = db_dir / "nested"
    nested.mkdir()
    (nested / "b.tracev3").write_text("y")
    # non-trace file should not be counted
    (nested / "other.txt").write_text("nope")

    dataset = _make_dataset(db_dir)
    inspector = Inspector()
    result = inspector.inspect(dataset)

    assert result.status == InspectionStatus.COMPLETE
    assert result.has_diagnostics is True
    assert result.has_uuidtext is True
    assert result.optional_folders["persist"] is True
    assert result.optional_folders["highvolume"] is True
    assert result.optional_folders["special"] is True
    assert result.optional_folders["signpost"] is True
    assert result.optional_folders["timesync"] is True
    assert result.trace_file_count == 2
    assert result.trace_files_by_directory == {
        db_dir: 1,
        nested: 1,
    }


def test_inspect_incomplete_dataset_missing_uuidtext(tmp_path: Path) -> None:
    db_dir = tmp_path / "case" / "db"
    (db_dir / "diagnostics").mkdir(parents=True)

    dataset = _make_dataset(db_dir)
    inspector = Inspector()
    result = inspector.inspect(dataset)

    assert result.status == InspectionStatus.INCOMPLETE
    assert result.has_diagnostics is True
    assert result.has_uuidtext is False


def test_inspect_invalid_dataset_nonexistent_db(tmp_path: Path) -> None:
    db_dir = tmp_path / "nonexistent" / "db"
    dataset = _make_dataset(db_dir)
    inspector = Inspector()
    result = inspector.inspect(dataset)

    assert result.status == InspectionStatus.INVALID
    assert result.trace_file_count == 0


def test_inspect_complete_dataset_with_zero_traces(tmp_path: Path) -> None:
    """Valid dataset (required folders present) but no .tracev3 files."""
    db_dir = tmp_path / "case" / "db"
    (db_dir / "diagnostics").mkdir(parents=True)
    (db_dir / "uuidtext").mkdir()

    dataset = _make_dataset(db_dir)
    inspector = Inspector()
    result = inspector.inspect(dataset)

    assert result.status == InspectionStatus.COMPLETE
    assert result.trace_file_count == 0
    # optional folders mapping should exist and have all False
    assert isinstance(result.optional_folders, dict)
    assert all(value is False for value in result.optional_folders.values())
