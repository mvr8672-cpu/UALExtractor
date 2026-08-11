from pathlib import Path

from ualextractor.inspector.inspector import Inspector
from ualextractor.inspector.inspection import InspectionStatus
from ualextractor.models import Dataset


def test_inspector_matches_nested_case_insensitive_diagnostics_components(
    tmp_path: Path,
) -> None:
    db_dir = tmp_path / "case" / "db"
    diagnostics = db_dir / "diagnostics"
    (diagnostics / "HighVolume").mkdir(parents=True)
    (diagnostics / "Persist").mkdir()
    (diagnostics / "Signpost").mkdir()
    (diagnostics / "Special").mkdir()
    (diagnostics / "timesync").mkdir()
    (db_dir / "uuidtext").mkdir()
    for directory, filename in (
        ("HighVolume", "high.tracev3"),
        ("Persist", "persist.tracev3"),
        ("Signpost", "signpost.tracev3"),
        ("Special", "special.tracev3"),
    ):
        (diagnostics / directory / filename).write_text("")

    dataset = Dataset(
        dataset_root=db_dir.parent,
        db_path=db_dir,
        diagnostics_path=diagnostics,
        uuidtext_path=db_dir / "uuidtext",
    )
    result = Inspector().inspect(dataset)

    assert result.status == InspectionStatus.COMPLETE
    assert all(result.optional_folders.values())
    assert result.optional_folder_paths["highvolume"] == diagnostics / "HighVolume"
    assert result.optional_folder_paths["persist"] == diagnostics / "Persist"
    assert result.optional_folder_paths["signpost"] == diagnostics / "Signpost"
    assert result.optional_folder_paths["special"] == diagnostics / "Special"
    assert result.optional_folder_paths["timesync"] == diagnostics / "timesync"
    assert result.trace_file_count == 4
    assert result.trace_files_by_directory == {
        diagnostics / "HighVolume": 1,
        diagnostics / "Persist": 1,
        diagnostics / "Signpost": 1,
        diagnostics / "Special": 1,
    }
