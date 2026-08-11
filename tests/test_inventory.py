from pathlib import Path

from ualextractor.inspector.inspector import Inspector
from ualextractor.inventory import TraceInventoryScanner
from ualextractor.models import Dataset


def _inspection(tmp_path: Path):
    db_dir = tmp_path / "case" / "db"
    diagnostics = db_dir / "diagnostics"
    (db_dir / "uuidtext").mkdir(parents=True)
    diagnostics.mkdir()
    dataset = Dataset(
        dataset_root=db_dir.parent,
        db_path=db_dir,
        diagnostics_path=diagnostics,
        uuidtext_path=db_dir / "uuidtext",
    )
    return dataset, diagnostics


def test_inventory_reports_empty_components(tmp_path: Path) -> None:
    dataset, diagnostics = _inspection(tmp_path)
    for component in ("HighVolume", "Persist", "Signpost", "Special"):
        (diagnostics / component).mkdir()

    inventory = TraceInventoryScanner().scan(Inspector().inspect(dataset))

    assert inventory.trace_files == ()
    assert inventory.count_by_component == {
        "HighVolume": 0,
        "Persist": 0,
        "Signpost": 0,
        "Special": 0,
    }
    assert inventory.size_by_component == {
        "HighVolume": 0,
        "Persist": 0,
        "Signpost": 0,
        "Special": 0,
    }
    assert inventory.total_count == 0
    assert inventory.total_size_bytes == 0


def test_inventory_counts_nested_files_sizes_and_components(tmp_path: Path) -> None:
    dataset, diagnostics = _inspection(tmp_path)
    highvolume = diagnostics / "hIgHvOlUmE"
    persist = diagnostics / "PERSIST"
    (highvolume / "nested").mkdir(parents=True)
    persist.mkdir()
    (highvolume / "nested" / "z.TRACEV3").write_bytes(b"12345")
    (highvolume / "a.tracev3").write_bytes(b"12")
    (persist / "b.tracev3").write_bytes(b"123")
    (persist / "ignore.txt").write_bytes(b"ignored")
    (diagnostics / "Signpost").mkdir()
    (diagnostics / "Special").mkdir()

    inventory = TraceInventoryScanner().scan(Inspector().inspect(dataset))

    assert [trace_file.path for trace_file in inventory.trace_files] == sorted(
        (
            highvolume / "a.tracev3",
            persist / "b.tracev3",
            highvolume / "nested" / "z.TRACEV3",
        )
    )
    assert inventory.count_by_component == {
        "HighVolume": 2,
        "Persist": 1,
        "Signpost": 0,
        "Special": 0,
    }
    assert inventory.size_by_component == {
        "HighVolume": 7,
        "Persist": 3,
        "Signpost": 0,
        "Special": 0,
    }
    assert inventory.total_count == 3
    assert inventory.total_size_bytes == 10


def test_inventory_order_is_sorted_by_full_path(tmp_path: Path) -> None:
    dataset, diagnostics = _inspection(tmp_path)
    (diagnostics / "Special").mkdir()
    nested = diagnostics / "Special" / "nested"
    nested.mkdir()
    paths = [
        diagnostics / "Special" / "z.tracev3",
        nested / "a.tracev3",
        diagnostics / "Special" / "a.tracev3",
    ]
    for path in paths:
        path.write_bytes(path.name.encode())

    inventory = TraceInventoryScanner().scan(Inspector().inspect(dataset))

    assert [trace_file.path for trace_file in inventory.trace_files] == sorted(paths)
