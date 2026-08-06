from pathlib import Path

from ualextractor.inspector.finder import UFEDFinder


def test_find_datasets_returns_empty_for_missing_root(tmp_path: Path) -> None:
    finder = UFEDFinder()
    result = finder.find_datasets(tmp_path / "missing")

    assert result == []


def test_find_datasets_skips_incomplete_db(tmp_path: Path) -> None:
    db_dir = tmp_path / "case" / "db"
    db_dir.mkdir(parents=True)
    (db_dir / "diagnostics").mkdir()

    finder = UFEDFinder()
    result = finder.find_datasets(tmp_path)

    assert result == []


def test_find_datasets_finds_complete_dataset(tmp_path: Path) -> None:
    db_dir = tmp_path / "case" / "db"
    diagnostics_dir = db_dir / "diagnostics"
    uuidtext_dir = db_dir / "uuidtext"
    diagnostics_dir.mkdir(parents=True)
    uuidtext_dir.mkdir()

    finder = UFEDFinder()
    datasets = finder.find_datasets(tmp_path)

    assert len(datasets) == 1
    dataset = datasets[0]
    assert dataset.dataset_root == db_dir.parent
    assert dataset.db_path == db_dir
    assert dataset.diagnostics_path == diagnostics_dir
    assert dataset.uuidtext_path == uuidtext_dir
    assert dataset.is_complete


def test_find_datasets_finds_multiple_datasets_sorted_by_dataset_root(tmp_path: Path) -> None:
    case1_db = tmp_path / "case1" / "db"
    case2_db = tmp_path / "case2" / "db"
    (case1_db / "diagnostics").mkdir(parents=True)
    (case1_db / "uuidtext").mkdir()
    (case2_db / "diagnostics").mkdir(parents=True)
    (case2_db / "uuidtext").mkdir()

    finder = UFEDFinder()
    datasets = finder.find_datasets(tmp_path)

    assert len(datasets) == 2
    assert [dataset.dataset_root.name for dataset in datasets] == ["case1", "case2"]
