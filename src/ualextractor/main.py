from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from ualextractor.inspector.finder import UFEDFinder
from ualextractor.inspector.inspection import InspectionResult
from ualextractor.inspector.inspector import Inspector


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ualextractor",
        description="Inspect UFED datasets without modifying evidence files.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="discover and inspect UFED datasets under ROOT",
    )
    inspect_parser.add_argument(
        "root",
        type=Path,
        help="root directory containing the UFED export",
    )
    return parser


def _format_presence(present: bool) -> str:
    return "present" if present else "missing"


def _print_report(result: InspectionResult) -> None:
    dataset = result.dataset
    print(f"Dataset root: {dataset.dataset_root}")
    print(f"db path: {dataset.db_path}")
    print(f"diagnostics: {_format_presence(result.has_diagnostics)}")
    print(f"uuidtext: {_format_presence(result.has_uuidtext)}")
    print("optional folders:")
    for name, present in result.optional_folders.items():
        path = result.optional_folder_paths.get(name)
        location = f" ({path})" if path is not None else ""
        print(f"  {name}: {_format_presence(present)}{location}")
    print(f"number of .tracev3 files: {result.trace_file_count}")
    if result.trace_files_by_directory:
        print("tracev3 files by directory:")
        for directory, count in result.trace_files_by_directory.items():
            print(f"  {directory}: {count}")
    print(f"inspection status: {result.status.value}")


def _inspect_root(root: Path) -> int:
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}")
        return 0

    inspector = Inspector()
    for index, dataset in enumerate(datasets):
        if index:
            print()
        _print_report(inspector.inspect(dataset))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "inspect":
        return _inspect_root(args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())