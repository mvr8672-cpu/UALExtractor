from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from ualextractor.decoder import RustDecoder
from ualextractor.inspector.finder import UFEDFinder
from ualextractor.inspector.inspection import InspectionResult
from ualextractor.inspector.inspector import Inspector
from ualextractor.inventory import TraceInventoryScanner
from ualextractor.models import TraceInventory


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
    inventory_parser = subparsers.add_parser(
        "inventory",
        help="inventory UFED Unified Log trace files under ROOT",
    )
    inventory_parser.add_argument(
        "root",
        type=Path,
        help="root directory containing the UFED export",
    )
    decode_parser = subparsers.add_parser(
        "decode-poc",
        help="decode one HighVolume or Persist tracev3 file",
    )
    decode_parser.add_argument("root", type=Path)
    decode_parser.add_argument(
        "--decoder",
        type=Path,
        required=True,
        help="path to the Rust decoder helper executable",
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


def _print_inventory(dataset_root: Path, inventory: TraceInventory) -> None:
    print(f"Dataset root: {dataset_root}")
    print("trace components:")
    for component, count in inventory.count_by_component.items():
        print(
            f"  {component}: {count} trace files, "
            f"{inventory.size_by_component[component]} bytes"
        )
    print(f"overall trace files: {inventory.total_count}")
    print(f"overall bytes: {inventory.total_size_bytes}")


def _inventory_root(root: Path) -> int:
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}")
        return 0

    inspector = Inspector()
    scanner = TraceInventoryScanner()
    for index, dataset in enumerate(datasets):
        if index:
            print()
        result = inspector.inspect(dataset)
        _print_inventory(dataset.dataset_root, scanner.scan(result))
    return 0


def _decode_poc_root(root: Path, decoder_path: Path) -> int:
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}")
        return 0
    if len(datasets) > 1:
        raise ValueError("decode-poc requires a root containing exactly one dataset")

    result = RustDecoder(decoder_path).decode_one(Inspector().inspect(datasets[0]))
    for diagnostic in result.diagnostics:
        print(diagnostic, file=sys.stderr)
    for record in result.records:
        print(json.dumps(asdict(record), sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "inspect":
        return _inspect_root(args.root)
    if args.command == "inventory":
        return _inventory_root(args.root)
    if args.command == "decode-poc":
        return _decode_poc_root(args.root, args.decoder)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())