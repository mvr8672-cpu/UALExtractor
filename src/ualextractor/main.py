from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from ualextractor.decoder import BatchDecodeSummary, RustDecoder
from ualextractor.filtering import FilterSpec
from ualextractor.forensic import (
    _now_iso,
    ForensicOutputError,
    auto_output_paths,
    validate_output_provenance,
    write_validation_report,
)
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
    batch_parser = subparsers.add_parser(
        "decode",
        help="batch decode selected trace components from ROOT",
    )
    batch_parser.add_argument("root", type=Path)
    batch_parser.add_argument(
        "--component",
        action="append",
        required=True,
        metavar="COMPONENT",
        help="Unified Log component to decode (HighVolume, Persist, Signpost, Special)",
    )
    batch_parser.add_argument(
        "--decoder",
        type=Path,
        required=True,
        help="path to the Rust decoder helper executable",
    )
    batch_parser.add_argument(
        "--output",
        type=Path,
        help="optional output JSONL file; stdout used if omitted",
    )
    batch_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing output file if it exists",
    )
    batch_parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="stop the batch when a trace decoding error occurs",
    )
    batch_parser.add_argument("--start", help="inclusive start timestamp or date-only UTC bound")
    batch_parser.add_argument("--end", help="inclusive end timestamp or date-only UTC upper bound")
    batch_parser.add_argument("--process", action="append", default=[], help="process substring filter; repeated values use OR")
    batch_parser.add_argument("--pid", action="append", type=int, default=[], help="PID exact filter; repeated values use OR")
    batch_parser.add_argument("--subsystem", action="append", default=[], help="subsystem substring filter; repeated values use OR")
    batch_parser.add_argument("--category", action="append", default=[], help="category substring filter; repeated values use OR")
    batch_parser.add_argument("--event-type", action="append", default=[], help="event type exact filter; repeated values use OR")
    batch_parser.add_argument("--log-type", action="append", default=[], help="log type exact filter; repeated values use OR")
    batch_parser.add_argument("--contains", action="append", default=[], help="case-insensitive text search across message/process/subsystem/category; repeated values use OR")
    batch_parser.add_argument(
        "--format",
        choices=["jsonl", "csv"],
        default="jsonl",
        help="output format: jsonl (default) or csv",
    )
    batch_parser.add_argument(
        "--downloads",
        action="store_true",
        help="automatic safe output naming under ~/Downloads when --output is not supplied",
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


def _build_filter_spec(args: argparse.Namespace) -> FilterSpec:
    return FilterSpec.from_cli(
        start=args.start,
        end=args.end,
        process=args.process,
        pid=args.pid,
        subsystem=args.subsystem,
        category=args.category,
        event_type=args.event_type,
        log_type=args.log_type,
        contains=args.contains,
    )


def _decode_root(
    root: Path,
    decoder_path: Path,
    components: list[str],
    output: Path | None,
    force: bool,
    stop_on_error: bool,
    filter_spec: FilterSpec | None = None,
    output_format: str = "jsonl",
    downloads: bool = False,
) -> int:
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}")
        return 0
    if len(datasets) > 1:
        raise ValueError("decode requires a root containing exactly one dataset")

    report_path: Path | None = None
    # handle automatic Downloads naming if requested and no explicit output provided
    if output is None and downloads:
        descriptor = None
        if filter_spec is not None and filter_spec.contains:
            # use first contains term as descriptor when present
            descriptor = filter_spec.contains[0]
        ext = "csv" if output_format == "csv" else "jsonl"
        try:
            out_path, report_path = auto_output_paths(root, descriptor, ext)
        except ForensicOutputError as error:
            print(error, file=sys.stderr)
            return 1
        output = out_path
    execution_start = _now_iso()

    summary = RustDecoder(decoder_path).decode_batch(
        Inspector().inspect(datasets[0]),
        components,
        output_path=output,
        force=force,
        stop_on_error=stop_on_error,
        filter_spec=filter_spec,
        output_format=output_format,
    )

    # if output was a file, and decode_batch produced it, write a forensic report
    if output is not None:
        trace_results = [
            {
                "trace_path": r.trace_path,
                "component": r.component,
                "records_decoded": r.records_decoded,
                "records_matched": r.records_matched,
                "records_filtered_out": r.records_filtered_out,
                "succeeded": r.succeeded,
                "diagnostics": list(r.diagnostics),
            }
            for r in summary.trace_results
        ]

        execution_end = _now_iso()

        fs = filter_spec
        if fs is not None:
            fs_repr = (
                f"start={fs.start!r}, end={fs.end!r}, process={fs.process}, pid={fs.pid}, "
                f"subsystem={fs.subsystem}, category={fs.category}, event_type={fs.event_type}, "
                f"log_type={fs.log_type}, contains={fs.contains}"
            )
        else:
            fs_repr = "(none)"

        provenance = validate_output_provenance(output, output_format)

        if report_path is None:
            report_path = output.with_name(output.stem + "_validation.txt")

        write_validation_report(
            report_path,
            dataset_identifier=root.name,
            evidence_root=root,
            output_path=output,
            output_format=output_format,
            components=components,
            decoder_path=decoder_path,
            start_time=execution_start,
            end_time=execution_end,
            elapsed_seconds=summary.elapsed_seconds,
            filter_spec_repr=fs_repr,
            trace_results=trace_results,
            records_decoded=summary.records_decoded,
            records_matched=summary.records_matched,
            records_filtered_out=summary.records_filtered_out,
            component_provenance_ok=provenance.component_ok,
            source_trace_path_provenance_ok=provenance.source_trace_path_ok,
        )

    print("Batch decode summary:", file=sys.stderr)
    print(f"  requested components: {', '.join(summary.requested_components)}", file=sys.stderr)
    print(f"  traces attempted: {summary.traces_attempted}", file=sys.stderr)
    print(f"  traces succeeded: {summary.traces_succeeded}", file=sys.stderr)
    print(f"  traces failed: {summary.traces_failed}", file=sys.stderr)
    print(f"  total decoded records: {summary.records_decoded}", file=sys.stderr)
    print(f"  total matched records: {summary.records_matched}", file=sys.stderr)
    print(f"  total filtered out records: {summary.records_filtered_out}", file=sys.stderr)
    print(f"  total emitted records: {summary.total_records}", file=sys.stderr)
    print("  records by component:", file=sys.stderr)
    for component, count in summary.records_by_component.items():
        if count:
            print(f"    {component}: {count}", file=sys.stderr)
    if summary.trace_results:
        print("  trace results:", file=sys.stderr)
        for trace_result in summary.trace_results:
            status = "SUCCESS" if trace_result.succeeded else "FAILED"
            print(
                f"    {trace_result.trace_path}: {status}, "
                f"{trace_result.records_decoded} decoded / "
                f"{trace_result.record_count} emitted / "
                f"{trace_result.records_filtered_out} filtered out",
                file=sys.stderr,
            )
            for diagnostic in trace_result.diagnostics:
                print(f"      diagnostic: {diagnostic}", file=sys.stderr)
    print(f"  elapsed seconds: {summary.elapsed_seconds:.2f}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "inspect":
        return _inspect_root(args.root)
    if args.command == "inventory":
        return _inventory_root(args.root)
    if args.command == "decode-poc":
        return _decode_poc_root(args.root, args.decoder)
    if args.command == "decode":
       filter_spec = _build_filter_spec(args)
       return _decode_root(
           args.root,
           args.decoder,
           args.component,
           args.output,
           args.force,
           args.stop_on_error,
           filter_spec,
           args.format,
           args.downloads,
       )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())