from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Sequence

from ualextractor.compare import CompareSide, compare_record_sets
from ualextractor.compare_io import (
    CompareInputError,
    CompareInputReadResult,
    detect_input_format,
    read_compare_input,
)
from ualextractor.compare_output import (
    InputFileMetadata,
    file_sha256,
    write_comparison_package,
)
from ualextractor.compare_semantic_io import scan_semantic_input
from ualextractor.compare_semantic_output import write_semantic_coverage_package
from ualextractor.compare_semantic_sqlite import run_semantic_coverage_sqlite
from ualextractor.decoder import BatchDecodeSummary, RustDecoder
from ualextractor.filtering import FilterSpec, format_filter_summary
from ualextractor.forensic import (
    _now_iso,
    ForensicOutputError,
    auto_output_paths,
    choose_auto_output_descriptor,
    get_user_downloads_dir,
    propose_auto_output_paths,
    sanitize_filename_component,
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
    batch_parser.add_argument("--message", action="append", default=[], help="case-insensitive text search of message field only; repeated values use OR")
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
    batch_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preflight-only: show what would be decoded without running the decoder",
    )
    compare_parser = subparsers.add_parser(
        "compare",
        help="compare two extracted CSV/JSONL exports and write a comparison package",
    )
    compare_parser.add_argument("--left", type=Path, required=True, help="left input file")
    compare_parser.add_argument("--right", type=Path, required=True, help="right input file")
    compare_parser.add_argument(
        "--left-format",
        choices=["csv", "jsonl"],
        help="optional explicit left input format override",
    )
    compare_parser.add_argument(
        "--right-format",
        choices=["csv", "jsonl"],
        help="optional explicit right input format override",
    )
    compare_parser.add_argument(
        "--output",
        type=Path,
        help="final comparison package directory",
    )
    compare_parser.add_argument(
        "--downloads",
        action="store_true",
        help="write the comparison package to a safe automatically named directory under ~/Downloads",
    )
    compare_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing explicit comparison package directory",
    )
    compare_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate inputs, hash them, and report the proposed output directory without creating output files",
    )
    semantic_compare_parser = subparsers.add_parser(
        "compare-semantic",
        help="directional semantic coverage comparison from reference to UALExtractor",
    )
    semantic_compare_parser.add_argument(
        "--reference", type=Path, required=True, help="reference input file"
    )
    semantic_compare_parser.add_argument(
        "--ualextractor", type=Path, required=True, help="UALExtractor input file"
    )
    semantic_compare_parser.add_argument(
        "--reference-format",
        choices=["csv", "jsonl"],
        help="optional explicit reference input format override",
    )
    semantic_compare_parser.add_argument(
        "--ualextractor-format",
        choices=["csv", "jsonl"],
        help="optional explicit UALExtractor input format override",
    )
    semantic_compare_parser.add_argument(
        "--output",
        type=Path,
        help="final semantic coverage package directory",
    )
    semantic_compare_parser.add_argument(
        "--downloads",
        action="store_true",
        help="write the semantic coverage package to a safe automatically named directory under ~/Downloads",
    )
    semantic_compare_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing explicit semantic coverage package directory",
    )
    semantic_compare_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate inputs, hash them, and report the proposed output directory without creating output files",
    )
    semantic_compare_parser.add_argument(
        "--sqlite-index",
        type=Path,
        help="optional SQLite index path for disk-backed semantic coverage reuse",
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
        message=args.message,
    )


def _validate_compare_destination_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    if args.output is None and not args.downloads:
        parser.error("either --output DIR or --downloads is required")
    if args.output is not None and args.downloads:
        parser.error("exactly one of --output DIR or --downloads must be supplied")


def _read_compare_side(
    *,
    path: Path,
    side: CompareSide,
    format_override: str | None,
) -> CompareInputReadResult:
    resolved_path = path.resolve()
    if not resolved_path.exists():
        raise CompareInputError(f"{side.title()} input file does not exist: {resolved_path}")
    if not resolved_path.is_file():
        raise CompareInputError(
            f"{side.title()} input path is not a regular file: {resolved_path}"
        )
    return read_compare_input(
        path=resolved_path,
        side=side,
        format_override=format_override,
    )


def _read_semantic_side(
    *,
    path: Path,
    side: Literal["reference", "ualextractor"],
    format_override: str | None,
) -> tuple[Path, str]:
    resolved_path = path.resolve()
    if not resolved_path.exists():
        raise CompareInputError(f"{side.title()} input file does not exist: {resolved_path}")
    if not resolved_path.is_file():
        raise CompareInputError(
            f"{side.title()} input path is not a regular file: {resolved_path}"
        )
    source_format = detect_input_format(resolved_path, format_override)
    return resolved_path, source_format


def _build_compare_input_metadata(read_result: CompareInputReadResult) -> InputFileMetadata:
    source_path = read_result.source_path.resolve()
    return InputFileMetadata(
        path=source_path,
        detected_format=read_result.source_format,
        size_bytes=source_path.stat().st_size,
        sha256=file_sha256(source_path),
    )


def _safe_compare_stem(path: Path, fallback: str) -> str:
    sanitized = sanitize_filename_component(path.stem)
    return sanitized or fallback


def _propose_compare_downloads_directory(
    left_path: Path, right_path: Path
) -> tuple[Path, bool]:
    downloads_dir = get_user_downloads_dir()
    date_part = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base_name = (
        "UALExtractor_compare_"
        f"{_safe_compare_stem(left_path, 'left')}_"
        f"{_safe_compare_stem(right_path, 'right')}_"
        f"{date_part}"
    )
    candidate = downloads_dir / base_name
    collision_applied = False
    suffix = 2
    while candidate.exists():
        collision_applied = True
        candidate = downloads_dir / f"{base_name}_{suffix}"
        suffix += 1
    return candidate.resolve(), collision_applied


def _resolve_compare_destination(
    *, left_path: Path, right_path: Path, args: argparse.Namespace
) -> tuple[Path, bool]:
    if args.output is not None:
        destination_dir = args.output.resolve()
        left_resolved = left_path.resolve()
        right_resolved = right_path.resolve()
        if destination_dir == left_resolved or destination_dir == right_resolved:
            raise ValueError("output directory must not overwrite an input file")
        return destination_dir, False
    return _propose_compare_downloads_directory(left_path, right_path)


def _print_compare_dry_run(
    *,
    left_meta: InputFileMetadata,
    right_meta: InputFileMetadata,
    destination_dir: Path,
    destination_exists: bool,
    collision_applied: bool,
) -> None:
    print("DRY RUN", file=sys.stderr)
    print(f"Left input: {left_meta.path.resolve()}", file=sys.stderr)
    print(f"Left detected format: {left_meta.detected_format}", file=sys.stderr)
    print(f"Left size bytes: {left_meta.size_bytes}", file=sys.stderr)
    print(f"Left SHA-256: {left_meta.sha256}", file=sys.stderr)
    print("Left structural validity: PASS", file=sys.stderr)
    print(f"Right input: {right_meta.path.resolve()}", file=sys.stderr)
    print(f"Right detected format: {right_meta.detected_format}", file=sys.stderr)
    print(f"Right size bytes: {right_meta.size_bytes}", file=sys.stderr)
    print(f"Right SHA-256: {right_meta.sha256}", file=sys.stderr)
    print("Right structural validity: PASS", file=sys.stderr)
    print(f"Proposed output directory: {destination_dir}", file=sys.stderr)
    print(f"Destination exists: {'YES' if destination_exists else 'NO'}", file=sys.stderr)
    print(
        f"Collision naming applied: {'YES' if collision_applied else 'NO'}",
        file=sys.stderr,
    )
    print("No comparison output files created.", file=sys.stderr)


def _print_semantic_compare_dry_run(
    *,
    reference_meta: InputFileMetadata,
    ualextractor_meta: InputFileMetadata,
    destination_dir: Path,
    destination_exists: bool,
    collision_applied: bool,
) -> None:
    print("DRY RUN", file=sys.stderr)
    print(f"Reference input: {reference_meta.path.resolve()}", file=sys.stderr)
    print(f"Reference detected format: {reference_meta.detected_format}", file=sys.stderr)
    print(f"Reference size bytes: {reference_meta.size_bytes}", file=sys.stderr)
    print(f"Reference SHA-256: {reference_meta.sha256}", file=sys.stderr)
    print("Reference structural validity: PASS", file=sys.stderr)
    print(f"UALExtractor input: {ualextractor_meta.path.resolve()}", file=sys.stderr)
    print(
        f"UALExtractor detected format: {ualextractor_meta.detected_format}",
        file=sys.stderr,
    )
    print(f"UALExtractor size bytes: {ualextractor_meta.size_bytes}", file=sys.stderr)
    print(f"UALExtractor SHA-256: {ualextractor_meta.sha256}", file=sys.stderr)
    print("UALExtractor structural validity: PASS", file=sys.stderr)
    print(f"Proposed output directory: {destination_dir}", file=sys.stderr)
    print(f"Destination exists: {'YES' if destination_exists else 'NO'}", file=sys.stderr)
    print(
        f"Collision naming applied: {'YES' if collision_applied else 'NO'}",
        file=sys.stderr,
    )
    print("No semantic coverage output files created.", file=sys.stderr)


def _run_compare(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    _validate_compare_destination_args(parser, args)
    try:
        left_result = _read_compare_side(
            path=args.left,
            side="left",
            format_override=args.left_format,
        )
        right_result = _read_compare_side(
            path=args.right,
            side="right",
            format_override=args.right_format,
        )
        destination_dir, collision_applied = _resolve_compare_destination(
            left_path=left_result.source_path,
            right_path=right_result.source_path,
            args=args,
        )
        left_meta = _build_compare_input_metadata(left_result)
        right_meta = _build_compare_input_metadata(right_result)
    except CompareInputError as error:
        message = str(error)
        if args.dry_run:
            if "Left input" in message or "left input" in message:
                parser.error(f"Left structural validity: FAIL - {message}")
            if "Right input" in message or "right input" in message:
                parser.error(f"Right structural validity: FAIL - {message}")
            parser.error(f"structural validity: FAIL - {message}")
        parser.error(message)
    except ValueError as error:
        parser.error(str(error))
    except OSError as error:
        parser.error(str(error))

    if args.dry_run:
        _print_compare_dry_run(
            left_meta=left_meta,
            right_meta=right_meta,
            destination_dir=destination_dir,
            destination_exists=destination_dir.exists(),
            collision_applied=collision_applied,
        )
        return 0

    result = compare_record_sets(list(left_result.records), list(right_result.records))

    try:
        write_comparison_package(
            result=result,
            left_input=left_meta,
            right_input=right_meta,
            destination_dir=destination_dir,
            replace_existing=bool(args.output is not None and args.force),
        )
    except ValueError as error:
        if str(error) == "destination directory must not match either input file":
            parser.error("output directory must not overwrite an input file")
        parser.error(str(error))
    except FileExistsError as error:
        message = str(error)
        if args.output is not None and not args.force:
            parser.error(f"{message}. Use --force to overwrite.")
        parser.error(message)
    except OSError as error:
        parser.error(str(error))

    print(f"Comparison package directory: {destination_dir}", file=sys.stderr)
    if args.downloads and args.force:
        print(
            "--force has no effect with --downloads; the next available directory is selected.",
            file=sys.stderr,
        )
    if not result.invariants.all_ok:
        print(
            "Comparison invariants failed; see comparison_summary.txt for VALIDATION: FAIL.",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_semantic_compare(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    _validate_compare_destination_args(parser, args)
    try:
        reference_path, reference_format = _read_semantic_side(
            path=args.reference,
            side="reference",
            format_override=args.reference_format,
        )
        ualextractor_path, ualextractor_format = _read_semantic_side(
            path=args.ualextractor,
            side="ualextractor",
            format_override=args.ualextractor_format,
        )
        destination_dir, collision_applied = _resolve_compare_destination(
            left_path=reference_path,
            right_path=ualextractor_path,
            args=args,
        )
        reference_meta = InputFileMetadata(
            path=reference_path,
            detected_format=reference_format,
            size_bytes=reference_path.stat().st_size,
            sha256=file_sha256(reference_path),
        )
        ualextractor_meta = InputFileMetadata(
            path=ualextractor_path,
            detected_format=ualextractor_format,
            size_bytes=ualextractor_path.stat().st_size,
            sha256=file_sha256(ualextractor_path),
        )
    except CompareInputError as error:
        message = str(error)
        if args.dry_run:
            if "Reference input" in message or "reference input" in message:
                parser.error(f"Reference structural validity: FAIL - {message}")
            if "UALExtractor input" in message or "ualextractor input" in message:
                parser.error(f"UALExtractor structural validity: FAIL - {message}")
            parser.error(f"structural validity: FAIL - {message}")
        parser.error(message)
    except ValueError as error:
        parser.error(str(error))
    except OSError as error:
        parser.error(str(error))

    if args.dry_run:
        _print_semantic_compare_dry_run(
            reference_meta=reference_meta,
            ualextractor_meta=ualextractor_meta,
            destination_dir=destination_dir,
            destination_exists=destination_dir.exists(),
            collision_applied=collision_applied,
        )
        try:
            scan_semantic_input(
                path=reference_meta.path,
                side="reference",
                format_override=args.reference_format,
            )
            scan_semantic_input(
                path=ualextractor_meta.path,
                side="ualextractor",
                format_override=args.ualextractor_format,
            )
        except CompareInputError as error:
            parser.error(f"structural validity: FAIL - {error}")
        return 0

    sqlite_index_path = args.sqlite_index
    if sqlite_index_path is None:
        sqlite_index_path = destination_dir / "semantic_index.sqlite3"
    else:
        sqlite_index_path = sqlite_index_path.resolve()

    result = run_semantic_coverage_sqlite(
        reference_input=reference_meta,
        ualextractor_input=ualextractor_meta,
        reference_format_override=args.reference_format,
        ualextractor_format_override=args.ualextractor_format,
        sqlite_db_path=sqlite_index_path,
    )
    try:
        write_semantic_coverage_package(
            result=result,
            reference_input=reference_meta,
            ualextractor_input=ualextractor_meta,
            destination_dir=destination_dir,
            replace_existing=bool(args.output is not None and args.force),
        )
    except ValueError as error:
        if str(error) == "destination directory must not match either input file":
            parser.error("output directory must not overwrite an input file")
        parser.error(str(error))
    except FileExistsError as error:
        message = str(error)
        if args.output is not None and not args.force:
            parser.error(f"{message}. Use --force to overwrite.")
        parser.error(message)
    except OSError as error:
        parser.error(str(error))

    print(f"Semantic coverage package directory: {destination_dir}", file=sys.stderr)
    print(f"Semantic SQLite index: {result.sqlite_db_path}", file=sys.stderr)
    if result.ual_index_reused:
        print("Semantic SQLite index reuse: YES", file=sys.stderr)
    else:
        print("Semantic SQLite index reuse: NO (rebuilt)", file=sys.stderr)
    print(
        f"Semantic SQLite index build seconds: {result.ual_index_build_seconds:.6f}",
        file=sys.stderr,
    )
    if args.downloads and args.force:
        print(
            "--force has no effect with --downloads; the next available directory is selected.",
            file=sys.stderr,
        )
    if not result.pass_semantic_coverage:
        print(
            "Semantic coverage validation failed; see semantic_coverage_summary.txt for PASS = NO.",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_dry_run(
    root: Path,
    components: list[str],
    filter_spec: FilterSpec | None = None,
    output_format: str = "jsonl",
    downloads: bool = False,
    output: Path | None = None,
) -> int:
    """Perform dry-run preflight without calling decoder or creating output."""
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}", file=sys.stderr)
        return 0
    if len(datasets) > 1:
        raise ValueError("decode requires a root containing exactly one dataset")

    dataset = datasets[0]
    inspector = Inspector()
    inspection_result = inspector.inspect(dataset)

    # Inventory traces
    inventory = TraceInventoryScanner().scan(inspection_result)

    # Filter inventory by requested components
    selected_traces = []
    total_bytes = 0
    for trace_file in inventory.trace_files:
        if trace_file.component in components:
            selected_traces.append(trace_file)
            total_bytes += trace_file.size_bytes

    # Sort deterministically by path
    selected_traces.sort(key=lambda t: t.path)

    # Print dry-run report to stderr
    print("DRY RUN — No decoder will be executed, no output will be created", file=sys.stderr)
    print(f"Dataset: {dataset.dataset_root.name}", file=sys.stderr)
    print(f"Evidence root: {dataset.dataset_root}", file=sys.stderr)
    print(f"Components: {', '.join(components)}", file=sys.stderr)
    print(f"Selected traces: {len(selected_traces)}", file=sys.stderr)
    print(f"Selected bytes: {total_bytes}", file=sys.stderr)
    print(f"Output format: {output_format}", file=sys.stderr)

    # Print filter summary
    filter_summary = format_filter_summary(filter_spec)
    print(f"Filters: {filter_summary}", file=sys.stderr)
    if filter_spec is not None and filter_spec.time_filter_active:
        print("[Time window]", file=sys.stderr)
        print(f"Examiner start: {filter_spec.start_raw}", file=sys.stderr)
        print(
            f"Effective UTC start: {filter_spec.effective_start_utc_text}",
            file=sys.stderr,
        )
        print(f"Start semantics: {filter_spec.start_semantics}", file=sys.stderr)
        print(f"Examiner end: {filter_spec.end_raw}", file=sys.stderr)
        print(
            f"Effective UTC end: {filter_spec.effective_end_utc_text}",
            file=sys.stderr,
        )
        print(f"End semantics: {filter_spec.end_semantics}", file=sys.stderr)
        print(
            "record-level time membership is evaluated only after trace "
            "records are decoded (after decoding); dry-run trace selection is based on "
            "metadata/component/path only.",
            file=sys.stderr,
        )

    # Print each selected trace
    print("Traces:", file=sys.stderr)
    for trace in selected_traces:
        print(f"  {trace.path} ({trace.size_bytes} bytes)", file=sys.stderr)

    # Show proposed output path if explicitly provided
    if output is not None:
        report_path = output.with_name(output.stem + "_validation.txt")
        print(f"Proposed output: {output}", file=sys.stderr)
        print(f"Proposed report: {report_path}", file=sys.stderr)

    # Show proposed Downloads behavior if requested
    if downloads:
        descriptor = choose_auto_output_descriptor(filter_spec)
        ext = "csv" if output_format == "csv" else "jsonl"
        try:
            out_path, report_path = propose_auto_output_paths(root, descriptor, ext)
            print(f"Proposed output: {out_path}", file=sys.stderr)
            print(f"Proposed report: {report_path}", file=sys.stderr)
        except ForensicOutputError as error:
            print(f"Proposed output error: {error}", file=sys.stderr)

    print("--force has no effect in dry-run mode (no output created)", file=sys.stderr)

    return 0



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
    dry_run: bool = False,
) -> int:
    datasets = UFEDFinder().find_datasets(root)
    if not datasets:
        print(f"No valid UFED dataset found under: {root.expanduser()}")
        return 0
    if len(datasets) > 1:
        raise ValueError("decode requires a root containing exactly one dataset")

    # Handle dry-run mode before any decoder processing
    if dry_run:
        return _run_dry_run(root, components, filter_spec, output_format, downloads, output)

    report_path: Path | None = None
    # handle automatic Downloads naming if requested and no explicit output provided
    if output is None and downloads:
        descriptor = choose_auto_output_descriptor(filter_spec)
        ext = "csv" if output_format == "csv" else "jsonl"
        try:
            out_path, report_path = auto_output_paths(root, descriptor, ext)
        except ForensicOutputError as error:
            print(error, file=sys.stderr)
            return 1
        output = out_path
    execution_start = _now_iso()

    # Print filter summary to stderr before decoding starts
    print(f"Active filters: {format_filter_summary(filter_spec)}", file=sys.stderr)

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
                "records_time_matched": getattr(r, "records_time_matched", 0),
                "records_time_filtered_out": getattr(r, "records_time_filtered_out", 0),
                "records_time_invalid": getattr(r, "records_time_invalid", 0),
                "records_filter_evaluated": getattr(r, "records_filter_evaluated", 0),
                "records_filter_matched": getattr(r, "records_filter_matched", 0),
                "records_filter_filtered_out": getattr(r, "records_filter_filtered_out", 0),
                "succeeded": r.succeeded,
                "diagnostics": list(r.diagnostics),
            }
            for r in summary.trace_results
        ]

        execution_end = _now_iso()

        fs_repr = format_filter_summary(filter_spec)

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
            time_window_applied=bool(filter_spec and filter_spec.time_filter_active),
            examiner_start=filter_spec.start_raw if filter_spec else None,
            effective_utc_start=(
                filter_spec.effective_start_utc_text if filter_spec else None
            ),
            start_semantics=filter_spec.start_semantics if filter_spec else None,
            examiner_end=filter_spec.end_raw if filter_spec else None,
            effective_utc_end=(
                filter_spec.effective_end_utc_text if filter_spec else None
            ),
            end_semantics=filter_spec.end_semantics if filter_spec else None,
            trace_results=trace_results,
            records_decoded=summary.records_decoded,
            records_matched=summary.records_matched,
            records_filtered_out=summary.records_filtered_out,
            records_time_matched=getattr(summary, "records_time_matched", 0),
            records_time_filtered_out=getattr(summary, "records_time_filtered_out", 0),
            records_time_invalid=getattr(summary, "records_time_invalid", 0),
            records_filter_evaluated=getattr(summary, "records_filter_evaluated", 0),
            records_filter_matched=getattr(summary, "records_filter_matched", 0),
            records_filter_filtered_out=getattr(summary, "records_filter_filtered_out", 0),
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
    parser = _build_parser()
    args = parser.parse_args(argv)
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
           args.dry_run,
       )
    if args.command == "compare":
       return _run_compare(parser, args)
    if args.command == "compare-semantic":
       return _run_semantic_compare(parser, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())