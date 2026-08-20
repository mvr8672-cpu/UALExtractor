from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Sequence

from ualextractor.filtering import FilterSpec, TimeClassification
from ualextractor.inspector.inspection import InspectionResult
from ualextractor.inventory import TraceInventoryScanner
from ualextractor.models import UNIFIED_LOG_TRACE_COMPONENTS


@dataclass(frozen=True)
class DecoderRecord:
    """One structured record emitted by the Rust decoder helper."""

    timestamp: str | None
    process: str | None
    pid: int | None
    subsystem: str | None
    category: str | None
    log_type: str | None
    event_type: str | None
    message: str | None
    source_trace_path: str


@dataclass(frozen=True)
class DecoderResult:
    """Records and diagnostics returned by one helper invocation."""

    source_trace_path: Path
    records: tuple[DecoderRecord, ...]
    diagnostics: tuple[str, ...]


class DecoderError(RuntimeError):
    """Raised when the decoder helper cannot produce valid JSONL."""


@dataclass(frozen=True)
class TraceDecodeResult:
    """Result of decoding one trace file in a batch."""

    trace_path: Path
    component: str
    exit_code: int
    record_count: int
    records_decoded: int = 0
    records_matched: int = 0
    records_filtered_out: int = 0
    records_time_matched: int = 0
    records_time_filtered_out: int = 0
    records_time_invalid: int = 0
    records_filter_evaluated: int = 0
    records_filter_matched: int = 0
    records_filter_filtered_out: int = 0
    diagnostics: tuple[str, ...] = ()
    succeeded: bool = True


@dataclass(frozen=True)
class BatchDecodeSummary:
    """Summary of a batch decode operation."""

    requested_components: tuple[str, ...]
    traces_attempted: int
    traces_succeeded: int
    traces_failed: int
    total_records: int
    records_decoded: int
    records_matched: int
    records_filtered_out: int
    records_time_matched: int
    records_time_filtered_out: int
    records_time_invalid: int
    records_filter_evaluated: int
    records_filter_matched: int
    records_filter_filtered_out: int
    records_by_component: dict[str, int]
    trace_results: tuple[TraceDecodeResult, ...]
    elapsed_seconds: float


def _resolve_decoder_executable(executable: Path) -> Path:
    candidate = executable.expanduser()

    if os.name == "nt" and candidate.suffix.lower() != ".exe":
        fallback = candidate.with_suffix(".exe")
        if fallback.name != candidate.name:
            return fallback

    return candidate


class RustDecoder:
    """Invoke the cross-platform Mandiant decoder helper for one trace file."""

    def __init__(self, executable: Path) -> None:
        self.executable = _resolve_decoder_executable(executable)

    def decode_one(
        self,
        inspection: InspectionResult,
        trace_path: Path | None = None,
    ) -> DecoderResult:
        """Decode exactly one deterministic HighVolume or Persist trace file."""
        inventory = TraceInventoryScanner().scan(inspection)
        candidates = [
            trace_file
            for trace_file in inventory.trace_files
            if trace_file.component in ("HighVolume", "Persist")
        ]
        if trace_path is None:
           if not candidates:
               raise DecoderError("No HighVolume or Persist tracev3 file was found")
           preferred_component = (
               "HighVolume"
               if any(item.component == "HighVolume" for item in candidates)
               else "Persist"
           )
           preferred = [
               item for item in candidates if item.component == preferred_component
           ]
           trace_path = min(preferred, key=lambda item: (item.size_bytes, item.path)).path
        elif trace_path not in {item.path for item in candidates}:
           raise DecoderError("The selected trace must be in HighVolume or Persist")

        diagnostics_path = inspection.dataset.diagnostics_path
        uuidtext_path = inspection.dataset.uuidtext_path
        timesync_path = inspection.optional_folder_paths.get("timesync")
        dsc_path = uuidtext_path / "dsc" if uuidtext_path is not None else None
        if diagnostics_path is None or uuidtext_path is None or timesync_path is None:
            raise DecoderError("UFED dataset is missing required decoder paths")

        command = [
            str(self.executable),
            "--trace",
            str(trace_path),
            "--diagnostics",
            str(diagnostics_path),
            "--uuidtext",
            str(uuidtext_path),
            "--timesync",
            str(timesync_path),
        ]
        if dsc_path is not None and dsc_path.is_dir():
            command.extend(["--dsc", str(dsc_path)])

        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise DecoderError(
                f"Decoder exited with status {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )

        records = tuple(
            self._parse_record(line, trace_path)
            for line in completed.stdout.splitlines()
            if line.strip()
        )
        diagnostics = tuple(
            line for line in completed.stderr.splitlines() if line.strip()
        )
        return DecoderResult(trace_path, records, diagnostics)

    def decode_batch(
       self,
       inspection: InspectionResult,
       components: Sequence[str],
       output_path: Path | None = None,
       force: bool = False,
       stop_on_error: bool = False,
       filter_spec: FilterSpec | None = None,
       output_format: str = "jsonl",
    ) -> BatchDecodeSummary:
       """Decode an explicit batch of traces by component.

       The batch decoder streams JSONL records directly to stdout or an output
       file. It does not accumulate the complete decoded dataset in memory.
       """
       requested_components = self._normalize_components(components)
       if not requested_components:
           raise DecoderError("At least one component must be requested")

       inventory = TraceInventoryScanner().scan(inspection)
       trace_files = [
           trace_file
           for trace_file in inventory.trace_files
           if trace_file.component in requested_components
       ]
       trace_files.sort(
           key=lambda trace_file: (
               UNIFIED_LOG_TRACE_COMPONENTS.index(trace_file.component),
               str(trace_file.path),
           )
       )

       csv_writer = None
       if output_path is not None:
           self._ensure_output_path(output_path, force, inspection)
           # open with newline="" to let csv module handle newlines correctly
           writer: IO[str] = output_path.open("w", encoding="utf-8", newline="")
           should_close_writer = True
       else:
           writer = sys.stdout
           should_close_writer = False

       if output_format == "csv":
           csv_writer = csv.writer(writer)
           # write header once
           csv_writer.writerow([
               "timestamp",
               "process",
               "pid",
               "subsystem",
               "category",
               "event_type",
               "log_type",
               "message",
               "component",
               "source_trace_path",
           ])
           try:
               writer.flush()
           except Exception:
               pass

       start_time = time.perf_counter()
       trace_results: list[TraceDecodeResult] = []
       try:
           # prepare progress tracking
           total_bytes = sum(getattr(tf, 'size_bytes', 0) for tf in trace_files)
           processed_bytes = 0
           current_trace_index = 0
           last_progress_time = time.perf_counter()

           for trace_file in trace_files:
               current_trace_index += 1
               # print progress start for this trace
               try:
                   pct = (processed_bytes / total_bytes * 100) if total_bytes else (current_trace_index / max(1, len(trace_files)) * 100)
                   print(
                       f"{trace_file.component} [{current_trace_index}/{len(trace_files)}] {pct:5.1f}%\n"
                       f"decoded={0} matched={0} elapsed=0:00:00",
                       file=sys.stderr,
                   )
               except Exception:
                   pass

               trace_result = self._decode_trace(
                   inspection,
                   trace_file,
                   writer,
                   filter_spec,
                   output_format=output_format,
                   csv_writer=csv_writer,
               )
               trace_results.append(trace_result)
               # advance bytes
               processed_bytes += getattr(trace_file, 'size_bytes', 0)
               # print progress after finishing trace
               try:
                   pct = (processed_bytes / total_bytes * 100) if total_bytes else (current_trace_index / max(1, len(trace_files)) * 100)
                   print(
                       f"{trace_file.component} [{current_trace_index}/{len(trace_files)}] {pct:5.1f}%\n"
                       f"decoded={trace_result.records_decoded} matched={trace_result.records_matched} elapsed={time.strftime('%H:%M:%S', time.gmtime(time.perf_counter()-start_time))}",
                       file=sys.stderr,
                   )
               except Exception:
                   pass

               if not trace_result.succeeded and stop_on_error:
                   break
       finally:
           if should_close_writer:
               writer.close()

       total_records = sum(result.record_count for result in trace_results)
       records_decoded = sum(result.records_decoded for result in trace_results)
       records_matched = sum(result.records_matched for result in trace_results)
       records_filtered_out = sum(result.records_filtered_out for result in trace_results)
       records_time_matched = sum(result.records_time_matched for result in trace_results)
       records_time_filtered_out = sum(
           result.records_time_filtered_out for result in trace_results
       )
       records_time_invalid = sum(result.records_time_invalid for result in trace_results)
       records_filter_evaluated = sum(
           result.records_filter_evaluated for result in trace_results
       )
       records_filter_matched = sum(
           result.records_filter_matched for result in trace_results
       )
       records_filter_filtered_out = sum(
           result.records_filter_filtered_out for result in trace_results
       )
       records_by_component = {
           component: 0 for component in UNIFIED_LOG_TRACE_COMPONENTS
       }
       for result in trace_results:
           records_by_component[result.component] += result.record_count

       elapsed_seconds = time.perf_counter() - start_time
       succeeded = sum(1 for result in trace_results if result.succeeded)
       failed = len(trace_results) - succeeded

       return BatchDecodeSummary(
           requested_components=tuple(requested_components),
           traces_attempted=len(trace_results),
           traces_succeeded=succeeded,
           traces_failed=failed,
           total_records=total_records,
           records_decoded=records_decoded,
           records_matched=records_matched,
           records_filtered_out=records_filtered_out,
           records_time_matched=records_time_matched,
           records_time_filtered_out=records_time_filtered_out,
           records_time_invalid=records_time_invalid,
           records_filter_evaluated=records_filter_evaluated,
           records_filter_matched=records_filter_matched,
           records_filter_filtered_out=records_filter_filtered_out,
           records_by_component=records_by_component,
           trace_results=tuple(trace_results),
           elapsed_seconds=elapsed_seconds,
       )

    def _normalize_components(self, components: Sequence[str]) -> list[str]:
       normalized: list[str] = []
       lower_to_component = {
           component.casefold(): component for component in UNIFIED_LOG_TRACE_COMPONENTS
       }
       for component in components:
           if component.casefold() not in lower_to_component:
               raise DecoderError(
                   f"Unknown component: {component}. "
                   f"Supported: {', '.join(UNIFIED_LOG_TRACE_COMPONENTS)}"
               )
           canonical = lower_to_component[component.casefold()]
           if canonical not in normalized:
               normalized.append(canonical)
       return normalized

    def _ensure_output_path(
       self, output_path: Path, force: bool, inspection: InspectionResult
    ) -> None:
       if output_path.exists() and not force:
           raise DecoderError(
               f"Output file already exists: {output_path}. "
               "Use --force to overwrite."
           )
       output_root = inspection.dataset.dataset_root.resolve()
       if output_path.resolve().is_relative_to(output_root):
           raise DecoderError(
               "Output path must not be inside the evidence dataset"
           )

    def _decode_trace(
       self,
       inspection: InspectionResult,
       trace_file: "TraceFile",
       writer: IO[str],
       filter_spec: FilterSpec | None = None,
       *,
       output_format: str = "jsonl",
       csv_writer=None,
    ) -> TraceDecodeResult:
       diagnostics_path = inspection.dataset.diagnostics_path
       uuidtext_path = inspection.dataset.uuidtext_path
       timesync_path = inspection.optional_folder_paths.get("timesync")
       dsc_path = uuidtext_path / "dsc" if uuidtext_path is not None else None
       if diagnostics_path is None or uuidtext_path is None or timesync_path is None:
           raise DecoderError("UFED dataset is missing required decoder paths")

       command = [
           str(self.executable),
           "--trace",
           str(trace_file.path),
           "--diagnostics",
           str(diagnostics_path),
           "--uuidtext",
           str(uuidtext_path),
           "--timesync",
           str(timesync_path),
       ]
       if dsc_path is not None and dsc_path.is_dir():
           command.extend(["--dsc", str(dsc_path)])

       process = subprocess.Popen(
           command,
           stdout=subprocess.PIPE,
           stderr=subprocess.PIPE,
           text=True,
       )

       record_count = 0
       records_decoded = 0
       records_matched = 0
       records_filtered_out = 0
       records_time_matched = 0
       records_time_filtered_out = 0
       records_time_invalid = 0
       records_filter_evaluated = 0
       records_filter_matched = 0
       records_filter_filtered_out = 0
       diagnostics: list[str] = []
       succeeded = True

       time_filter_active = filter_spec is not None and filter_spec.time_filter_active

       assert process.stdout is not None
       assert process.stderr is not None
       for raw_line in process.stdout:
           line = raw_line.rstrip("\n")
           if not line.strip():
               continue
           try:
               payload = json.loads(line)
           except json.JSONDecodeError as error:
               diagnostics.append(
                   f"Malformed JSONL from decoder for {trace_file.path}: {error}"
               )
               succeeded = False
               continue
           if not isinstance(payload, dict):
               diagnostics.append(
                   f"Decoder JSONL record was not an object for {trace_file.path}"
               )
               succeeded = False
               continue

           records_decoded += 1
           payload["source_trace_path"] = str(trace_file.path)
           payload["component"] = trace_file.component

           if time_filter_active:
               assert filter_spec is not None
               time_classification = filter_spec.classify_record_time(payload)
               if time_classification == TimeClassification.TIME_INVALID:
                   records_time_invalid += 1
                   records_filtered_out += 1
                   continue
               if time_classification == TimeClassification.TIME_FILTERED_OUT:
                   records_time_filtered_out += 1
                   records_filtered_out += 1
                   continue
               records_time_matched += 1
               records_filter_evaluated += 1
               if not filter_spec.matches_generic(payload):
                   records_filter_filtered_out += 1
                   records_filtered_out += 1
                   continue
               records_filter_matched += 1
           elif filter_spec is not None:
               records_filter_evaluated += 1
               if not filter_spec.matches_generic(payload):
                   records_filter_filtered_out += 1
                   records_filtered_out += 1
                   continue
               records_filter_matched += 1
           else:
               records_filter_evaluated += 1
               records_filter_matched += 1
           # Output according to requested format
           if output_format == "jsonl":
               writer.write(json.dumps(payload, sort_keys=True) + "\n")
               try:
                   writer.flush()
               except Exception:
                   pass
           elif output_format == "csv":
               # write CSV row in exact header order
               row = [
                   payload.get("timestamp") or "",
                   payload.get("process") or "",
                   str(payload.get("pid")) if payload.get("pid") is not None else "",
                   payload.get("subsystem") or "",
                   payload.get("category") or "",
                   payload.get("event_type") or "",
                   payload.get("log_type") or "",
                   payload.get("message") or "",
                   payload.get("component") or "",
                   payload.get("source_trace_path") or "",
               ]
               if csv_writer is None:
                   # fallback: create a temporary csv writer
                   local_csv = csv.writer(writer)
                   local_csv.writerow(row)
               else:
                   csv_writer.writerow(row)
               try:
                   writer.flush()
               except Exception:
                   pass
           else:
               raise RuntimeError(f"Unknown output format: {output_format}")

           record_count += 1
           records_matched += 1

       stderr = process.stderr.read()
       process.wait()
       if stderr.strip():
           diagnostics.extend(line for line in stderr.splitlines() if line.strip())

       if process.returncode != 0:
           diagnostics.append(
               f"Decoder exited with status {process.returncode}"
           )
           succeeded = False

       # If output is to stdout (streaming), emit diagnostics to stderr immediately
       try:
           if writer is sys.stdout and diagnostics:
               for d in diagnostics:
                   print(d, file=sys.stderr)
       except Exception:
           # best-effort: do not fail decoding if printing diagnostics fails
           pass

       return TraceDecodeResult(
           trace_path=trace_file.path,
           component=trace_file.component,
           exit_code=process.returncode,
           record_count=record_count,
           records_decoded=records_decoded,
           records_matched=records_matched,
           records_filtered_out=records_filtered_out,
           records_time_matched=records_time_matched,
           records_time_filtered_out=records_time_filtered_out,
           records_time_invalid=records_time_invalid,
           records_filter_evaluated=records_filter_evaluated,
           records_filter_matched=records_filter_matched,
           records_filter_filtered_out=records_filter_filtered_out,
           diagnostics=tuple(diagnostics),
           succeeded=succeeded,
       )

    def _parse_record(self, line: str, source_trace_path: Path) -> DecoderRecord:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise DecoderError("Decoder stdout contained invalid JSONL") from error
        if not isinstance(payload, dict):
            raise DecoderError("Decoder JSONL record must be an object")
        return DecoderRecord(
            timestamp=payload.get("timestamp"),
            process=payload.get("process"),
            pid=payload.get("pid"),
            subsystem=payload.get("subsystem"),
            category=payload.get("category"),
            log_type=payload.get("log_type"),
            event_type=payload.get("event_type"),
            message=payload.get("message"),
            source_trace_path=payload.get("source_trace_path", str(source_trace_path)),
        )
