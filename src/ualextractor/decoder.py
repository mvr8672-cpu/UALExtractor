from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Sequence

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
    diagnostics: tuple[str, ...]
    succeeded: bool


@dataclass(frozen=True)
class BatchDecodeSummary:
    """Summary of a batch decode operation."""

    requested_components: tuple[str, ...]
    traces_attempted: int
    traces_succeeded: int
    traces_failed: int
    total_records: int
    records_by_component: dict[str, int]
    trace_results: tuple[TraceDecodeResult, ...]
    elapsed_seconds: float


class RustDecoder:
    """Invoke the cross-platform Mandiant decoder helper for one trace file."""

    def __init__(self, executable: Path) -> None:
        self.executable = executable

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

       if output_path is not None:
           self._ensure_output_path(output_path, force, inspection)
           writer: IO[str] = output_path.open("w", encoding="utf-8")
           should_close_writer = True
       else:
           writer = sys.stdout
           should_close_writer = False

       start_time = time.perf_counter()
       trace_results: list[TraceDecodeResult] = []
       try:
           for trace_file in trace_files:
               trace_result = self._decode_trace(
                   inspection,
                   trace_file,
                   writer,
               )
               trace_results.append(trace_result)
               if not trace_result.succeeded and stop_on_error:
                   break
       finally:
           if should_close_writer:
               writer.close()

       total_records = sum(result.record_count for result in trace_results)
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
       diagnostics: list[str] = []
       succeeded = True

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

           payload["source_trace_path"] = str(trace_file.path)
           payload["component"] = trace_file.component
           writer.write(json.dumps(payload, sort_keys=True) + "\n")
           writer.flush()
           record_count += 1

       stderr = process.stderr.read()
       process.wait()
       if stderr.strip():
           diagnostics.extend(line for line in stderr.splitlines() if line.strip())

       if process.returncode != 0:
           diagnostics.append(
               f"Decoder exited with status {process.returncode}"
           )
           succeeded = False

       return TraceDecodeResult(
           trace_path=trace_file.path,
           component=trace_file.component,
           exit_code=process.returncode,
           record_count=record_count,
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
