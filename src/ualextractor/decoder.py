from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ualextractor.inspector.inspection import InspectionResult
from ualextractor.inventory import TraceInventoryScanner


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
