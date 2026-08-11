from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass(frozen=True)
class Dataset:
    """Represents a discovered UFED dataset.

    A Dataset corresponds to a discovered "db" directory. It stores the
    dataset root containing that directory and the discovered diagnostics and
    uuidtext paths.
    """

    dataset_root: Path
    db_path: Path
    diagnostics_path: Optional[Path] = None
    uuidtext_path: Optional[Path] = None
    is_complete: bool = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "is_complete",
            self.diagnostics_path is not None and self.uuidtext_path is not None,
        )


@dataclass(frozen=True)
class TraceFile:
    """Represents one discovered trace file without reading its contents."""

    path: Path
    component: str
    filename: str
    size_bytes: int


UNIFIED_LOG_TRACE_COMPONENTS = ("HighVolume", "Persist", "Signpost", "Special")


@dataclass(frozen=True)
class TraceInventory:
    """Immutable inventory of trace files discovered under Unified Log components."""

    trace_files: tuple[TraceFile, ...]

    @property
    def total_count(self) -> int:
        """Return the total number of discovered trace files."""
        return len(self.trace_files)

    @property
    def total_size_bytes(self) -> int:
        """Return the combined size of all discovered trace files."""
        return sum(trace_file.size_bytes for trace_file in self.trace_files)

    @property
    def count_by_component(self) -> dict[str, int]:
        """Return deterministic trace counts for every supported component."""
        return self._summary_by_component(lambda trace_file: 1)

    @property
    def size_by_component(self) -> dict[str, int]:
        """Return deterministic trace sizes for every supported component."""
        return self._summary_by_component(lambda trace_file: trace_file.size_bytes)

    def _summary_by_component(self, value: Callable[[TraceFile], int]) -> dict[str, int]:
        summary = {component: 0 for component in UNIFIED_LOG_TRACE_COMPONENTS}
        for trace_file in self.trace_files:
            summary[trace_file.component] = summary.get(trace_file.component, 0) + value(
                trace_file
            )
        return summary
