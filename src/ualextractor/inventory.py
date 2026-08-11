from __future__ import annotations

from pathlib import Path

from ualextractor.inspector.inspection import InspectionResult
from ualextractor.models import (
    TraceFile,
    TraceInventory,
    UNIFIED_LOG_TRACE_COMPONENTS,
)


TRACE_COMPONENTS = UNIFIED_LOG_TRACE_COMPONENTS


class TraceInventoryScanner:
    """Inventory Unified Log trace files using filesystem metadata only."""

    def scan(self, inspection: InspectionResult) -> TraceInventory:
        """Return a deterministic inventory for the inspected dataset.

        The scanner enumerates supported component directories discovered by
        ``Inspector`` and reads only paths and file sizes. It never opens trace
        files or reads their contents.
        """
        trace_files: list[TraceFile] = []
        for component in TRACE_COMPONENTS:
            component_path = inspection.optional_folder_paths.get(component.casefold())
            if component_path is None:
                continue
            trace_files.extend(self._scan_component(component_path, component))

        trace_files.sort(key=lambda trace_file: trace_file.path)
        return TraceInventory(tuple(trace_files))

    def _scan_component(self, component_path: Path, component: str) -> list[TraceFile]:
        trace_files: list[TraceFile] = []
        for path in component_path.rglob("*"):
            if path.is_file() and path.suffix.casefold() == ".tracev3":
                trace_files.append(
                    TraceFile(
                        path=path,
                        component=component,
                        filename=path.name,
                        size_bytes=path.stat().st_size,
                    )
                )
        return trace_files
