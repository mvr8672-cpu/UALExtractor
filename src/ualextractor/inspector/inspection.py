from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ualextractor.models import Dataset


class InspectionStatus(Enum):
    """Status of inspection for a Dataset."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


@dataclass
class InspectionResult:
    """Result of inspecting a Dataset.

    Attributes:
        dataset: The Dataset that was inspected.
        has_diagnostics: Whether a `diagnostics` directory exists under db.
        has_uuidtext: Whether a `uuidtext` directory exists under db.
        optional_folders: Mapping of optional folder name -> presence (e.g. 'persist': True)
        optional_folder_paths: Mapping of optional folder name -> discovered path.
        trace_file_count: Number of files matching `*.tracev3` found recursively under db.
        trace_files_by_directory: Mapping of containing directory -> trace count.
        status: InspectionStatus indicating completeness or invalidity.
    """

    dataset: Dataset
    has_diagnostics: bool
    has_uuidtext: bool
    optional_folders: dict[str, bool]
    trace_file_count: int
    status: InspectionStatus
    optional_folder_paths: dict[str, Path | None] = field(default_factory=dict)
    trace_files_by_directory: dict[Path, int] = field(default_factory=dict)
