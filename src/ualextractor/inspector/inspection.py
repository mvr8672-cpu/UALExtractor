from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

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
        trace_file_count: Number of files matching `*.tracev3` found recursively under db.
        status: InspectionStatus indicating completeness or invalidity.
    """

    dataset: Dataset
    has_diagnostics: bool
    has_uuidtext: bool
    optional_folders: dict[str, bool]
    trace_file_count: int
    status: InspectionStatus
