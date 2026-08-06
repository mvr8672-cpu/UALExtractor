from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from ualextractor.inspector.inspection import InspectionResult, InspectionStatus
from ualextractor.models import Dataset

logger = logging.getLogger(__name__)

# Folder name constants
REQUIRED_FOLDERS = ("diagnostics", "uuidtext")
OPTIONAL_FOLDERS = ("persist", "highvolume", "special", "signpost", "timesync")

TRACE_GLOB = "*.tracev3"


class Inspector:
    """Inspect a discovered UFED Dataset.

    The Inspector performs lightweight validation and counting only. It:
    - Verifies the dataset.db_path exists and is a directory.
    - Checks for presence of required folders (REQUIRED_FOLDERS).
    - Checks for presence of optional folders (OPTIONAL_FOLDERS).
    - Counts trace files with the ``.tracev3`` extension recursively.

    The Inspector does not modify evidence files and does not parse tracev3
    files — it only uses pathlib to examine the filesystem and returns an
    InspectionResult summarizing findings.
    """

    def inspect(self, dataset: Dataset) -> InspectionResult:
        """Inspect the given Dataset and return an InspectionResult.

        Args:
            dataset: Dataset to inspect.

        Returns:
            InspectionResult summarizing the inspection.
        """
        db_path = dataset.db_path
        if not db_path.exists() or not db_path.is_dir():
            logger.warning("Invalid dataset db path: %s", db_path)
            # Build empty optional_folders mapping
            empty_optional = {name: False for name in OPTIONAL_FOLDERS}
            return InspectionResult(
                dataset=dataset,
                has_diagnostics=False,
                has_uuidtext=False,
                optional_folders=empty_optional,
                trace_file_count=0,
                status=InspectionStatus.INVALID,
            )

        has_diagnostics, has_uuidtext = self._check_required_folders(db_path)
        optional_map = self._check_optional_folders(db_path)
        trace_count = self._count_trace_files(db_path)
        status = self._determine_status(has_diagnostics, has_uuidtext)

        result = InspectionResult(
            dataset=dataset,
            has_diagnostics=has_diagnostics,
            has_uuidtext=has_uuidtext,
            optional_folders=optional_map,
            trace_file_count=trace_count,
            status=status,
        )

        logger.info(
            "Inspection completed for %s: status=%s, traces=%d",
            db_path,
            status.name,
            trace_count,
        )
        return result

    def _check_required_folders(self, db_path: Path) -> tuple[bool, bool]:
        """Return (has_diagnostics, has_uuidtext)."""
        diagnostics = (db_path / "diagnostics").is_dir()
        uuidtext = (db_path / "uuidtext").is_dir()
        return diagnostics, uuidtext

    def _check_optional_folders(self, db_path: Path) -> dict[str, bool]:
        """Return a mapping of optional folder name -> presence."""
        return {name: (db_path / name).is_dir() for name in OPTIONAL_FOLDERS}

    def _count_trace_files(self, db_path: Path) -> int:
        """Count files matching TRACE_GLOB recursively under db_path."""
        count = 0
        for p in db_path.rglob(TRACE_GLOB):
            if p.is_file():
                count += 1
        return count

    def _determine_status(self, has_diagnostics: bool, has_uuidtext: bool) -> InspectionStatus:
        """Return InspectionStatus based on required folder presence."""
        if has_diagnostics and has_uuidtext:
            return InspectionStatus.COMPLETE
        return InspectionStatus.INCOMPLETE
