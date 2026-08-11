from __future__ import annotations

import logging
from pathlib import Path

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
            empty_optional = {name: False for name in OPTIONAL_FOLDERS}
            return InspectionResult(
                dataset=dataset,
                has_diagnostics=False,
                has_uuidtext=False,
                optional_folders=empty_optional,
                trace_file_count=0,
                status=InspectionStatus.INVALID,
                optional_folder_paths={name: None for name in OPTIONAL_FOLDERS},
            )

        has_diagnostics, has_uuidtext = self._check_required_folders(db_path)
        optional_map, optional_paths = self._check_optional_folders(
            db_path,
            db_path / "diagnostics",
        )
        trace_counts = self._count_trace_files(db_path)
        trace_count = sum(trace_counts.values())
        status = self._determine_status(has_diagnostics, has_uuidtext)

        result = InspectionResult(
            dataset=dataset,
            has_diagnostics=has_diagnostics,
            has_uuidtext=has_uuidtext,
            optional_folders=optional_map,
            trace_file_count=trace_count,
            status=status,
            optional_folder_paths=optional_paths,
            trace_files_by_directory=trace_counts,
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

    def _check_optional_folders(
        self,
        db_path: Path,
        diagnostics_path: Path,
    ) -> tuple[dict[str, bool], dict[str, Path | None]]:
        """Find optional folders below diagnostics, with a legacy db fallback."""
        paths: dict[str, Path | None] = {}
        for name in OPTIONAL_FOLDERS:
            path = self._find_directory(diagnostics_path, name)
            if path is None:
                path = self._find_directory(db_path, name)
            paths[name] = path
        return (
            {name: path is not None for name, path in paths.items()},
            paths,
        )

    def _find_directory(self, parent: Path, expected_name: str) -> Path | None:
        """Find a direct child directory without relying on name casing."""
        if not parent.is_dir():
            return None
        for child in sorted(parent.iterdir(), key=lambda path: path.name.casefold()):
            if child.is_dir() and child.name.casefold() == expected_name.casefold():
                return child
        return None

    def _count_trace_files(self, db_path: Path) -> dict[Path, int]:
        """Count trace files grouped by their containing directory."""
        counts: dict[Path, int] = {}
        for p in db_path.rglob(TRACE_GLOB):
            if p.is_file():
                counts[p.parent] = counts.get(p.parent, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: str(item[0])))

    def _determine_status(self, has_diagnostics: bool, has_uuidtext: bool) -> InspectionStatus:
        """Return InspectionStatus based on required folder presence."""
        if has_diagnostics and has_uuidtext:
            return InspectionStatus.COMPLETE
        return InspectionStatus.INCOMPLETE
