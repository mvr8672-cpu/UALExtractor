from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from ualextractor.models import Dataset

logger = logging.getLogger(__name__)


class UFEDFinder:
    """Locate UFED datasets by finding `db` directories recursively."""

    REQUIRED_CHILDREN = ("diagnostics", "uuidtext")

    def find_datasets(self, root: Path) -> List[Dataset]:
        """Search recursively for UFED datasets under the given root path.

        A valid dataset is anchored at a directory named ``db`` and contains both
        ``diagnostics`` and ``uuidtext`` directories inside it.
        """
        root = root.expanduser().resolve()
        if not root.exists():
            logger.warning("Root path does not exist: %s", root)
            return []

        if not root.is_dir():
            logger.warning("Root path is not a directory: %s", root)
            return []

        datasets: list[Dataset] = []
        for db_path in root.rglob("db"):
            if not db_path.is_dir():
                continue

            diagnostics_path = db_path / "diagnostics"
            uuidtext_path = db_path / "uuidtext"
            if not diagnostics_path.is_dir() or not uuidtext_path.is_dir():
                logger.debug(
                    "Skipping db path %s because required children are missing",
                    db_path,
                )
                continue

            dataset = Dataset(
                dataset_root=db_path.parent,
                db_path=db_path,
                diagnostics_path=diagnostics_path,
                uuidtext_path=uuidtext_path,
            )
            datasets.append(dataset)
            logger.debug("Discovered dataset: %s", dataset)

        datasets.sort(key=lambda dataset: dataset.dataset_root)
        logger.info("Found %d valid dataset(s) under %s", len(datasets), root)
        return datasets