from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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
