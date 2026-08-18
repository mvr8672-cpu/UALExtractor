from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ualextractor.compare import (
    CanonicalComparisonRecord,
    CompareSide,
    InputFormat,
    REQUIRED_IDENTITY_FIELDS,
    canonicalize_record,
)


class CompareInputError(ValueError):
    """Raised when a comparison input file fails file-level validation."""


@dataclass(frozen=True)
class CompareInputReadResult:
    side: CompareSide
    source_path: Path
    source_format: InputFormat
    records: tuple[CanonicalComparisonRecord, ...]


def detect_input_format(path: Path, override: str | None = None) -> InputFormat:
    if override is not None:
        normalized = override.casefold()
        if normalized in ("jsonl", "ndjson"):
            return "jsonl"
        if normalized == "csv":
            return "csv"
        raise CompareInputError(
            f"Unsupported input format override: {override!r}. Supported formats: csv, jsonl, ndjson."
        )

    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return "csv"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    raise CompareInputError(
        f"Unsupported input format for {path}: {suffix or '(none)'}. Supported extensions: .csv, .jsonl, .ndjson."
    )


def read_compare_input(
    *,
    path: Path,
    side: CompareSide,
    format_override: str | None = None,
) -> CompareInputReadResult:
    source_format = detect_input_format(path, format_override)
    if source_format == "csv":
        records = tuple(_read_csv_records(path=path, side=side))
    else:
        records = tuple(_read_jsonl_records(path=path, side=side))
    return CompareInputReadResult(
        side=side,
        source_path=path,
        source_format=source_format,
        records=records,
    )


def _read_csv_records(*, path: Path, side: CompareSide) -> Iterable[CanonicalComparisonRecord]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            header = []
        except csv.Error as error:
            raise CompareInputError(
                f"CSV structural validation failed for {path}: {error}"
            ) from error

        missing_columns = [
            field for field in REQUIRED_IDENTITY_FIELDS if field not in header
        ]
        if missing_columns:
            raise CompareInputError(
                f"CSV file {path} is missing required column(s): {', '.join(missing_columns)}"
            )

        field_count = len(header)
        try:
            for index, row in enumerate(reader, start=1):
                if len(row) != field_count:
                    yield canonicalize_record(
                        side=side,
                        source_path=path,
                        source_format="csv",
                        source_record_number=index,
                        original_record=None,
                        invalid_reason="invalid_structure",
                        invalid_detail=(
                            f"row has {len(row)} columns but header has {field_count}"
                        ),
                    )
                    continue
                payload = dict(zip(header, row))
                yield canonicalize_record(
                    side=side,
                    source_path=path,
                    source_format="csv",
                    source_record_number=index,
                    original_record=payload,
                )
        except csv.Error as error:
            raise CompareInputError(
                f"CSV structural validation failed for {path}: {error}"
            ) from error


def _read_jsonl_records(
    *, path: Path, side: CompareSide
) -> Iterable[CanonicalComparisonRecord]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            text = raw_line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as error:
                yield canonicalize_record(
                    side=side,
                    source_path=path,
                    source_format="jsonl",
                    source_record_number=line_number,
                    original_record=None,
                    invalid_reason="invalid_json",
                    invalid_detail=str(error),
                )
                continue
            if not isinstance(parsed, dict):
                yield canonicalize_record(
                    side=side,
                    source_path=path,
                    source_format="jsonl",
                    source_record_number=line_number,
                    original_record=None,
                    invalid_reason="invalid_structure",
                    invalid_detail="JSONL record must be an object",
                )
                continue
            yield canonicalize_record(
                side=side,
                source_path=path,
                source_format="jsonl",
                source_record_number=line_number,
                original_record=parsed,
            )
