from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ualextractor.compare_io import CompareInputError, detect_input_format
from ualextractor.compare_semantic import (
    CompareSide,
    InputFormat,
    SemanticRecord,
    canonicalize_semantic_record,
)


@dataclass(frozen=True)
class SemanticInputScanResult:
    side: CompareSide
    source_path: Path
    source_format: InputFormat
    total_records: int
    invalid_records: int


def iterate_semantic_records(
    *,
    path: Path,
    side: CompareSide,
    format_override: str | None = None,
) -> tuple[InputFormat, Iterable[SemanticRecord]]:
    source_format = detect_input_format(path, format_override)
    if source_format == "csv":
        return source_format, _read_csv_records(path=path, side=side)
    return source_format, _read_jsonl_records(path=path, side=side)


def scan_semantic_input(
    *,
    path: Path,
    side: CompareSide,
    format_override: str | None = None,
) -> SemanticInputScanResult:
    source_format, records = iterate_semantic_records(
        path=path,
        side=side,
        format_override=format_override,
    )
    total = 0
    invalid = 0
    for record in records:
        total += 1
        if not record.is_valid:
            invalid += 1
    return SemanticInputScanResult(
        side=side,
        source_path=path,
        source_format=source_format,
        total_records=total,
        invalid_records=invalid,
    )


def _read_csv_records(*, path: Path, side: CompareSide) -> Iterable[SemanticRecord]:
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

        field_count = len(header)
        try:
            for index, row in enumerate(reader, start=1):
                if len(row) != field_count:
                    yield canonicalize_semantic_record(
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
                yield canonicalize_semantic_record(
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


def _read_jsonl_records(*, path: Path, side: CompareSide) -> Iterable[SemanticRecord]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            text = raw_line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as error:
                yield canonicalize_semantic_record(
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
                yield canonicalize_semantic_record(
                    side=side,
                    source_path=path,
                    source_format="jsonl",
                    source_record_number=line_number,
                    original_record=None,
                    invalid_reason="invalid_structure",
                    invalid_detail="JSONL record must be an object",
                )
                continue
            yield canonicalize_semantic_record(
                side=side,
                source_path=path,
                source_format="jsonl",
                source_record_number=line_number,
                original_record=parsed,
            )
