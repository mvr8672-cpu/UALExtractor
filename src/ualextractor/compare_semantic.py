from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ualextractor.filtering import _parse_timestamp_to_epoch_ns

CompareSide = Literal["reference", "ualextractor"]
InputFormat = Literal["csv", "jsonl"]

_FRACTION_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?P<fraction>\.\d+)?(?P<tz>Z|z|[+-]\d{2}:\d{2})?$"
)


@dataclass(frozen=True)
class SemanticRecord:
    side: CompareSide
    source_path: Path
    source_format: InputFormat
    source_record_number: int
    original_record: dict[str, Any] | None
    is_valid: bool
    invalid_reason: str | None
    invalid_field: str | None
    invalid_detail: str | None
    message: str | None
    process: str | None
    process_basename: str | None
    pid_raw: Any
    normalized_pid: int | None
    subsystem: str | None
    category: str | None
    event_type: str | None
    log_type: str | None
    timestamp_text: str | None
    timestamp_epoch_ns: int | None
    timestamp_precision_digits: int | None


def normalize_nullable_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("value must be UTF-8 text when present")
    if value == "":
        return None
    return value


def normalize_required_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UTF-8 text value")
    return value


def normalize_pid(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("pid must not be bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("pid must be >= 0")
        return value
    if isinstance(value, str):
        if value == "":
            raise ValueError("pid value is empty")
        if not value.isdecimal():
            raise ValueError("pid string must contain decimal digits only")
        parsed = int(value)
        if parsed < 0:
            raise ValueError("pid must be >= 0")
        return parsed
    raise ValueError("pid must be an integer or decimal digit string")


def normalize_process_basename(value: str | None) -> str | None:
    if value is None:
        return None
    basename = value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return basename if basename else value


def timestamp_precision_digits(value: str) -> int | None:
    matched = _FRACTION_RE.match(value.strip())
    if matched is None:
        return None
    fraction = matched.group("fraction")
    if fraction is None:
        return 0
    return len(fraction) - 1


def normalize_epoch_ns_to_precision(epoch_ns: int, digits: int) -> int:
    step = 10 ** (9 - digits)
    return (epoch_ns // step) * step


def compare_timestamp_texts(
    reference_timestamp: str | None, ualextractor_timestamp: str | None
) -> str:
    if reference_timestamp is None or ualextractor_timestamp is None:
        return "unknown_not_comparable"
    try:
        ref_ns = _parse_timestamp_to_epoch_ns(reference_timestamp)
        ua_ns = _parse_timestamp_to_epoch_ns(ualextractor_timestamp)
    except ValueError:
        return "unknown_not_comparable"

    if ref_ns == ua_ns:
        return "exact"

    ref_digits = timestamp_precision_digits(reference_timestamp)
    ua_digits = timestamp_precision_digits(ualextractor_timestamp)
    if ref_digits is None or ua_digits is None:
        return "unknown_not_comparable"

    common_digits = min(ref_digits, ua_digits)
    if normalize_epoch_ns_to_precision(ref_ns, common_digits) == normalize_epoch_ns_to_precision(
        ua_ns, common_digits
    ):
        return "precision_normalized_match"
    return "different"


def canonicalize_semantic_record(
    *,
    side: CompareSide,
    source_path: Path,
    source_format: InputFormat,
    source_record_number: int,
    original_record: dict[str, Any] | None,
    invalid_reason: str | None = None,
    invalid_detail: str | None = None,
) -> SemanticRecord:
    if original_record is None:
        return SemanticRecord(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=None,
            is_valid=False,
            invalid_reason=invalid_reason or "invalid_structure",
            invalid_field=None,
            invalid_detail=invalid_detail,
            message=None,
            process=None,
            process_basename=None,
            pid_raw=None,
            normalized_pid=None,
            subsystem=None,
            category=None,
            event_type=None,
            log_type=None,
            timestamp_text=None,
            timestamp_epoch_ns=None,
            timestamp_precision_digits=None,
        )

    if "pid" not in original_record:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="missing_required_value",
            invalid_field="pid",
            invalid_detail="field is missing",
        )
    if "message" not in original_record:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="missing_required_value",
            invalid_field="message",
            invalid_detail="field is missing",
        )

    try:
        message = normalize_required_text(original_record.get("message"), field="message")
    except ValueError as error:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="invalid_required_type",
            invalid_field="message",
            invalid_detail=str(error),
        )

    pid_raw = original_record.get("pid")
    try:
        normalized_pid = normalize_pid(pid_raw)
    except ValueError as error:
        reason = "empty_required_value" if pid_raw == "" else "invalid_pid"
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason=reason,
            invalid_field="pid",
            invalid_detail=str(error),
        )

    try:
        process = normalize_nullable_text(original_record.get("process"))
        subsystem = normalize_nullable_text(original_record.get("subsystem"))
        category = normalize_nullable_text(original_record.get("category"))
        event_type = normalize_nullable_text(original_record.get("event_type"))
        log_type = normalize_nullable_text(original_record.get("log_type"))
    except ValueError as error:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="invalid_optional_type",
            invalid_field=None,
            invalid_detail=str(error),
        )

    timestamp_value = original_record.get("timestamp")
    if timestamp_value is None:
        timestamp_text = None
    elif isinstance(timestamp_value, str):
        timestamp_text = timestamp_value
    else:
        timestamp_text = str(timestamp_value)

    timestamp_epoch_ns: int | None = None
    timestamp_digits: int | None = None
    if timestamp_text is not None and timestamp_text.strip() != "":
        timestamp_digits = timestamp_precision_digits(timestamp_text)
        try:
            timestamp_epoch_ns = _parse_timestamp_to_epoch_ns(timestamp_text)
        except ValueError:
            timestamp_epoch_ns = None

    return SemanticRecord(
        side=side,
        source_path=source_path,
        source_format=source_format,
        source_record_number=source_record_number,
        original_record=dict(original_record),
        is_valid=True,
        invalid_reason=None,
        invalid_field=None,
        invalid_detail=None,
        message=message,
        process=process,
        process_basename=normalize_process_basename(process),
        pid_raw=pid_raw,
        normalized_pid=normalized_pid,
        subsystem=subsystem,
        category=category,
        event_type=event_type,
        log_type=log_type,
        timestamp_text=timestamp_text,
        timestamp_epoch_ns=timestamp_epoch_ns,
        timestamp_precision_digits=timestamp_digits,
    )


def _invalid_from_record(
    *,
    side: CompareSide,
    source_path: Path,
    source_format: InputFormat,
    source_record_number: int,
    original_record: dict[str, Any],
    invalid_reason: str,
    invalid_field: str | None,
    invalid_detail: str,
) -> SemanticRecord:
    process = original_record.get("process") if isinstance(original_record.get("process"), str) else None
    subsystem = original_record.get("subsystem") if isinstance(original_record.get("subsystem"), str) else None
    category = original_record.get("category") if isinstance(original_record.get("category"), str) else None
    event_type = original_record.get("event_type") if isinstance(original_record.get("event_type"), str) else None
    log_type = original_record.get("log_type") if isinstance(original_record.get("log_type"), str) else None
    message = original_record.get("message") if isinstance(original_record.get("message"), str) else None
    timestamp_text = original_record.get("timestamp") if isinstance(original_record.get("timestamp"), str) else None
    return SemanticRecord(
        side=side,
        source_path=source_path,
        source_format=source_format,
        source_record_number=source_record_number,
        original_record=dict(original_record),
        is_valid=False,
        invalid_reason=invalid_reason,
        invalid_field=invalid_field,
        invalid_detail=invalid_detail,
        message=message,
        process=process,
        process_basename=normalize_process_basename(process),
        pid_raw=original_record.get("pid"),
        normalized_pid=None,
        subsystem=subsystem,
        category=category,
        event_type=event_type,
        log_type=log_type,
        timestamp_text=timestamp_text,
        timestamp_epoch_ns=None,
        timestamp_precision_digits=timestamp_precision_digits(timestamp_text) if timestamp_text else None,
    )


def semantic_identity_key(record: SemanticRecord) -> tuple[Any, ...] | None:
    if not record.is_valid:
        return None
    return (
        record.message,
        record.process_basename,
        record.normalized_pid,
        record.subsystem,
        record.category,
    )
