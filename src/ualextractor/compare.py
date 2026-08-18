from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ualextractor.filtering import _parse_timestamp_to_epoch_ns

CompareSide = Literal["left", "right"]
InputFormat = Literal["csv", "jsonl"]

REQUIRED_IDENTITY_FIELDS = (
    "timestamp",
    "process",
    "pid",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
)

OPTIONAL_PROVENANCE_FIELDS = ("component", "source_trace_path")

EXACT_MATCH_KEY_FIELDS = (
    "timestamp_epoch_ns",
    "normalized_pid",
    "process",
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
)

FIELD_DIFFERENCE_ORDER = (
    "subsystem",
    "category",
    "event_type",
    "log_type",
    "message",
)


@dataclass(frozen=True)
class CanonicalComparisonRecord:
    side: CompareSide
    source_path: Path
    source_format: InputFormat
    source_record_number: int
    original_record: dict[str, Any] | None
    original_timestamp_text: str | None
    timestamp_epoch_ns: int | None
    original_pid_value: Any
    normalized_pid: int | None
    process: str | None
    subsystem: str | None
    category: str | None
    event_type: str | None
    log_type: str | None
    message: str | None
    component: str | None
    source_trace_path: str | None
    is_valid: bool
    invalid_reason: str | None
    invalid_field: str | None
    invalid_detail: str | None


@dataclass(frozen=True)
class ExactMatchPair:
    left: CanonicalComparisonRecord
    right: CanonicalComparisonRecord


@dataclass(frozen=True)
class FieldDifferencePair:
    left: CanonicalComparisonRecord
    right: CanonicalComparisonRecord
    differing_fields: tuple[str, ...]


@dataclass(frozen=True)
class ComparisonAccounting:
    left_input_records: int
    right_input_records: int
    left_valid_records: int
    right_valid_records: int
    left_invalid_records: int
    right_invalid_records: int
    left_exact_match_records: int
    right_exact_match_records: int
    left_difference_records: int
    right_difference_records: int
    left_only_records: int
    right_only_records: int
    duplicate_key_groups_left: int
    duplicate_key_groups_right: int
    duplicate_records_left: int
    duplicate_records_right: int


@dataclass(frozen=True)
class ComparisonInvariantResult:
    left_accounting_ok: bool
    right_accounting_ok: bool
    left_valid_breakdown_ok: bool
    right_valid_breakdown_ok: bool
    exact_count_symmetry_ok: bool
    difference_count_symmetry_ok: bool

    @property
    def all_ok(self) -> bool:
        return (
            self.left_accounting_ok
            and self.right_accounting_ok
            and self.left_valid_breakdown_ok
            and self.right_valid_breakdown_ok
            and self.exact_count_symmetry_ok
            and self.difference_count_symmetry_ok
        )


@dataclass(frozen=True)
class ComparisonResult:
    exact_matches: tuple[ExactMatchPair, ...]
    field_differences: tuple[FieldDifferencePair, ...]
    left_only: tuple[CanonicalComparisonRecord, ...]
    right_only: tuple[CanonicalComparisonRecord, ...]
    left_invalid: tuple[CanonicalComparisonRecord, ...]
    right_invalid: tuple[CanonicalComparisonRecord, ...]
    accounting: ComparisonAccounting
    invariants: ComparisonInvariantResult


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


def canonicalize_record(
    *,
    side: CompareSide,
    source_path: Path,
    source_format: InputFormat,
    source_record_number: int,
    original_record: dict[str, Any] | None,
    invalid_reason: str | None = None,
    invalid_detail: str | None = None,
) -> CanonicalComparisonRecord:
    if original_record is None:
        return CanonicalComparisonRecord(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=None,
            original_timestamp_text=None,
            timestamp_epoch_ns=None,
            original_pid_value=None,
            normalized_pid=None,
            process=None,
            subsystem=None,
            category=None,
            event_type=None,
            log_type=None,
            message=None,
            component=None,
            source_trace_path=None,
            is_valid=False,
            invalid_reason=invalid_reason or "invalid_structure",
            invalid_field=None,
            invalid_detail=invalid_detail,
        )

    for field in REQUIRED_IDENTITY_FIELDS:
        if field not in original_record:
            return _invalid_from_record(
                side=side,
                source_path=source_path,
                source_format=source_format,
                source_record_number=source_record_number,
                original_record=original_record,
                invalid_reason="missing_required_value",
                invalid_field=field,
                invalid_detail="field is missing",
            )

    timestamp_raw = original_record.get("timestamp")
    if not isinstance(timestamp_raw, str):
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="invalid_timestamp",
            invalid_field="timestamp",
            invalid_detail="timestamp must be a UTF-8 text value",
        )
    if timestamp_raw == "":
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="empty_required_value",
            invalid_field="timestamp",
            invalid_detail="timestamp is empty",
        )

    try:
        timestamp_epoch_ns = _parse_timestamp_to_epoch_ns(timestamp_raw)
    except ValueError as error:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="invalid_timestamp",
            invalid_field="timestamp",
            invalid_detail=str(error),
        )

    pid_raw = original_record.get("pid")
    if pid_raw == "":
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="empty_required_value",
            invalid_field="pid",
            invalid_detail="pid is empty",
        )
    try:
        normalized_pid = normalize_pid(pid_raw)
    except ValueError as error:
        return _invalid_from_record(
            side=side,
            source_path=source_path,
            source_format=source_format,
            source_record_number=source_record_number,
            original_record=original_record,
            invalid_reason="invalid_pid",
            invalid_field="pid",
            invalid_detail=str(error),
        )

    required_text_values: dict[str, str] = {}
    for field in (
        "process",
        "subsystem",
        "category",
        "event_type",
        "log_type",
        "message",
    ):
        value = original_record.get(field)
        if not isinstance(value, str):
            return _invalid_from_record(
                side=side,
                source_path=source_path,
                source_format=source_format,
                source_record_number=source_record_number,
                original_record=original_record,
                invalid_reason="invalid_required_type",
                invalid_field=field,
                invalid_detail=f"{field} must be a UTF-8 text value",
            )
        required_text_values[field] = value

    component = original_record.get("component")
    if component is not None and not isinstance(component, str):
        component = str(component)
    source_trace_path = original_record.get("source_trace_path")
    if source_trace_path is not None and not isinstance(source_trace_path, str):
        source_trace_path = str(source_trace_path)

    return CanonicalComparisonRecord(
        side=side,
        source_path=source_path,
        source_format=source_format,
        source_record_number=source_record_number,
        original_record=dict(original_record),
        original_timestamp_text=timestamp_raw,
        timestamp_epoch_ns=timestamp_epoch_ns,
        original_pid_value=pid_raw,
        normalized_pid=normalized_pid,
        process=required_text_values["process"],
        subsystem=required_text_values["subsystem"],
        category=required_text_values["category"],
        event_type=required_text_values["event_type"],
        log_type=required_text_values["log_type"],
        message=required_text_values["message"],
        component=component,
        source_trace_path=source_trace_path,
        is_valid=True,
        invalid_reason=None,
        invalid_field=None,
        invalid_detail=None,
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
) -> CanonicalComparisonRecord:
    timestamp_raw = original_record.get("timestamp")
    return CanonicalComparisonRecord(
        side=side,
        source_path=source_path,
        source_format=source_format,
        source_record_number=source_record_number,
        original_record=dict(original_record),
        original_timestamp_text=timestamp_raw if isinstance(timestamp_raw, str) else None,
        timestamp_epoch_ns=None,
        original_pid_value=original_record.get("pid"),
        normalized_pid=None,
        process=original_record.get("process")
        if isinstance(original_record.get("process"), str)
        else None,
        subsystem=original_record.get("subsystem")
        if isinstance(original_record.get("subsystem"), str)
        else None,
        category=original_record.get("category")
        if isinstance(original_record.get("category"), str)
        else None,
        event_type=original_record.get("event_type")
        if isinstance(original_record.get("event_type"), str)
        else None,
        log_type=original_record.get("log_type")
        if isinstance(original_record.get("log_type"), str)
        else None,
        message=original_record.get("message")
        if isinstance(original_record.get("message"), str)
        else None,
        component=original_record.get("component")
        if isinstance(original_record.get("component"), str)
        else None,
        source_trace_path=original_record.get("source_trace_path")
        if isinstance(original_record.get("source_trace_path"), str)
        else None,
        is_valid=False,
        invalid_reason=invalid_reason,
        invalid_field=invalid_field,
        invalid_detail=invalid_detail,
    )


def exact_match_key(record: CanonicalComparisonRecord) -> tuple[Any, ...] | None:
    if not record.is_valid:
        return None
    return (
        record.timestamp_epoch_ns,
        record.normalized_pid,
        record.process,
        record.subsystem,
        record.category,
        record.event_type,
        record.log_type,
        record.message,
    )


def difference_alignment_key(record: CanonicalComparisonRecord) -> tuple[Any, ...] | None:
    if not record.is_valid:
        return None
    return (
        record.timestamp_epoch_ns,
        record.normalized_pid,
        record.process,
    )


def differing_fields(
    left: CanonicalComparisonRecord, right: CanonicalComparisonRecord
) -> tuple[str, ...]:
    values = []
    for field in FIELD_DIFFERENCE_ORDER:
        if getattr(left, field) != getattr(right, field):
            values.append(field)
    return tuple(values)


def compare_record_sets(
    left_records: list[CanonicalComparisonRecord],
    right_records: list[CanonicalComparisonRecord],
) -> ComparisonResult:
    left_sorted = sorted(left_records, key=lambda record: record.source_record_number)
    right_sorted = sorted(right_records, key=lambda record: record.source_record_number)

    left_invalid = tuple(record for record in left_sorted if not record.is_valid)
    right_invalid = tuple(record for record in right_sorted if not record.is_valid)
    left_valid = [record for record in left_sorted if record.is_valid]
    right_valid = [record for record in right_sorted if record.is_valid]

    duplicate_groups_left, duplicate_records_left = _duplicate_statistics(left_valid)
    duplicate_groups_right, duplicate_records_right = _duplicate_statistics(right_valid)

    exact_matches, left_after_exact, right_after_exact = _consume_exact_matches(
        left_valid, right_valid
    )
    differences, left_remaining, right_remaining = _consume_field_differences(
        left_after_exact, right_after_exact
    )

    left_only = tuple(sorted(left_remaining, key=lambda record: record.source_record_number))
    right_only = tuple(
        sorted(right_remaining, key=lambda record: record.source_record_number)
    )

    accounting = ComparisonAccounting(
        left_input_records=len(left_sorted),
        right_input_records=len(right_sorted),
        left_valid_records=len(left_valid),
        right_valid_records=len(right_valid),
        left_invalid_records=len(left_invalid),
        right_invalid_records=len(right_invalid),
        left_exact_match_records=len(exact_matches),
        right_exact_match_records=len(exact_matches),
        left_difference_records=len(differences),
        right_difference_records=len(differences),
        left_only_records=len(left_only),
        right_only_records=len(right_only),
        duplicate_key_groups_left=duplicate_groups_left,
        duplicate_key_groups_right=duplicate_groups_right,
        duplicate_records_left=duplicate_records_left,
        duplicate_records_right=duplicate_records_right,
    )
    invariants = _validate_invariants(accounting)

    return ComparisonResult(
        exact_matches=tuple(sorted(exact_matches, key=_pair_sort_key)),
        field_differences=tuple(sorted(differences, key=_diff_pair_sort_key)),
        left_only=left_only,
        right_only=right_only,
        left_invalid=left_invalid,
        right_invalid=right_invalid,
        accounting=accounting,
        invariants=invariants,
    )


def _duplicate_statistics(records: list[CanonicalComparisonRecord]) -> tuple[int, int]:
    counts: dict[tuple[Any, ...], int] = {}
    for record in records:
        key = exact_match_key(record)
        assert key is not None
        counts[key] = counts.get(key, 0) + 1
    duplicate_key_groups = sum(1 for count in counts.values() if count > 1)
    duplicate_records = sum(count for count in counts.values() if count > 1)
    return duplicate_key_groups, duplicate_records


def _consume_exact_matches(
    left_records: list[CanonicalComparisonRecord],
    right_records: list[CanonicalComparisonRecord],
) -> tuple[
    list[ExactMatchPair], list[CanonicalComparisonRecord], list[CanonicalComparisonRecord]
]:
    left_by_key: dict[tuple[Any, ...], list[CanonicalComparisonRecord]] = {}
    right_by_key: dict[tuple[Any, ...], list[CanonicalComparisonRecord]] = {}

    for record in left_records:
        key = exact_match_key(record)
        assert key is not None
        left_by_key.setdefault(key, []).append(record)
    for record in right_records:
        key = exact_match_key(record)
        assert key is not None
        right_by_key.setdefault(key, []).append(record)

    exact_pairs: list[ExactMatchPair] = []
    left_remaining: list[CanonicalComparisonRecord] = []
    right_remaining: list[CanonicalComparisonRecord] = []

    all_keys = sorted(
        set(left_by_key) | set(right_by_key),
        key=lambda item: repr(item),
    )
    for key in all_keys:
        left_group = sorted(
            left_by_key.get(key, []), key=lambda record: record.source_record_number
        )
        right_group = sorted(
            right_by_key.get(key, []), key=lambda record: record.source_record_number
        )
        pair_count = min(len(left_group), len(right_group))
        for index in range(pair_count):
            exact_pairs.append(
                ExactMatchPair(left=left_group[index], right=right_group[index])
            )
        left_remaining.extend(left_group[pair_count:])
        right_remaining.extend(right_group[pair_count:])

    return exact_pairs, left_remaining, right_remaining


def _consume_field_differences(
    left_records: list[CanonicalComparisonRecord],
    right_records: list[CanonicalComparisonRecord],
) -> tuple[
    list[FieldDifferencePair], list[CanonicalComparisonRecord], list[CanonicalComparisonRecord]
]:
    left_remaining = list(left_records)
    right_remaining = list(right_records)
    difference_pairs: list[FieldDifferencePair] = []

    while True:
        left_candidates: dict[int, list[int]] = {}
        right_candidates: dict[int, list[int]] = {}

        for left_index, left_record in enumerate(left_remaining):
            for right_index, right_record in enumerate(right_remaining):
                if difference_alignment_key(left_record) != difference_alignment_key(
                    right_record
                ):
                    continue
                diffs = differing_fields(left_record, right_record)
                if not diffs:
                    continue
                left_candidates.setdefault(left_index, []).append(right_index)
                right_candidates.setdefault(right_index, []).append(left_index)

        unique_pairs: list[tuple[int, int, tuple[str, ...]]] = []
        for left_index, right_indexes in left_candidates.items():
            if len(right_indexes) != 1:
                continue
            right_index = right_indexes[0]
            reciprocal = right_candidates.get(right_index, [])
            if len(reciprocal) != 1 or reciprocal[0] != left_index:
                continue
            diffs = differing_fields(left_remaining[left_index], right_remaining[right_index])
            unique_pairs.append((left_index, right_index, diffs))

        if not unique_pairs:
            break

        unique_pairs.sort(
            key=lambda pair: (
                left_remaining[pair[0]].source_record_number,
                right_remaining[pair[1]].source_record_number,
            )
        )

        consumed_left: set[int] = set()
        consumed_right: set[int] = set()
        for left_index, right_index, diffs in unique_pairs:
            if left_index in consumed_left or right_index in consumed_right:
                continue
            consumed_left.add(left_index)
            consumed_right.add(right_index)
            difference_pairs.append(
                FieldDifferencePair(
                    left=left_remaining[left_index],
                    right=right_remaining[right_index],
                    differing_fields=diffs,
                )
            )

        left_remaining = [
            record
            for index, record in enumerate(left_remaining)
            if index not in consumed_left
        ]
        right_remaining = [
            record
            for index, record in enumerate(right_remaining)
            if index not in consumed_right
        ]

    return difference_pairs, left_remaining, right_remaining


def _validate_invariants(accounting: ComparisonAccounting) -> ComparisonInvariantResult:
    left_accounting_ok = accounting.left_input_records == (
        accounting.left_exact_match_records
        + accounting.left_difference_records
        + accounting.left_only_records
        + accounting.left_invalid_records
    )
    right_accounting_ok = accounting.right_input_records == (
        accounting.right_exact_match_records
        + accounting.right_difference_records
        + accounting.right_only_records
        + accounting.right_invalid_records
    )
    left_valid_breakdown_ok = accounting.left_valid_records == (
        accounting.left_exact_match_records
        + accounting.left_difference_records
        + accounting.left_only_records
    )
    right_valid_breakdown_ok = accounting.right_valid_records == (
        accounting.right_exact_match_records
        + accounting.right_difference_records
        + accounting.right_only_records
    )
    exact_count_symmetry_ok = (
        accounting.left_exact_match_records == accounting.right_exact_match_records
    )
    difference_count_symmetry_ok = (
        accounting.left_difference_records == accounting.right_difference_records
    )
    return ComparisonInvariantResult(
        left_accounting_ok=left_accounting_ok,
        right_accounting_ok=right_accounting_ok,
        left_valid_breakdown_ok=left_valid_breakdown_ok,
        right_valid_breakdown_ok=right_valid_breakdown_ok,
        exact_count_symmetry_ok=exact_count_symmetry_ok,
        difference_count_symmetry_ok=difference_count_symmetry_ok,
    )


def _pair_sort_key(pair: ExactMatchPair) -> tuple[int, int]:
    return (
        pair.left.source_record_number,
        pair.right.source_record_number,
    )


def _diff_pair_sort_key(pair: FieldDifferencePair) -> tuple[int, int]:
    return (
        pair.left.source_record_number,
        pair.right.source_record_number,
    )
