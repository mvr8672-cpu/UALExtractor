from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIMESTAMP_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d+)?"
    r"(?P<tz>Z|z|[+-]\d{2}:\d{2})?$"
)


def _as_lower(value: str) -> str:
    return value.casefold()


def _text_matches(value: Any, needle: str) -> bool:
    if value is None:
        return False
    return _as_lower(str(value)).find(_as_lower(needle)) >= 0


@dataclass(frozen=True)
class TimeInstant:
    epoch_ns: int
    utc_text: str
    datetime_utc: datetime


class TimeClassification(Enum):
    NOT_APPLIED = "NOT_APPLIED"
    TIME_MATCHED = "TIME_MATCHED"
    TIME_FILTERED_OUT = "TIME_FILTERED_OUT"
    TIME_INVALID = "TIME_INVALID"


def _epoch_seconds_from_utc_datetime(value: datetime) -> int:
    delta = value - _EPOCH_UTC
    return delta.days * 86_400 + delta.seconds


def _format_epoch_ns_utc(epoch_ns: int) -> str:
    seconds, nanos = divmod(epoch_ns, 1_000_000_000)
    whole = _EPOCH_UTC + timedelta(seconds=seconds)
    base = whole.strftime("%Y-%m-%dT%H:%M:%S")
    if nanos == 0:
        return f"{base}Z"
    fraction = f"{nanos:09d}".rstrip("0")
    return f"{base}.{fraction}Z"


def _parse_offset(offset_text: str) -> timedelta:
    if offset_text in ("Z", "z"):
        return timedelta(0)
    sign = 1 if offset_text[0] == "+" else -1
    hours = int(offset_text[1:3])
    minutes = int(offset_text[4:6])
    if hours > 23 or minutes > 59:
        raise ValueError(f"invalid timezone offset: {offset_text!r}")
    return timedelta(minutes=sign * (hours * 60 + minutes))


def _parse_timestamp_to_instant(value: str, *, date_only: bool = False) -> TimeInstant:
    if value is None:
        raise ValueError("timestamp value is required")
    text = value.strip()
    if not text:
        raise ValueError("timestamp value is required")

    if date_only or _DATE_ONLY_RE.match(text):
        parsed = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        epoch_seconds = _epoch_seconds_from_utc_datetime(parsed)
        epoch_ns = epoch_seconds * 1_000_000_000
        return TimeInstant(
            epoch_ns=epoch_ns,
            utc_text=_format_epoch_ns_utc(epoch_ns),
            datetime_utc=parsed,
        )

    match = _TIMESTAMP_RE.match(text)
    if match is None:
        raise ValueError(f"invalid timestamp format: {value!r}")

    tz_text = match.group("tz")
    if tz_text is None:
        raise ValueError(f"timestamp must be timezone-aware: {value!r}")

    year, month, day = (int(part) for part in match.group("date").split("-"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    fraction_text = match.group("fraction")
    fractional_digits = fraction_text[1:] if fraction_text else ""
    if len(fractional_digits) > 9:
        raise ValueError(
            f"timestamp fractional precision exceeds 9 digits: {value!r}"
        )
    fractional_ns = int(fractional_digits.ljust(9, "0")) if fractional_digits else 0

    offset = _parse_offset(tz_text)
    local_dt = datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
        tzinfo=timezone(offset),
    )
    utc_whole_second = local_dt.astimezone(timezone.utc).replace(microsecond=0)
    epoch_seconds = _epoch_seconds_from_utc_datetime(utc_whole_second)
    epoch_ns = epoch_seconds * 1_000_000_000 + fractional_ns
    return TimeInstant(
        epoch_ns=epoch_ns,
        utc_text=_format_epoch_ns_utc(epoch_ns),
        datetime_utc=utc_whole_second + timedelta(microseconds=fractional_ns // 1000),
    )


def _parse_timestamp_to_epoch_ns(value: str, *, date_only: bool = False) -> int:
    return _parse_timestamp_to_instant(value, date_only=date_only).epoch_ns


def _parse_datetime(value: str, *, date_only: bool = False) -> datetime:
    # Retained for backward-compatible tests and non-authoritative datetime views.
    return _parse_timestamp_to_instant(value, date_only=date_only).datetime_utc


@dataclass(frozen=True)
class FilterSpec:
    start: datetime | None = None
    end: datetime | None = None
    start_is_date_only: bool = False
    end_is_date_only: bool = False
    start_raw: str | None = None
    end_raw: str | None = None
    effective_start_ns: int | None = None
    effective_end_ns: int | None = None
    effective_start_utc_text: str | None = None
    effective_end_utc_text: str | None = None
    start_semantics: str | None = None
    end_semantics: str | None = None
    process: tuple[str, ...] = ()
    pid: tuple[int, ...] = ()
    subsystem: tuple[str, ...] = ()
    category: tuple[str, ...] = ()
    event_type: tuple[str, ...] = ()
    log_type: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()
    message: tuple[str, ...] = ()

    @classmethod
    def from_cli(
        cls,
        *,
        start: str | None = None,
        end: str | None = None,
        process: Sequence[str] | None = None,
        pid: Sequence[int] | None = None,
        subsystem: Sequence[str] | None = None,
        category: Sequence[str] | None = None,
        event_type: Sequence[str] | None = None,
        log_type: Sequence[str] | None = None,
        contains: Sequence[str] | None = None,
        message: Sequence[str] | None = None,
    ) -> "FilterSpec":
        start_dt = None
        end_dt = None
        start_ns = None
        end_ns = None
        start_utc_text = None
        end_utc_text = None
        start_semantics = None
        end_semantics = None
        start_is_date_only = False
        end_is_date_only = False

        if start is not None:
            start_is_date_only = bool(_DATE_ONLY_RE.match(start))
            start_instant = _parse_timestamp_to_instant(start, date_only=start_is_date_only)
            start_dt = start_instant.datetime_utc
            start_ns = start_instant.epoch_ns
            start_utc_text = start_instant.utc_text
            start_semantics = "inclusive"

        if end is not None:
            end_is_date_only = bool(_DATE_ONLY_RE.match(end))
            end_instant = _parse_timestamp_to_instant(end, date_only=end_is_date_only)
            end_dt = end_instant.datetime_utc
            if end_is_date_only:
                end_ns = end_instant.epoch_ns + 86_400 * 1_000_000_000
                end_utc_text = _format_epoch_ns_utc(end_ns)
                end_semantics = "exclusive"
            else:
                end_ns = end_instant.epoch_ns
                end_utc_text = end_instant.utc_text
                end_semantics = "inclusive"

        if start_ns is not None and end_ns is not None:
            if end_is_date_only:
                invalid = start_ns >= end_ns
            else:
                invalid = start_ns > end_ns
            if invalid:
                raise ValueError(
                    "The supplied time range is invalid: start is later than end."
                )

        return cls(
            start=start_dt,
            end=end_dt,
            start_is_date_only=start_is_date_only,
            end_is_date_only=end_is_date_only,
            start_raw=start,
            end_raw=end,
            effective_start_ns=start_ns,
            effective_end_ns=end_ns,
            effective_start_utc_text=start_utc_text,
            effective_end_utc_text=end_utc_text,
            start_semantics=start_semantics,
            end_semantics=end_semantics,
            process=tuple(_as_lower(value) for value in (process or ())),
            pid=tuple(int(value) for value in (pid or ())),
            subsystem=tuple(_as_lower(value) for value in (subsystem or ())),
            category=tuple(_as_lower(value) for value in (category or ())),
            event_type=tuple(_as_lower(value) for value in (event_type or ())),
            log_type=tuple(_as_lower(value) for value in (log_type or ())),
            contains=tuple(_as_lower(value) for value in (contains or ())),
            message=tuple(value.casefold() for value in (message or ())),
        )

    @property
    def time_filter_active(self) -> bool:
        return self.effective_start_ns is not None or self.effective_end_ns is not None

    def classify_record_time(self, record: Mapping[str, Any]) -> TimeClassification:
        if not self.time_filter_active:
            return TimeClassification.NOT_APPLIED

        timestamp_value = record.get("timestamp")
        if timestamp_value is None:
            return TimeClassification.TIME_INVALID

        try:
            record_ns = _parse_timestamp_to_epoch_ns(str(timestamp_value))
        except ValueError:
            return TimeClassification.TIME_INVALID

        if self.effective_start_ns is not None and record_ns < self.effective_start_ns:
            return TimeClassification.TIME_FILTERED_OUT

        if self.effective_end_ns is not None:
            if self.end_is_date_only:
                if record_ns >= self.effective_end_ns:
                    return TimeClassification.TIME_FILTERED_OUT
            elif record_ns > self.effective_end_ns:
                return TimeClassification.TIME_FILTERED_OUT

        return TimeClassification.TIME_MATCHED

    def matches_generic(self, record: Mapping[str, Any]) -> bool:
        if self.process and not any(
            _text_matches(record.get("process"), value) for value in self.process
        ):
            return False

        if self.pid:
            record_pid = record.get("pid")
            if record_pid is None:
                return False
            try:
                pid_value = int(record_pid)
            except (TypeError, ValueError):
                return False
            if pid_value not in self.pid:
                return False

        if self.subsystem and not any(
            _text_matches(record.get("subsystem"), value) for value in self.subsystem
        ):
            return False

        if self.category and not any(
            _text_matches(record.get("category"), value) for value in self.category
        ):
            return False

        if self.event_type and not any(
            _as_lower(str(record.get("event_type", ""))) == value
            for value in self.event_type
        ):
            return False

        if self.log_type and not any(
            _as_lower(str(record.get("log_type", ""))) == value
            for value in self.log_type
        ):
            return False

        if self.message:
            message_value = record.get("message")
            if message_value is None or not any(
                _text_matches(message_value, value) for value in self.message
            ):
                return False

        if self.contains:
            haystacks = (
                record.get("message"),
                record.get("process"),
                record.get("subsystem"),
                record.get("category"),
            )
            if not any(
                any(_text_matches(haystack, value) for haystack in haystacks)
                for value in self.contains
            ):
                return False

        return True

    def matches(self, record: Mapping[str, Any]) -> bool:
        time_class = self.classify_record_time(record)
        if time_class in (
            TimeClassification.TIME_FILTERED_OUT,
            TimeClassification.TIME_INVALID,
        ):
            return False
        return self.matches_generic(record)


def format_filter_summary(spec: FilterSpec | None) -> str:
    """
    Format a FilterSpec as a canonical human-readable filter summary.

    Used by:
    - dry-run output
    - normal decode stderr before first trace
    - forensic validation report

    If no filters are active, returns "(none)".
    """
    if spec is None:
        return "(none)"

    parts: list[str] = []

    if spec.effective_start_utc_text is not None:
        parts.append(
            "start: "
            f"raw={spec.start_raw!r}, "
            f"effective={spec.effective_start_utc_text} "
            "(inclusive, timezone=UTC)"
        )

    if spec.effective_end_utc_text is not None:
        end_semantics = "exclusive" if spec.end_is_date_only else "inclusive"
        parts.append(
            "end: "
            f"raw={spec.end_raw!r}, "
            f"effective={spec.effective_end_utc_text} "
            f"({end_semantics}, timezone=UTC)"
        )

    if spec.message:
        parts.append(f"message: {list(spec.message)}")

    if spec.contains:
        parts.append(f"contains: {list(spec.contains)}")

    if spec.process:
        parts.append(f"process: {list(spec.process)}")

    if spec.pid:
        parts.append(f"pid: {list(spec.pid)}")

    if spec.subsystem:
        parts.append(f"subsystem: {list(spec.subsystem)}")

    if spec.category:
        parts.append(f"category: {list(spec.category)}")

    if spec.event_type:
        parts.append(f"event_type: {list(spec.event_type)}")

    if spec.log_type:
        parts.append(f"log_type: {list(spec.log_type)}")

    if not parts:
        return "(none)"

    return "\n".join(parts)
