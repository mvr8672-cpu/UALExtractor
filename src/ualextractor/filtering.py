from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence


def _as_lower(value: str) -> str:
    return value.casefold()


def _text_matches(value: Any, needle: str) -> bool:
    if value is None:
        return False
    return _as_lower(str(value)).find(_as_lower(needle)) >= 0


def _parse_datetime(value: str, *, date_only: bool = False) -> datetime:
    if value is None:
        raise ValueError("timestamp value is required")
    text = value.strip()
    if not text:
        raise ValueError("timestamp value is required")

    if date_only:
        parsed = datetime.strptime(text, "%Y-%m-%d")
        return parsed.replace(tzinfo=timezone.utc)

    if "T" not in text and " " not in text:
        parsed = datetime.strptime(text, "%Y-%m-%d")
        return parsed.replace(tzinfo=timezone.utc)

    iso_text = text.replace("Z", "+00:00").replace("z", "+00:00")
    parsed = datetime.fromisoformat(iso_text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must be timezone-aware: {value!r}")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class FilterSpec:
    start: datetime | None = None
    end: datetime | None = None
    start_is_date_only: bool = False
    end_is_date_only: bool = False
    process: tuple[str, ...] = ()
    pid: tuple[int, ...] = ()
    subsystem: tuple[str, ...] = ()
    category: tuple[str, ...] = ()
    event_type: tuple[str, ...] = ()
    log_type: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()

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
    ) -> "FilterSpec":
        start_dt = None
        end_dt = None
        start_is_date_only = False
        end_is_date_only = False

        if start is not None:
            if start.endswith("-00:00"):
                start_is_date_only = False
            elif len(start) == 10 and start.count("-") == 2 and "T" not in start:
                start_is_date_only = True
            start_dt = _parse_datetime(start, date_only=start_is_date_only)

        if end is not None:
            if len(end) == 10 and end.count("-") == 2 and "T" not in end:
                end_is_date_only = True
            end_dt = _parse_datetime(end, date_only=end_is_date_only)

        if start_dt is not None and end_dt is not None:
            upper_bound = end_dt + timedelta(days=1) if end_is_date_only else end_dt
            if start_dt >= upper_bound:
                raise ValueError(
                    "The supplied time range is invalid: start is later than end."
                )

        return cls(
            start=start_dt,
            end=end_dt,
            start_is_date_only=start_is_date_only,
            end_is_date_only=end_is_date_only,
            process=tuple(_as_lower(value) for value in (process or ())),
            pid=tuple(int(value) for value in (pid or ())),
            subsystem=tuple(_as_lower(value) for value in (subsystem or ())),
            category=tuple(_as_lower(value) for value in (category or ())),
            event_type=tuple(_as_lower(value) for value in (event_type or ())),
            log_type=tuple(_as_lower(value) for value in (log_type or ())),
            contains=tuple(_as_lower(value) for value in (contains or ())),
        )

    def matches(self, record: Mapping[str, Any]) -> bool:
        if not self._matches_time(record):
            return False

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

    def _matches_time(self, record: Mapping[str, Any]) -> bool:
        timestamp_value = record.get("timestamp")
        if self.start is None and self.end is None:
            return True

        if timestamp_value is None:
            return False

        try:
            record_timestamp = _parse_datetime(str(timestamp_value))
        except ValueError:
            return False

        if self.start is not None and record_timestamp < self.start:
            return False

        if self.end is not None:
            if self.end_is_date_only:
                upper_bound = self.end + timedelta(days=1)
                if record_timestamp >= upper_bound:
                    return False
            elif record_timestamp > self.end:
                return False

        return True
