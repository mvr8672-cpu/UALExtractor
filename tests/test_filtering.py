"""Sprint 9 tests for FilterSpec extensions and format_filter_summary().

All tests are written test-first. Production support does not yet exist for:
- FilterSpec.message field
- FilterSpec.start_raw / end_raw fields
- format_filter_summary() function

Tests for existing Sprint 8 FilterSpec behaviour are in test_decoder.py and
are not duplicated here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ualextractor.filtering import FilterSpec, format_filter_summary


# ============================================================================
# 1. --message filter — FilterSpec.matches() unit tests
# ============================================================================


def test_message_filter_matches_message_field() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({"message": "bluetooth session started"}) is True


def test_message_filter_no_match_wrong_content() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({"message": "wifi session started"}) is False


def test_message_filter_case_insensitive() -> None:
    fs = FilterSpec.from_cli(message=["BLUETOOTH"])
    assert fs.matches({"message": "Bluetooth session started"}) is True
    assert fs.matches({"message": "BLUETOOTH"}) is True
    assert fs.matches({"message": "bluetooth"}) is True


def test_message_filter_missing_message_key_excluded() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    # record has no message key at all
    assert fs.matches({"process": "bluetoothd", "subsystem": "com.apple.bt"}) is False


def test_message_filter_none_message_value_excluded() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({"message": None}) is False


def test_message_filter_empty_string_message_excluded() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({"message": ""}) is False


def test_message_filter_repeated_values_or_semantics() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth", "wifi"])
    # matches if EITHER term appears in message
    assert fs.matches({"message": "bluetooth session"}) is True
    assert fs.matches({"message": "wifi connected"}) is True
    assert fs.matches({"message": "other message"}) is False


def test_message_filter_combined_with_process_and_semantics() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"], process=["bluetoothd"])
    # both must match
    assert fs.matches({"message": "bluetooth ok", "process": "bluetoothd"}) is True
    # message matches but process does not
    assert fs.matches({"message": "bluetooth ok", "process": "SpringBoard"}) is False
    # process matches but message does not
    assert fs.matches({"message": "other", "process": "bluetoothd"}) is False


def test_message_filter_combined_with_contains_and_semantics() -> None:
    fs = FilterSpec.from_cli(message=["session"], contains=["bluetooth"])
    # --contains searches message/process/subsystem/category
    # --message searches message only
    # Both must pass (AND)
    assert fs.matches({
        "message": "bluetooth session started",
        "process": "bluetoothd",
        "subsystem": "com.apple.bt",
        "category": "conn",
    }) is True
    # contains match via process, but message does not contain "session"
    assert fs.matches({
        "message": "other message",
        "process": "bluetooth-daemon",
    }) is False


def test_message_filter_does_not_match_process_field() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    # process contains "bluetooth" but message does not
    assert fs.matches({"message": "other message", "process": "bluetoothd"}) is False


def test_message_filter_does_not_match_subsystem_field() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({
        "message": "other",
        "subsystem": "com.apple.bluetooth",
    }) is False


def test_message_filter_does_not_match_category_field() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    assert fs.matches({
        "message": "other",
        "category": "Bluetooth",
    }) is False


def test_contains_semantics_unchanged_when_message_filter_also_present() -> None:
    # --contains still searches message + process + subsystem + category
    fs = FilterSpec.from_cli(contains=["bluetooth"])
    # match via subsystem (not message)
    assert fs.matches({
        "message": "unrelated",
        "process": "springboard",
        "subsystem": "com.apple.bluetooth",
        "category": "conn",
    }) is True
    # match via process
    assert fs.matches({
        "message": "unrelated",
        "process": "bluetoothd",
    }) is True


def test_message_filter_stored_casefolded() -> None:
    fs = FilterSpec.from_cli(message=["BlueTOOTH", "WiFI"])
    assert fs.message == ("bluetooth", "wifi")


# ============================================================================
# 2. start_raw / end_raw preservation
# ============================================================================


def test_filter_spec_preserves_start_raw_date_only() -> None:
    fs = FilterSpec.from_cli(start="2026-05-02")
    assert fs.start_raw == "2026-05-02"
    assert fs.start_is_date_only is True


def test_filter_spec_preserves_start_raw_timestamp() -> None:
    fs = FilterSpec.from_cli(start="2026-05-02T10:00:00Z")
    assert fs.start_raw == "2026-05-02T10:00:00Z"
    assert fs.start_is_date_only is False


def test_filter_spec_preserves_end_raw_date_only() -> None:
    fs = FilterSpec.from_cli(end="2026-05-02")
    assert fs.end_raw == "2026-05-02"
    assert fs.end_is_date_only is True


def test_filter_spec_preserves_end_raw_timestamp() -> None:
    fs = FilterSpec.from_cli(end="2026-05-02T14:30:00+02:00")
    assert fs.end_raw == "2026-05-02T14:30:00+02:00"
    assert fs.end_is_date_only is False


def test_filter_spec_raw_none_when_not_supplied() -> None:
    fs = FilterSpec.from_cli(process=["springboard"])
    assert fs.start_raw is None
    assert fs.end_raw is None


# ============================================================================
# 3. Time normalization — effective boundaries
# ============================================================================


def test_time_normalization_date_only_start_effective_midnight_utc() -> None:
    fs = FilterSpec.from_cli(start="2026-05-02")
    assert fs.start == datetime(2026, 5, 2, 0, 0, 0, tzinfo=timezone.utc)
    assert fs.start_is_date_only is True


def test_time_normalization_date_only_end_stored_at_midnight() -> None:
    # The exclusive next-day logic lives in _matches_time(), not in the stored value.
    # The stored end is the date midnight; +1 day expansion is applied at match time.
    fs = FilterSpec.from_cli(end="2026-05-02")
    assert fs.end == datetime(2026, 5, 2, 0, 0, 0, tzinfo=timezone.utc)
    assert fs.end_is_date_only is True


def test_time_normalization_timestamp_end_stored_as_supplied() -> None:
    fs = FilterSpec.from_cli(end="2026-05-02T14:30:00+02:00")
    # stored in UTC
    assert fs.end == datetime(2026, 5, 2, 12, 30, 0, tzinfo=timezone.utc)
    assert fs.end_is_date_only is False


def test_time_normalization_timezone_aware_required_for_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FilterSpec.from_cli(start="2026-05-02T10:00:00")

    with pytest.raises(ValueError, match="timezone-aware"):
        FilterSpec.from_cli(end="2026-05-02T10:00:00")


def test_time_normalization_invalid_range_still_rejected() -> None:
    with pytest.raises(ValueError, match="invalid"):
        FilterSpec.from_cli(start="2026-05-03", end="2026-05-02")


def test_time_normalization_existing_date_only_end_semantics_unchanged() -> None:
    """Filtering must still exclude records on the next day for date-only end."""
    fs = FilterSpec.from_cli(end="2026-05-02")
    # record at midnight of end date → included (< 2026-05-03T00:00:00Z)
    assert fs.matches({"timestamp": "2026-05-02T00:00:00Z"}) is True
    # record at end of end date → included (< 2026-05-03T00:00:00Z)
    assert fs.matches({"timestamp": "2026-05-02T23:59:59Z"}) is True
    # record at next day → excluded (>= 2026-05-03T00:00:00Z)
    assert fs.matches({"timestamp": "2026-05-03T00:00:00Z"}) is False


def test_time_normalization_existing_timestamp_end_semantics_unchanged() -> None:
    """Timestamp end is inclusive — existing Sprint 8 behaviour."""
    fs = FilterSpec.from_cli(end="2026-05-02T06:00:00Z")
    assert fs.matches({"timestamp": "2026-05-02T06:00:00Z"}) is True
    assert fs.matches({"timestamp": "2026-05-02T06:00:01Z"}) is False


# ============================================================================
# 4. format_filter_summary() — canonical output
# ============================================================================


def test_filter_summary_none_spec_returns_none_string() -> None:
    assert format_filter_summary(None) == "(none)"


def test_filter_summary_empty_spec_returns_none_string() -> None:
    fs = FilterSpec()
    assert format_filter_summary(fs) == "(none)"


def test_filter_summary_contains_only() -> None:
    fs = FilterSpec.from_cli(contains=["bluetooth"])
    summary = format_filter_summary(fs)
    assert "contains:" in summary
    assert "bluetooth" in summary


def test_filter_summary_message_only() -> None:
    fs = FilterSpec.from_cli(message=["bluetooth"])
    summary = format_filter_summary(fs)
    assert "message:" in summary
    assert "bluetooth" in summary


def test_filter_summary_message_and_contains_distinct() -> None:
    fs = FilterSpec.from_cli(message=["session"], contains=["bluetooth"])
    summary = format_filter_summary(fs)
    assert "message:" in summary
    assert "contains:" in summary
    # Both labels must appear — they are different filter types
    assert summary.index("message:") != summary.index("contains:")


def test_filter_summary_process_pid_subsystem_category() -> None:
    fs = FilterSpec.from_cli(
        process=["springboard", "bluetoothd"],
        pid=[123, 456],
        subsystem=["com.apple.bt"],
        category=["airplay"],
    )
    summary = format_filter_summary(fs)
    assert "process:" in summary
    assert "springboard" in summary
    assert "bluetoothd" in summary
    assert "pid:" in summary
    assert "123" in summary
    assert "456" in summary
    assert "subsystem:" in summary
    assert "com.apple.bt" in summary
    assert "category:" in summary
    assert "airplay" in summary


def test_filter_summary_event_type_log_type() -> None:
    fs = FilterSpec.from_cli(event_type=["Log"], log_type=["Info"])
    summary = format_filter_summary(fs)
    assert "event_type:" in summary
    assert "log" in summary.lower()
    assert "log_type:" in summary
    assert "info" in summary.lower()


def test_filter_summary_time_start_date_only() -> None:
    fs = FilterSpec.from_cli(start="2026-05-02")
    summary = format_filter_summary(fs)
    # raw value present
    assert "2026-05-02" in summary
    # effective midnight UTC present
    assert "2026-05-02T00:00:00" in summary
    # semantics label
    assert "inclusive" in summary.lower()


def test_filter_summary_time_end_date_only_shows_exclusive_next_day() -> None:
    fs = FilterSpec.from_cli(end="2026-05-02")
    summary = format_filter_summary(fs)
    assert "2026-05-02" in summary
    # effective upper bound is next day
    assert "2026-05-03T00:00:00" in summary
    assert "exclusive" in summary.lower()


def test_filter_summary_time_start_explicit_timestamp() -> None:
    fs = FilterSpec.from_cli(start="2026-05-02T10:30:00Z")
    summary = format_filter_summary(fs)
    assert "2026-05-02T10:30:00Z" in summary or "2026-05-02T10:30:00" in summary
    assert "inclusive" in summary.lower()


def test_filter_summary_time_end_explicit_timestamp_shows_inclusive() -> None:
    fs = FilterSpec.from_cli(end="2026-05-02T23:59:59Z")
    summary = format_filter_summary(fs)
    assert "2026-05-02T23:59:59" in summary
    assert "inclusive" in summary.lower()


def test_filter_summary_deterministic_field_order() -> None:
    """Time bounds must appear before text filters; message before contains."""
    fs = FilterSpec.from_cli(
        start="2026-05-01",
        end="2026-05-02",
        message=["session"],
        contains=["bluetooth"],
        process=["springboard"],
    )
    summary = format_filter_summary(fs)
    # Time must precede text filters
    start_pos = summary.find("start:")
    message_pos = summary.find("message:")
    contains_pos = summary.find("contains:")
    process_pos = summary.find("process:")
    assert start_pos < message_pos
    assert message_pos < contains_pos
    assert contains_pos < process_pos


def test_filter_summary_repeated_values_all_visible() -> None:
    fs = FilterSpec.from_cli(contains=["bluetooth", "wifi", "airplay"])
    summary = format_filter_summary(fs)
    assert "bluetooth" in summary
    assert "wifi" in summary
    assert "airplay" in summary


def test_filter_summary_no_empty_lines_for_unused_fields() -> None:
    # Only message is active; pid/subsystem/category/event_type/log_type not present
    fs = FilterSpec.from_cli(message=["bluetooth"])
    summary = format_filter_summary(fs)
    assert "pid:" not in summary
    assert "subsystem:" not in summary
    assert "category:" not in summary
    assert "event_type:" not in summary
    assert "log_type:" not in summary
    assert "contains:" not in summary
    assert "process:" not in summary


def test_filter_summary_raw_start_preserved_verbatim() -> None:
    raw = "2026-05-02T14:30:00+02:00"
    fs = FilterSpec.from_cli(start=raw)
    summary = format_filter_summary(fs)
    assert raw in summary


def test_filter_summary_raw_end_preserved_verbatim() -> None:
    raw = "2026-05-02"
    fs = FilterSpec.from_cli(end=raw)
    summary = format_filter_summary(fs)
    assert raw in summary
