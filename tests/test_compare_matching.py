from __future__ import annotations

from pathlib import Path
from typing import Literal

from ualextractor.compare import canonicalize_record, compare_record_sets


def _record(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "timestamp": "2026-05-04T12:00:00.123456701Z",
        "process": "bluetoothd",
        "pid": 123,
        "subsystem": "com.apple.bluetooth",
        "category": "control",
        "event_type": "log",
        "log_type": "default",
        "message": "Device connected",
    }
    value.update(overrides)
    return value


def _canonical(side: Literal["left", "right"], row: int, **overrides: object):
    return canonicalize_record(
        side=side,
        source_path=Path(f"/tmp/{side}.synthetic"),
        source_format="csv",
        source_record_number=row,
        original_record=_record(**overrides),
    )


def test_one_exact_match() -> None:
    result = compare_record_sets(
        [_canonical("left", 1)],
        [_canonical("right", 1)],
    )
    assert len(result.exact_matches) == 1
    assert len(result.field_differences) == 0
    assert len(result.left_only) == 0
    assert len(result.right_only) == 0


def test_provenance_difference_still_exact_match() -> None:
    result = compare_record_sets(
        [_canonical("left", 3, component="Persist", source_trace_path="/a.tracev3")],
        [_canonical("right", 7, component="Special", source_trace_path="/b.tracev3")],
    )
    assert len(result.exact_matches) == 1
    assert result.exact_matches[0].left.source_record_number == 3
    assert result.exact_matches[0].right.source_record_number == 7


def test_exact_mismatch_on_message_process_and_pid() -> None:
    result = compare_record_sets(
        [
            _canonical("left", 1, message="A"),
            _canonical("left", 2, process="procA"),
            _canonical("left", 3, pid=111),
        ],
        [
            _canonical("right", 1, message="B"),  # FIELD_DIFFERENCE candidate
            _canonical("right", 2, process="procB"),
            _canonical("right", 3, pid=222),
        ],
    )
    assert len(result.exact_matches) == 0
    assert len(result.field_differences) == 1
    assert len(result.left_only) == 2
    assert len(result.right_only) == 2


def test_duplicate_multiset_pairing_and_counterpart_row_numbers() -> None:
    result = compare_record_sets(
        [
            _canonical("left", 10),
            _canonical("left", 20),
            _canonical("left", 30),
        ],
        [
            _canonical("right", 11),
            _canonical("right", 21),
        ],
    )
    assert len(result.exact_matches) == 2
    assert [pair.left.source_record_number for pair in result.exact_matches] == [10, 20]
    assert [pair.right.source_record_number for pair in result.exact_matches] == [11, 21]
    assert [record.source_record_number for record in result.left_only] == [30]


def test_duplicate_statistics_definition_counts_all_records_in_duplicate_groups() -> None:
    left = [
        _canonical("left", 1, message="A"),
        _canonical("left", 2, message="A"),
        _canonical("left", 3, message="A"),
        _canonical("left", 4, message="B"),
        _canonical("left", 5, message="B"),
        _canonical("left", 6, message="C"),
    ]
    right = [_canonical("right", 1, message="Z")]
    result = compare_record_sets(left, right)
    assert result.accounting.duplicate_key_groups_left == 2
    assert result.accounting.duplicate_records_left == 5


def test_field_difference_single_and_multiple_fields_and_order() -> None:
    result = compare_record_sets(
        [
            _canonical("left", 1, process="proc-1", category="cat-left"),
            _canonical("left", 2, process="proc-2", category="cat-left", message="msg-left"),
        ],
        [
            _canonical("right", 1, process="proc-1", category="cat-right"),
            _canonical("right", 2, process="proc-2", category="cat-right", message="msg-right"),
        ],
    )
    assert len(result.field_differences) == 2
    assert result.field_differences[0].differing_fields == ("category",)
    assert result.field_differences[1].differing_fields == ("category", "message")


def test_ambiguous_two_left_two_right_cluster_remains_side_only() -> None:
    result = compare_record_sets(
        [
            _canonical("left", 1, message="L1"),
            _canonical("left", 2, message="L2"),
        ],
        [
            _canonical("right", 1, message="R1"),
            _canonical("right", 2, message="R2"),
        ],
    )
    assert len(result.field_differences) == 0
    assert [record.source_record_number for record in result.left_only] == [1, 2]
    assert [record.source_record_number for record in result.right_only] == [1, 2]


def test_ambiguous_one_left_to_two_right_and_two_left_to_one_right_remain_side_only() -> None:
    left = [
        _canonical("left", 1, process="proc-1", message="L"),
        _canonical("left", 2, process="proc-2", message="L2"),
        _canonical("left", 3, process="proc-2", message="L3"),
    ]
    right = [
        _canonical("right", 1, process="proc-1", message="R1"),
        _canonical("right", 2, process="proc-1", message="R2"),
        _canonical("right", 3, process="proc-2", message="R"),
    ]
    result = compare_record_sets(left, right)
    assert len(result.field_differences) == 0
    assert len(result.left_only) == 3
    assert len(result.right_only) == 3


def test_exact_matching_precedes_field_difference_matching() -> None:
    result = compare_record_sets(
        [
            _canonical("left", 1, message="exact"),
            _canonical("left", 2, message="diff-left"),
        ],
        [
            _canonical("right", 1, message="exact"),
            _canonical("right", 2, message="diff-right"),
        ],
    )
    assert len(result.exact_matches) == 1
    assert result.exact_matches[0].left.source_record_number == 1
    assert len(result.field_differences) == 1
    assert result.field_differences[0].left.source_record_number == 2


def test_invalid_records_are_excluded_from_matching_and_tracked_by_side() -> None:
    left_valid = _canonical("left", 1, message="X")
    left_invalid = canonicalize_record(
        side="left",
        source_path=Path("/tmp/left"),
        source_format="csv",
        source_record_number=2,
        original_record=None,
        invalid_reason="invalid_json",
        invalid_detail="boom",
    )
    right_valid = _canonical("right", 1, message="X")
    right_invalid = canonicalize_record(
        side="right",
        source_path=Path("/tmp/right"),
        source_format="csv",
        source_record_number=3,
        original_record=None,
        invalid_reason="invalid_structure",
        invalid_detail="bad row",
    )
    result = compare_record_sets(
        [left_valid, left_invalid],
        [right_valid, right_invalid],
    )
    assert len(result.exact_matches) == 1
    assert [record.source_record_number for record in result.left_invalid] == [2]
    assert [record.source_record_number for record in result.right_invalid] == [3]


def test_all_matches_zero_matches_and_empty_inputs() -> None:
    all_match = compare_record_sets(
        [_canonical("left", 1), _canonical("left", 2, message="B")],
        [_canonical("right", 1), _canonical("right", 2, message="B")],
    )
    assert len(all_match.exact_matches) == 2

    zero_match = compare_record_sets(
        [_canonical("left", 1, process="left-proc", message="only-left")],
        [_canonical("right", 1, process="right-proc", message="only-right")],
    )
    assert len(zero_match.exact_matches) == 0
    assert len(zero_match.left_only) == 1
    assert len(zero_match.right_only) == 1

    empty = compare_record_sets([], [])
    assert len(empty.exact_matches) == 0
    assert len(empty.left_only) == 0
    assert len(empty.right_only) == 0


def test_accounting_and_invariants_are_reported() -> None:
    left = [
        _canonical("left", 1, message="exact"),
        _canonical("left", 2, process="shared-proc", message="diff-left"),
        _canonical("left", 3, process="left-only-proc", message="left-only"),
        canonicalize_record(
            side="left",
            source_path=Path("/tmp/left"),
            source_format="csv",
            source_record_number=4,
            original_record=None,
            invalid_reason="invalid_json",
            invalid_detail="x",
        ),
    ]
    right = [
        _canonical("right", 1, message="exact"),
        _canonical("right", 2, process="shared-proc", message="diff-right"),
        _canonical("right", 3, process="right-only-proc", message="right-only"),
        canonicalize_record(
            side="right",
            source_path=Path("/tmp/right"),
            source_format="csv",
            source_record_number=4,
            original_record=None,
            invalid_reason="invalid_structure",
            invalid_detail="y",
        ),
    ]
    result = compare_record_sets(left, right)
    accounting = result.accounting
    assert accounting.left_input_records == 4
    assert accounting.right_input_records == 4
    assert accounting.left_exact_match_records == 1
    assert accounting.right_exact_match_records == 1
    assert accounting.left_difference_records == 1
    assert accounting.right_difference_records == 1
    assert accounting.left_only_records == 1
    assert accounting.right_only_records == 1
    assert accounting.left_invalid_records == 1
    assert accounting.right_invalid_records == 1
    assert result.invariants.all_ok is True
    assert result.invariants.left_accounting_ok is True
    assert result.invariants.right_accounting_ok is True
    assert result.invariants.left_valid_breakdown_ok is True
    assert result.invariants.right_valid_breakdown_ok is True
    assert result.invariants.exact_count_symmetry_ok is True
    assert result.invariants.difference_count_symmetry_ok is True


def test_result_ordering_is_deterministic() -> None:
    left = [
        _canonical("left", 30, message="E"),
        _canonical("left", 10, message="E"),
        _canonical("left", 20, process="proc", message="D-left"),
    ]
    right = [
        _canonical("right", 31, message="E"),
        _canonical("right", 11, message="E"),
        _canonical("right", 21, process="proc", message="D-right"),
    ]
    result = compare_record_sets(left, right)
    assert [pair.left.source_record_number for pair in result.exact_matches] == [10, 30]
    assert [pair.right.source_record_number for pair in result.exact_matches] == [11, 31]
    assert [pair.left.source_record_number for pair in result.field_differences] == [20]
