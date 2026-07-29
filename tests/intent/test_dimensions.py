# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for DecisionDimensions — the raw, redacted inputs a decision judges.

The dimensions are what makes core rail-agnostic: policy reasons over a band of
value, a window, a counterparty and a rail *class*, never a vendor field. Two
security shapes are asserted here directly — value is a band, and a raw
identifier cannot be represented (threat A5).
"""

import pytest
from pydantic import ValidationError

from tests.intent.conftest import make_dimensions


def test_value_is_a_band_not_a_scalar():
    """A market order has no settled amount at decision time — only a range."""
    d = make_dimensions(value_lower_minor=100, value_upper_minor=500)
    assert (d.value_lower_minor, d.value_upper_minor) == (100, 500)


def test_a_settled_amount_is_the_degenerate_band():
    d = make_dimensions(value_lower_minor=250, value_upper_minor=250)
    assert d.value_lower_minor == d.value_upper_minor


def test_upper_below_lower_is_rejected():
    with pytest.raises(ValidationError):
        make_dimensions(value_lower_minor=500, value_upper_minor=100)


def test_negative_value_is_rejected():
    with pytest.raises(ValidationError):
        make_dimensions(value_lower_minor=-1, value_upper_minor=-1)


def test_floating_point_money_is_rejected():
    """Money is integer minor units; a float amount is a reconciliation defect."""
    with pytest.raises(ValidationError):
        make_dimensions(value_lower_minor=1.5, value_upper_minor=2.5)


def test_window_must_be_strictly_ordered():
    d = make_dimensions()
    with pytest.raises(ValidationError):
        make_dimensions(not_before=d.not_after, not_after=d.not_after)


def test_missing_timezone_is_rejected():
    """A naive timestamp is ambiguous; the window must be absolute."""
    from datetime import datetime

    with pytest.raises(ValidationError):
        make_dimensions(not_before=datetime(2026, 7, 23, 12, 0))  # noqa: DTZ001


def test_raw_account_identifier_is_unrepresentable():
    """A PAN-shaped string is not a fingerprint, so it cannot enter (A5)."""
    with pytest.raises(ValidationError):
        make_dimensions(counterparty_ref="4111111111111111")


def test_malformed_fingerprint_error_is_safe_for_decision_dimensions():
    raw = "acct_1234567890"

    with pytest.raises(ValidationError) as exc_info:
        make_dimensions(counterparty_ref=raw)

    message = str(exc_info.value)

    assert "fp: followed by 64 hexadecimal characters" in message
    assert "fingerprint of the identifier" in message
    assert raw not in message
    assert raw not in repr(exc_info.value.errors())


def test_dimensions_are_frozen():
    d = make_dimensions()
    with pytest.raises(ValidationError):
        d.value_lower_minor = 9


def test_unknown_field_is_rejected():
    """extra='forbid' — nothing rides along as a free-form channel."""
    with pytest.raises(ValidationError):
        make_dimensions(memo="pay the invoice")
