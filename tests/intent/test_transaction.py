# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for TransactionIntent — the immutable unit a decision binds to.

The intent carries the decision dimensions, the closed rail payload, and the
adapter-derived idempotency key. It is deeply immutable: the value a decision
was made on must be the value that is executed (B1), which is only guaranteed
if nothing can rewrite the object in between.
"""

import pytest
from pydantic import ValidationError

from tests.intent.conftest import make_intent, make_payment


def test_intent_carries_dimensions_payload_and_key():
    i = make_intent()
    assert i.dimensions.quote_currency.value == "USD"
    assert i.payload.payload_kind == "payment"
    assert i.idempotency_key == "idem-0000000000000000"


def test_intent_is_frozen():
    i = make_intent()
    with pytest.raises(ValidationError):
        i.idempotency_key = "other"


def test_nested_dimensions_cannot_be_mutated():
    """Deep immutability — a frozen intent whose parts mutate is not immutable."""
    i = make_intent()
    with pytest.raises(ValidationError):
        i.dimensions.value_lower_minor = 0


def test_empty_idempotency_key_is_rejected():
    """A blank key is not a key; a replay guard must actually bind something (B2)."""
    with pytest.raises(ValidationError):
        make_intent(idempotency_key="")


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        make_intent(note="pay it")


def test_payload_must_be_a_known_variant():
    """The payload is the closed union; a foreign object is not accepted."""
    with pytest.raises(ValidationError):
        make_intent(payload={"payload_kind": "wire", "amount": 100})


def test_a_valid_payload_dict_is_still_accepted():
    """Sanity: the closed shape validates from data, it just cannot be open."""
    i = make_intent(payload=make_payment(cross_border=True))
    assert i.payload.cross_border is True
