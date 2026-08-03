# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the closed rail-payload union.

A payment and a trade share decision *dimensions* but not fields. The payload
is therefore a closed, tagged union — never an open mapping — so a new rail is
a new variant and nothing in the decision layer changes to accept it (INV-8).
Today the union has one member; the closure is what this slice establishes.
"""

import pytest
from pydantic import ValidationError

from secondsign.intent import RAIL_PAYLOAD_TYPES, PaymentPayload, TradePayload
from tests.intent.conftest import make_payment


def test_payment_payload_carries_its_own_fields():
    p = make_payment(new_beneficiary=True, cross_border=True)
    assert p.new_beneficiary is True
    assert p.cross_border is True
    assert p.payload_kind == "payment"


def test_payload_is_frozen():
    p = make_payment()
    with pytest.raises(ValidationError):
        p.cross_border = True


def test_no_free_form_field_rides_along():
    """extra='forbid' — an account number cannot be smuggled as a stray key."""
    with pytest.raises(ValidationError):
        make_payment(account_number="4111111111111111")


def test_the_union_is_closed_and_each_member_is_a_closed_model():
    discriminators = set()
    for payload_type in RAIL_PAYLOAD_TYPES:
        assert payload_type.model_config.get("frozen") is True
        assert payload_type.model_config.get("extra") == "forbid"
        discriminators.add(payload_type.model_fields["payload_kind"].default)
    # Every member has a distinct discriminator, so the union is unambiguous.
    assert len(discriminators) == len(RAIL_PAYLOAD_TYPES)


def test_the_union_holds_exactly_the_known_variants():
    """Payment (S006) and trade (S015). A new rail adds a variant here, and the
    decision layer is unchanged when it does (INV-8)."""
    assert RAIL_PAYLOAD_TYPES == (PaymentPayload, TradePayload)


class TestSymbolIsNotAFreeTextChannel:
    """INV-3: a boundary field may not carry free text. `symbol` is a ticker,
    pattern-bounded so a raw identifier, a name, or a paragraph cannot ride in
    it into the immutable intent."""

    def _trade(self, symbol: str) -> TradePayload:
        from secondsign.intent import OrderType, TradeSide

        return TradePayload(
            symbol=symbol, quantity=1, side=TradeSide.buy, order_type=OrderType.market
        )

    def test_a_plain_ticker_is_accepted(self) -> None:
        assert self._trade("AAPL").symbol == "AAPL"
        assert self._trade("BRK.B").symbol == "BRK.B"

    @pytest.mark.parametrize(
        "bad",
        [
            "aapl",  # lower case is not a ticker shape
            "A" * 11,  # over ten characters
            "GB29 NWBK 6016 1331 9268 19",  # an IBAN
            "Jane Doe",  # a name (space)
            "'; DROP TABLE",  # an injection attempt
            "",  # empty
            "1234567890123456",  # a card-number-shaped string
        ],
    )
    def test_a_free_text_symbol_is_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            self._trade(bad)
