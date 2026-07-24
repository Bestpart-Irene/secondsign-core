# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The conformance suite must reject a non-conformant adapter, not just pass a
good one. A kit that only ever passes proves nothing; these adapters each break
one guarantee and the matching check is asserted to fail.
"""

import itertools

from secondsign.adapters import StripeAdapter, StripeCall
from secondsign.adapters.stripe import (
    _SUPPORTED_CURRENCIES,  # noqa: PLC2701 — test probes internals
)
from secondsign.conformance import RailAdapterConformance
from secondsign.contracts import RailClass, Reversibility, SourceTrust
from secondsign.intent import DecisionDimensions, TransactionIntent
from tests.adapters.conftest import make_stripe_call

_CORPUS = (make_stripe_call(declared_source_trust=SourceTrust.untrusted_data),)


class _TrustUpgradingAdapter:
    """Raises declared provenance — the exact B9 violation the suite must catch."""

    rail_class = RailClass.card

    def derive(self, call: StripeCall) -> TransactionIntent:
        dimensions = DecisionDimensions(
            value_lower_minor=call.amount_minor,
            value_upper_minor=call.amount_minor,
            quote_currency=call.quote_currency,
            counterparty_ref=call.counterparty_ref,
            source_account_ref=call.source_account_ref,
            rail_class=self.rail_class,
            not_before=call.not_before,
            not_after=call.not_after,
            reversibility=Reversibility.irreversible,
            source_trust=SourceTrust.trusted_instruction,  # upgraded — the defect
            scope_count=call.scope_count,
        )
        base = StripeAdapter().derive(call)
        assert isinstance(base, TransactionIntent)
        return base.model_copy(update={"dimensions": dimensions})


class _NonDeterministicAdapter:
    """Returns a different key each call — breaks determinism."""

    rail_class = RailClass.card

    def __init__(self) -> None:
        self._counter = itertools.count()

    def derive(self, call: StripeCall) -> TransactionIntent:
        base = StripeAdapter().derive(call)
        assert isinstance(base, TransactionIntent)
        return base.model_copy(update={"idempotency_key": f"key-{next(self._counter)}"})


def _assert_raises(fn) -> None:
    try:
        fn()
    except AssertionError:
        return
    raise AssertionError("conformance check accepted a non-conformant adapter")


def test_suite_rejects_a_trust_upgrading_adapter():
    class Cert(RailAdapterConformance):
        adapter = _TrustUpgradingAdapter()
        valid_calls = _CORPUS

    _assert_raises(Cert().test_source_trust_is_never_upgraded)


def test_suite_rejects_a_non_deterministic_adapter():
    class Cert(RailAdapterConformance):
        adapter = _NonDeterministicAdapter()
        valid_calls = _CORPUS

    _assert_raises(Cert().test_derivation_is_deterministic)


def test_suite_refuses_a_subclass_that_sets_no_adapter():
    class Cert(RailAdapterConformance):
        valid_calls = _CORPUS

    _assert_raises(Cert().test_declares_the_rail_class_it_serves)


def test_suite_refuses_a_subclass_with_an_empty_corpus():
    class Cert(RailAdapterConformance):
        adapter = StripeAdapter()

    _assert_raises(Cert().test_every_valid_call_maps_to_an_intent)


def test_supported_currency_set_is_non_empty():
    """Guard the probe import above stays meaningful."""
    assert _SUPPORTED_CURRENCIES
