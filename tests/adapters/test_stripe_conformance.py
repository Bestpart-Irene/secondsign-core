# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The Stripe adapter certified against the rail-adapter conformance suite.

The subclass below is the entire integration: inheriting the suite runs every
guarantee the adapter boundary makes against a corpus of Stripe calls.
"""

from secondsign.adapters import StripeAdapter
from secondsign.conformance import RailAdapterConformance
from secondsign.contracts import Currency, SourceTrust
from secondsign.intent import PaymentTargetKind, SettlementPriority
from tests.adapters.conftest import make_stripe_call


class TestStripeAdapterConformance(RailAdapterConformance):
    adapter = StripeAdapter()
    valid_calls = (
        make_stripe_call(),
        make_stripe_call(amount_minor=1),
        make_stripe_call(amount_minor=9_999_999_999),
        make_stripe_call(cross_border=True, new_beneficiary=True),
        make_stripe_call(declared_source_trust=SourceTrust.untrusted_data),
        make_stripe_call(declared_source_trust=SourceTrust.mixed),
        make_stripe_call(quote_currency=Currency.EUR),
        make_stripe_call(quote_currency=Currency.GBP),
        make_stripe_call(target_kind=PaymentTargetKind.card),
        make_stripe_call(settlement_priority=SettlementPriority.express),
        make_stripe_call(scope_count=0),
    )
