# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Certifying the example plugin, and showing both of its branches.

The one line that matters is the :class:`PolicyPluginConformance` subclass — that
is the entire integration a third party performs. The inherited suite exercises
the plugin across a corpus of edge-case views and enforces the properties the
project will not negotiate: no approval, no view mutation, no leakage,
determinism, and no weakening of another extension.

The conformance corpus always presents the same counterparty fingerprint, so the
certified instance is configured with an allow-list that does **not** contain it.
The plugin therefore denies across the corpus, exercising its active path rather
than a trivial always-abstain. The two unit tests cover the other branch
directly.
"""

from datetime import datetime, timedelta, timezone

from counterparty_allowlist import CounterpartyAllowlistPolicy

from secondsign.conformance import PolicyPluginConformance
from secondsign.contracts import (
    ActionClass,
    Currency,
    MarketSession,
    PluginVerdict,
    PolicyView,
    RailClass,
    ReasonCode,
    Reversibility,
    RiskBand,
    SourceTrust,
    run_plugins,
)

#: An arbitrary allow-listed fingerprint, distinct from the corpus counterparty.
_ALLOWED = "fp:" + "cd" * 32
#: The fingerprint the conformance corpus uses — deliberately *not* allow-listed.
_NOT_ALLOWED = "fp:" + "a1" * 32


class TestCounterpartyAllowlistConformance(PolicyPluginConformance):
    # Certified against an allow-list that excludes the corpus counterparty, so
    # the suite runs the deny path from end to end.
    plugin = CounterpartyAllowlistPolicy(allowed_counterparties={_ALLOWED})


def _view(counterparty_ref: str) -> PolicyView:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return PolicyView(
        action_class=ActionClass.payment,
        rail_class=RailClass.bank_transfer,
        value_lower_minor=1_000,
        value_upper_minor=1_000,
        quote_currency=Currency.USD,
        counterparty_ref=counterparty_ref,
        source_account_ref="fp:" + "b2" * 32,
        not_before=now,
        not_after=now + timedelta(minutes=5),
        reversibility=Reversibility.irreversible,
        source_trust=SourceTrust.trusted_instruction,
        scope_count=1,
        recent_count_window=0,
        counterparty_risk_band=RiskBand.low,
        new_counterparty=False,
        cross_border=False,
        market_session=MarketSession.not_applicable,
    )


def test_allow_listed_counterparty_abstains():
    plugin = CounterpartyAllowlistPolicy(allowed_counterparties={_ALLOWED})
    result = run_plugins([plugin], _view(_ALLOWED))
    assert result.verdict is PluginVerdict.ABSTAIN
    assert result.findings == ()


def test_unlisted_counterparty_is_denied_with_org_policy():
    plugin = CounterpartyAllowlistPolicy(allowed_counterparties={_ALLOWED})
    result = run_plugins([plugin], _view(_NOT_ALLOWED))
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.org_policy in result.reasons
