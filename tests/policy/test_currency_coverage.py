# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A currency no policy governs must be denied, not silently allowed.

The engine reads permission as the *absence* of any concern, so a decision in
which every policy abstained is an ALLOW. That is right for the plugin model —
until it meets a limit configured for one currency and a request that names
another. `AmountWindowPolicy` abstains on a currency mismatch (a USD limit is
not the authority on a EUR payment), so a deployment holding only a USD limit
would ALLOW an unlimited EUR payment: no policy raised a concern, so none was
had.

`CurrencyCoveragePolicy` closes that by *being* the concern: it denies any
currency outside the set a deployment has actually configured a limit for.
Composed beside the limits, it turns "no limit governs this currency" from a
silent allow into an explicit denial — without touching the combination law,
which stays a maximum over strictness.
"""

from __future__ import annotations

from datetime import datetime, timezone

from secondsign.contracts import Currency, PluginVerdict, ReasonCode
from secondsign.controlplane.window import WindowLedger
from secondsign.policy import AggregateKey, CurrencyCoveragePolicy, PolicyContext
from tests.policy.conftest import make_intent


def test_two_currencies_do_not_share_a_spending_window() -> None:
    """The aggregate is keyed by currency, so a multi-currency deployment cannot
    sum EUR minor units into a USD window. Without this, a coverage policy that
    admits more than one currency would measure both against one number of
    incomparable units."""
    now = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    ledger = WindowLedger(window_seconds=3600)
    usd_key = AggregateKey.from_intent(make_intent(currency=Currency.USD))
    eur_key = AggregateKey.from_intent(make_intent(currency=Currency.EUR))

    assert usd_key != eur_key, "same counterparty/source/rail but different currency must differ"

    ledger.record(usd_key, amount_minor=500_00, at=now)

    assert ledger.aggregate(usd_key, now=now).aggregate_minor == 500_00
    assert ledger.aggregate(eur_key, now=now).aggregate_minor == 0, (
        "EUR spend saw USD spend in its window — minor units of two currencies were summed"
    )


def test_a_covered_currency_abstains() -> None:
    policy = CurrencyCoveragePolicy(covered={Currency.USD, Currency.EUR})
    result = policy.evaluate(make_intent(currency=Currency.USD), PolicyContext())
    assert result.verdict is PluginVerdict.ABSTAIN
    assert result.findings == ()


def test_an_uncovered_currency_is_denied() -> None:
    policy = CurrencyCoveragePolicy(covered={Currency.USD})
    result = policy.evaluate(make_intent(currency=Currency.EUR), PolicyContext())
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.org_policy in {finding.code for finding in result.findings}


def test_an_empty_coverage_set_denies_everything() -> None:
    """A deployment that configured no limits at all governs no currency, so it
    permits none — the strictest reading of "no policy claims this"."""
    policy = CurrencyCoveragePolicy(covered=frozenset())
    result = policy.evaluate(make_intent(currency=Currency.USD), PolicyContext())
    assert result.verdict is PluginVerdict.DENY


def test_the_finding_names_no_raw_value() -> None:
    policy = CurrencyCoveragePolicy(covered={Currency.USD})
    result = policy.evaluate(make_intent(currency=Currency.EUR), PolicyContext())
    # The currency code is a closed enum member, not a raw identifier, and the
    # finding carries only a reason code — no amount, no account, no free text.
    for finding in result.findings:
        assert finding.observed is None


class TestTheCompositionRefusesAForeignCurrency:
    """The whole point, at the level the vulnerability lived: a service composed
    the way `build_authorization` composes it — a USD limit beside a USD
    coverage policy — moves a USD payment under the cap and refuses a EUR one
    outright, with the rail never touched."""

    def _service(self, rail):
        from datetime import datetime, timezone

        from secondsign.audit import AuditLog, InMemoryAuditSink
        from secondsign.controlplane.fingerprint import FingerprintKey
        from secondsign.controlplane.window import WindowLedger
        from secondsign.decision import DecisionEngine
        from secondsign.gateway.authorization import AuthorizationService
        from secondsign.gateway.execution import ExecutionGateway, InMemoryIdempotencyStore
        from secondsign.policy import AmountLimit, AmountWindowPolicy

        limit = AmountLimit(
            quote_currency=Currency.USD, window_seconds=3600, max_aggregate_minor=1_000_00
        )
        return AuthorizationService(
            engine=DecisionEngine(
                [AmountWindowPolicy(limit), CurrencyCoveragePolicy(covered={Currency.USD})]
            ),
            gateway=ExecutionGateway(rail, InMemoryIdempotencyStore()),
            ledger=WindowLedger(window_seconds=3600),
            audit=AuditLog(InMemoryAuditSink()),
            keys=FingerprintKey.generate(),
        ), datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)

    def _request(self, currency: str):
        from secondsign.agent.surface import AuthorizationRequest

        return AuthorizationRequest.model_validate(
            {
                "action": "payment",
                "rail": "card",
                "currency": currency,
                "amount_minor": 100_00,
                "reversibility": "irreversible",
                "counterparty_ref": "fp:" + "cd" * 32,
                "source_account_ref": "fp:" + "ef" * 32,
                "request_ref": "fp:" + "12" * 32,
            }
        )

    def test_a_usd_payment_under_the_cap_completes(self) -> None:
        from secondsign.gateway.execution import ExecutionStatus, RailResult

        class Rail:
            def __init__(self):
                self.calls = 0

            def dispatch(self, intent):
                self.calls += 1
                return RailResult(status=ExecutionStatus.success, reference="r")

        rail = Rail()
        service, now = self._service(rail)
        outcome = service.authorize("spiffe://x/a", self._request("USD"), now=now)
        assert outcome.status.value == "completed"
        assert rail.calls == 1

    def test_a_eur_payment_is_refused_and_never_reaches_the_rail(self) -> None:
        from secondsign.gateway.execution import ExecutionStatus, RailResult

        class Rail:
            def __init__(self):
                self.calls = 0

            def dispatch(self, intent):
                self.calls += 1
                return RailResult(status=ExecutionStatus.success, reference="r")

        rail = Rail()
        service, now = self._service(rail)
        outcome = service.authorize("spiffe://x/a", self._request("EUR"), now=now)
        assert outcome.status.value == "refused", (
            "a currency with no configured limit was not refused — the coverage "
            "guard did not fire, and an unlimited foreign-currency payment is "
            "allowed"
        )
        assert rail.calls == 0, "a refused foreign-currency payment reached the rail"
