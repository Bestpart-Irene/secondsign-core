# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for policy plugins.

A third party proves their extension is safe to install by inheriting from
:class:`PolicyPluginConformance` and naming their subclass ``Test...``:

.. code-block:: python

    from secondsign.conformance import PolicyPluginConformance
    from my_package import MyPlugin


    class TestMyPlugin(PolicyPluginConformance):
        plugin = MyPlugin()

That is the whole integration. The suite then exercises the plugin across a
corpus of edge-case views and checks the properties this project will not
negotiate — no approval capability, no input mutation, no leakage of the
identifiers it was shown, determinism, and no downgrade when combined with
other extensions.

Passing this suite is what "compatible with SecondSign" means. It is
deliberately mechanical: nobody should have to re-argue the security
principles in review every time a rail or a rule is added.

This module imports no test framework. The methods are plain assertions, so
pytest collects them from the subclass without the kit itself becoming a
runtime dependency on pytest.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from secondsign.contracts import (
    CONTRACT_VERSION,
    MAX_DETAIL_MAGNITUDE,
    ActionClass,
    Currency,
    Finding,
    MarketSession,
    PluginJudgement,
    PluginVerdict,
    PolicyView,
    RailClass,
    ReasonCode,
    Reversibility,
    RiskBand,
    SourceTrust,
    render,
    run_plugins,
)

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_REF_A = "fp:" + "a1" * 32
_REF_B = "fp:" + "b2" * 32


def _view(**overrides: object) -> PolicyView:
    # Local construction dict, not a model field — INV-3 constrains what a
    # published model may declare, not how a fixture is assembled.
    base: dict[str, Any] = {
        "action_class": ActionClass.payment,
        "rail_class": RailClass.bank_transfer,
        "value_lower_minor": 1_000,
        "value_upper_minor": 1_000,
        "quote_currency": Currency.USD,
        "counterparty_ref": _REF_A,
        "source_account_ref": _REF_B,
        "not_before": _EPOCH,
        "not_after": _EPOCH + timedelta(minutes=5),
        "reversibility": Reversibility.irreversible,
        "source_trust": SourceTrust.trusted_instruction,
        "scope_count": 1,
        "recent_count_window": 0,
        "counterparty_risk_band": RiskBand.low,
        "new_counterparty": False,
        "cross_border": False,
        "market_session": MarketSession.not_applicable,
    }
    base.update(overrides)
    return PolicyView(**base)


def conformance_corpus() -> tuple[PolicyView, ...]:
    """Edge-case views every extension is exercised against.

    Chosen to cross the boundaries a plugin is likely to branch on: the value
    extremes, an unsettled value band, every risk band and trust level, batch
    scope, and the market states that only matter for brokerage rails.
    """
    views = [
        _view(),
        _view(value_lower_minor=0, value_upper_minor=0),
        _view(value_lower_minor=1, value_upper_minor=9_999_999_999),
        _view(scope_count=0),
        _view(scope_count=10_000),
        _view(recent_count_window=10_000),
        _view(new_counterparty=True),
        _view(cross_border=True),
        _view(reversibility=Reversibility.reversible),
    ]
    views += [_view(action_class=member) for member in ActionClass]
    views += [_view(rail_class=member) for member in RailClass]
    views += [_view(counterparty_risk_band=member) for member in RiskBand]
    views += [_view(source_trust=member) for member in SourceTrust]
    views += [_view(market_session=member) for member in MarketSession]
    views += [_view(quote_currency=member) for member in Currency]
    return tuple(views)


class _AlwaysDeny:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        return PluginJudgement(
            verdict=PluginVerdict.DENY,
            findings=(Finding(code=ReasonCode.org_policy),),
        )


class _AlwaysAbstain:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class PolicyPluginConformance:
    """Inherit and set ``plugin``. Name the subclass ``Test...``."""

    #: The extension under test. Subclasses must set this.
    plugin: object = None

    # -- helpers ------------------------------------------------------------

    def _plugin(self) -> object:
        if self.plugin is None:
            raise AssertionError(
                f"{type(self).__name__} must set a `plugin` attribute to the "
                "extension instance being certified"
            )
        return self.plugin

    def _judgements(self):
        plugin = self._plugin()
        for view in conformance_corpus():
            yield view, run_plugins([plugin], view)

    # -- contract compliance ------------------------------------------------

    def test_declares_the_supported_contract_version(self):
        declared = getattr(self._plugin(), "contract_version", None)
        assert declared == CONTRACT_VERSION, (
            f"plugin declares contract version {declared!r}; this build speaks "
            f"{CONTRACT_VERSION!r}. A plugin with a mismatched version is never consulted."
        )

    def test_returns_a_judgement_for_every_view_in_the_corpus(self):
        for view, result in self._judgements():
            assert isinstance(result, PluginJudgement), f"no judgement for {view.action_class}"

    def test_never_trips_the_runner_failure_paths(self):
        """The runner denies on a crash, a bad return, or a version mismatch.

        Those denials are safe but they are not judgements — the plugin did not
        actually answer. A conformant extension never causes one.
        """
        runner_failures = {
            ReasonCode.plugin_error,
            ReasonCode.plugin_invalid_result,
            ReasonCode.plugin_contract_mismatch,
        }
        for view, result in self._judgements():
            tripped = runner_failures & set(result.reasons)
            assert not tripped, (
                f"plugin caused a runner failure ({', '.join(sorted(tripped))}) "
                f"on a {view.action_class} view — it crashed, returned a non-judgement, "
                "or declared an unsupported contract version"
            )

    def test_never_claims_approval(self):
        """INV-6. There is no ALLOW to return, so this catches a plugin that
        tries to signal approval by some other means."""
        assert not hasattr(PluginVerdict, "ALLOW")
        for _, result in self._judgements():
            assert result.verdict in (
                PluginVerdict.ABSTAIN,
                PluginVerdict.REVIEW,
                PluginVerdict.DENY,
            )

    # -- purity and determinism ---------------------------------------------

    def test_does_not_mutate_the_view(self):
        plugin = self._plugin()
        for view in conformance_corpus():
            before = view.model_dump()
            run_plugins([plugin], view)
            assert view.model_dump() == before, "plugin mutated the view it was given"

    def test_is_deterministic(self):
        """INV-13. Same input, same output — including reason ordering."""
        plugin = self._plugin()
        for view in conformance_corpus():
            first = run_plugins([plugin], view)
            second = run_plugins([plugin], view)
            assert first == second, "plugin is not deterministic for an identical view"

    def test_has_no_side_effects_across_views(self):
        """Judging one action must not change how the next is judged."""
        plugin = self._plugin()
        corpus = conformance_corpus()
        fresh = [run_plugins([plugin], view) for view in corpus]
        replayed = [run_plugins([plugin], view) for view in reversed(corpus)]
        assert fresh == list(reversed(replayed)), "plugin carries state between evaluations"

    # -- leakage -------------------------------------------------------------

    def test_findings_stay_within_the_closed_vocabulary(self):
        """INV-5. Text leakage is structurally impossible since CORE-S004 —
        there is no prose field to echo an identifier into.

        What remains checkable is the quantity bound. Pydantic validation can
        be bypassed with ``model_construct``, so the emitted values are
        verified here rather than trusted: a quantity large enough to hold an
        account number is a leak whatever route produced it.
        """
        for _, result in self._judgements():
            for finding in result.findings:
                assert isinstance(finding.code, ReasonCode), (
                    f"finding carries {finding.code!r}, which is not a published reason code"
                )
                for quantity in (finding.observed, finding.limit):
                    if quantity is None:
                        continue
                    assert isinstance(quantity, int) and not isinstance(quantity, bool), (
                        "finding quantities must be integers"
                    )
                    assert 0 <= quantity <= MAX_DETAIL_MAGNITUDE, (
                        f"finding quantity {quantity} is outside the published bound — "
                        "large enough to carry an identifier"
                    )

    def test_every_concern_is_actionable(self):
        """A non-ABSTAIN verdict nobody can act on is not a concern."""
        for _, result in self._judgements():
            if result.verdict is not PluginVerdict.ABSTAIN:
                assert result.findings, "non-abstaining judgement carries no finding"
                assert render(result).strip(), "non-abstaining judgement renders to nothing"

    # -- composition ---------------------------------------------------------

    def test_cannot_weaken_another_extension(self):
        """INV-2. Installing this plugin never lowers an existing verdict."""
        plugin = self._plugin()
        for view in conformance_corpus():
            with_deny = run_plugins([_AlwaysDeny(), plugin], view)
            assert with_deny.verdict is PluginVerdict.DENY, (
                "plugin weakened a DENY produced by another extension"
            )

    def test_registration_order_does_not_change_the_outcome(self):
        """INV-13. Two operators with the same plugins get the same answer."""
        plugin = self._plugin()
        others = [_AlwaysAbstain(), _AlwaysDeny()]
        for view in conformance_corpus():
            forward = run_plugins([plugin, *others], view)
            reverse = run_plugins([*reversed(others), plugin], view)
            assert forward.verdict is reverse.verdict
            assert set(forward.reasons) == set(reverse.reasons)

    def test_a_failing_neighbour_does_not_suppress_this_plugin(self):
        """One broken extension must not silence a healthy one."""

        class Exploding:
            contract_version = CONTRACT_VERSION

            def evaluate(self, view):
                raise RuntimeError("conformance fixture failure")

        plugin = self._plugin()
        for view in conformance_corpus():
            alone = run_plugins([plugin], view)
            beside = run_plugins([Exploding(), plugin], view)
            assert set(alone.reasons) <= set(beside.reasons), (
                "plugin findings were lost when a neighbouring extension failed"
            )
