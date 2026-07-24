# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The conformance kit must certify good extensions and reject bad ones.

A suite that passes everything certifies nothing, so half this file is
deliberately non-conformant plugins that the kit is required to catch.
"""

import pytest

from secondsign.conformance import PolicyPluginConformance
from secondsign.contracts import (
    CONTRACT_VERSION,
    MAX_DETAIL_MAGNITUDE,
    Finding,
    PluginJudgement,
    PluginVerdict,
    PolicyView,
    ReasonCode,
    RiskBand,
)


class WellBehavedPlugin:
    """A minimal conformant extension — the worked example for contributors."""

    contract_version = CONTRACT_VERSION

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        if view.counterparty_risk_band is RiskBand.prohibited:
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.counterparty_risk),),
            )
        if view.recent_count_window > 5:
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW,
                findings=(
                    Finding(
                        code=ReasonCode.velocity_limit, observed=view.recent_count_window, limit=5
                    ),
                ),
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class TestWellBehavedPlugin(PolicyPluginConformance):
    """This is exactly what a third party writes. Nothing else."""

    plugin = WellBehavedPlugin()


# --- the kit must reject these -----------------------------------------------


class Stateful:
    contract_version = CONTRACT_VERSION

    def __init__(self):
        self._seen = 0

    def evaluate(self, view):
        self._seen += 1
        if self._seen > 3:
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW,
                findings=(Finding(code=ReasonCode.velocity_limit),),
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class SmugglesAnIdentifier:
    """Bypasses validation with model_construct to carry a card-shaped number.

    Since CORE-S004 there is no prose field to echo an identifier into, so the
    remaining leak route is an out-of-bounds quantity built without validation.
    The kit checks emitted values rather than trusting the model.
    """

    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        smuggled = Finding.model_construct(
            code=ReasonCode.org_policy,
            observed=MAX_DETAIL_MAGNITUDE + 4111111111111111,
            limit=None,
        )
        return PluginJudgement.model_construct(
            contract_version=CONTRACT_VERSION,
            verdict=PluginVerdict.REVIEW,
            findings=(smuggled,),
        )


class WrongVersion:
    contract_version = CONTRACT_VERSION + 1

    def evaluate(self, view):
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class Crashes:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        raise RuntimeError("bad plugin")


class ReturnsGarbage:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        return {"verdict": "fine"}


def _run(suite_cls, plugin, method: str) -> None:
    suite = suite_cls()
    suite.plugin = plugin
    getattr(suite, method)()


@pytest.mark.parametrize(
    ("plugin", "method"),
    [
        (Stateful(), "test_has_no_side_effects_across_views"),
        (SmugglesAnIdentifier(), "test_findings_stay_within_the_closed_vocabulary"),
        (WrongVersion(), "test_declares_the_supported_contract_version"),
        (Crashes(), "test_never_trips_the_runner_failure_paths"),
        (ReturnsGarbage(), "test_never_trips_the_runner_failure_paths"),
    ],
    ids=["stateful", "smuggles-identifier", "wrong-version", "crashes", "returns-garbage"],
)
def test_kit_rejects_non_conformant_plugins(plugin, method):
    with pytest.raises(AssertionError):
        _run(PolicyPluginConformance, plugin, method)


def test_kit_refuses_to_certify_nothing():
    """Forgetting to set `plugin` must fail loudly, not pass vacuously."""
    with pytest.raises(AssertionError, match="must set a `plugin` attribute"):
        _run(PolicyPluginConformance, None, "test_declares_the_supported_contract_version")


def test_corpus_is_not_trivially_small():
    from secondsign.conformance import conformance_corpus

    assert len(conformance_corpus()) >= 30
