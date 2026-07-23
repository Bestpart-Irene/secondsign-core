"""The conformance kit must certify good extensions and reject bad ones.

A suite that passes everything certifies nothing, so half this file is
deliberately non-conformant plugins that the kit is required to catch.
"""

import pytest

from secondsign.conformance import PolicyPluginConformance
from secondsign.contracts import (
    CONTRACT_VERSION,
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
                reasons=(ReasonCode.counterparty_risk,),
                explanation="Counterparty risk band is prohibited by policy.",
            )
        if view.recent_count_window > 5:
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW,
                reasons=(ReasonCode.velocity_limit,),
                explanation="Recent activity exceeds the configured window.",
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
                reasons=(ReasonCode.velocity_limit,),
                explanation="Too many evaluations in this process.",
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class EchoesIdentifiers:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        return PluginJudgement(
            verdict=PluginVerdict.REVIEW,
            reasons=(ReasonCode.org_policy,),
            explanation=f"Flagged {view.counterparty_ref}",
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
        (EchoesIdentifiers(), "test_does_not_echo_identifiers_it_was_shown"),
        (WrongVersion(), "test_declares_the_supported_contract_version"),
        (Crashes(), "test_never_trips_the_runner_failure_paths"),
        (ReturnsGarbage(), "test_never_trips_the_runner_failure_paths"),
    ],
    ids=["stateful", "echoes-identifiers", "wrong-version", "crashes", "returns-garbage"],
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
