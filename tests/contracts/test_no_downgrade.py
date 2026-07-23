"""A plugin may tighten. It has no vocabulary for anything else.

The guarantee is structural, not procedural: there is no ALLOW member for a
plugin to return, so "plugin approved the payment" is not an expressible
statement in this contract.
"""

import pytest

from secondsign.contracts import (
    Finding,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
    run_plugins,
)


class StubPlugin:
    contract_version = 1

    def __init__(self, verdict, reason=ReasonCode.org_policy):
        self._judgement = (
            PluginJudgement(verdict=verdict)
            if verdict is PluginVerdict.ABSTAIN
            else PluginJudgement(verdict=verdict, findings=(Finding(code=reason),))
        )

    def evaluate(self, view):
        return self._judgement


def test_plugin_vocabulary_has_no_allow():
    assert {v.name for v in PluginVerdict} == {"ABSTAIN", "REVIEW", "DENY"}
    assert not hasattr(PluginVerdict, "ALLOW")


def test_abstaining_plugin_cannot_clear_a_deny(view):
    plugins = [StubPlugin(PluginVerdict.DENY), StubPlugin(PluginVerdict.ABSTAIN)]
    assert run_plugins(plugins, view).verdict is PluginVerdict.DENY


def test_reviewing_plugin_cannot_soften_a_deny(view):
    plugins = [StubPlugin(PluginVerdict.DENY), StubPlugin(PluginVerdict.REVIEW)]
    assert run_plugins(plugins, view).verdict is PluginVerdict.DENY


def test_order_does_not_change_the_outcome(view):
    strict = StubPlugin(PluginVerdict.DENY, ReasonCode.counterparty_risk)
    soft = StubPlugin(PluginVerdict.REVIEW, ReasonCode.velocity_limit)
    quiet = StubPlugin(PluginVerdict.ABSTAIN)

    forward = run_plugins([strict, soft, quiet], view)
    reverse = run_plugins([quiet, soft, strict], view)

    assert forward.verdict is reverse.verdict
    assert set(forward.reasons) == set(reverse.reasons)


@pytest.mark.parametrize("added", [PluginVerdict.ABSTAIN, PluginVerdict.REVIEW, PluginVerdict.DENY])
def test_adding_a_plugin_never_lowers_strictness(view, added):
    strictness = {PluginVerdict.ABSTAIN: 0, PluginVerdict.REVIEW: 1, PluginVerdict.DENY: 2}
    base = [StubPlugin(PluginVerdict.REVIEW)]
    before = run_plugins(base, view)
    after = run_plugins([*base, StubPlugin(added)], view)
    assert strictness[after.verdict] >= strictness[before.verdict]


def test_no_plugins_means_abstain(view):
    assert run_plugins([], view).verdict is PluginVerdict.ABSTAIN


def test_result_is_immutable(view):
    result = run_plugins([StubPlugin(PluginVerdict.DENY)], view)
    assert isinstance(result.reasons, tuple)
    with pytest.raises(Exception):  # noqa: B017 — pydantic raises ValidationError
        result.verdict = PluginVerdict.ABSTAIN


def test_plugins_receive_the_view_unmodified(view):
    seen = []

    class Recorder:
        contract_version = 1

        def evaluate(self, v):
            seen.append(v)
            return PluginJudgement(verdict=PluginVerdict.ABSTAIN)

    run_plugins([Recorder(), Recorder()], view)
    assert seen == [view, view]
    assert all(v is view for v in seen)
