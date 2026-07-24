# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A misbehaving plugin fails upward, never open.

Three failure modes are distinguished so an operator can tell a crash from a
version mismatch from a contract violation. All three escalate; none of them
can clear another plugin's finding, and none of them can result in silence.
"""

import pytest

from secondsign.contracts import (
    CONTRACT_VERSION,
    Finding,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
    render,
    run_plugins,
)


class Exploding:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        raise RuntimeError("boom")


class ReturnsGarbage:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        return "looks fine to me"


class ReturnsNothing:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view):
        return None


class FromTheFuture:
    contract_version = CONTRACT_VERSION + 99

    def evaluate(self, view):
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class NoVersion:
    def evaluate(self, view):
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class NotAPluginAtAll:
    pass


@pytest.mark.parametrize(
    ("plugin", "expected_reason"),
    [
        (Exploding(), ReasonCode.plugin_error),
        (ReturnsGarbage(), ReasonCode.plugin_invalid_result),
        (ReturnsNothing(), ReasonCode.plugin_invalid_result),
        (FromTheFuture(), ReasonCode.plugin_contract_mismatch),
        (NoVersion(), ReasonCode.plugin_contract_mismatch),
        (NotAPluginAtAll(), ReasonCode.plugin_contract_mismatch),
    ],
)
def test_every_failure_mode_escalates_with_a_distinct_reason(view, plugin, expected_reason):
    result = run_plugins([plugin], view)
    assert result.verdict is PluginVerdict.DENY
    assert expected_reason in result.reasons
    assert render(result).strip()


def test_a_failing_plugin_does_not_suppress_a_healthy_one(view):
    class Denier:
        contract_version = CONTRACT_VERSION

        def evaluate(self, v):
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.counterparty_risk),),
            )

    result = run_plugins([Exploding(), Denier()], view)
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.counterparty_risk in result.reasons
    assert ReasonCode.plugin_error in result.reasons


def test_a_failing_plugin_cannot_clear_a_deny_from_another(view):
    class Denier:
        contract_version = CONTRACT_VERSION

        def evaluate(self, v):
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.org_policy),),
            )

    assert run_plugins([Denier(), ReturnsGarbage()], view).verdict is PluginVerdict.DENY


def test_all_plugins_run_even_when_one_explodes(view):
    seen = []

    class Recorder:
        contract_version = CONTRACT_VERSION

        def evaluate(self, v):
            seen.append(1)
            return PluginJudgement(verdict=PluginVerdict.ABSTAIN)

    run_plugins([Recorder(), Exploding(), Recorder()], view)
    assert len(seen) == 2


def test_exception_does_not_propagate_to_the_caller(view):
    run_plugins([Exploding()], view)  # must not raise


def test_base_exceptions_are_allowed_to_unwind(view):
    """Cancellation and interrupt must not be swallowed.

    An unwind is fail-closed by construction: nothing downstream executes on a
    stack that never returned a decision.
    """

    class Interrupted:
        contract_version = CONTRACT_VERSION

        def evaluate(self, v):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_plugins([Interrupted()], view)


def test_a_judgement_from_a_mismatched_version_is_ignored_entirely(view):
    """Even a well-formed judgement is discarded if the dialect is unknown."""

    class FutureDenier:
        contract_version = CONTRACT_VERSION + 1

        def evaluate(self, v):
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.org_policy),),
            )

    result = run_plugins([FutureDenier()], view)
    assert ReasonCode.plugin_contract_mismatch in result.reasons
    assert ReasonCode.org_policy not in result.reasons


def test_non_abstain_judgement_requires_reason_and_explanation():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PluginJudgement(verdict=PluginVerdict.DENY)
    with pytest.raises(ValidationError):
        PluginJudgement(verdict=PluginVerdict.REVIEW, findings=())
