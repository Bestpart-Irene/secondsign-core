# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Running plugins without letting them break the decision path.

A plugin is third-party code on a path that moves money. It may crash, it may
return nonsense, it may speak a contract version this build has never heard of.
None of those may result in silence, and none of them may stop the other
plugins from being heard.
"""

import logging
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from secondsign.contracts.combine import combine, neutral
from secondsign.contracts.types import (
    CONTRACT_VERSION,
    PluginJudgement,
    PluginVerdict,
    PolicyView,
    ReasonCode,
)

logger = logging.getLogger("secondsign.contracts")


@runtime_checkable
class PolicyPlugin(Protocol):
    """What an extension implements.

    Pure: one view in, one judgement out, no side effects and no mutation of
    the view (which is frozen regardless).

    An ``isinstance`` check against this Protocol is structural only — it sees
    the attribute names and nothing else. It is therefore never the safety
    gate; the gate is that the returned value is validated as a
    :class:`PluginJudgement`, and anything else is treated as a failure.
    """

    contract_version: int

    def evaluate(self, view: PolicyView) -> PluginJudgement: ...


def _deny(reason: ReasonCode, explanation: str) -> PluginJudgement:
    """The response to a plugin that cannot be trusted to have answered.

    DENY, not an escalation (INV-1). A plugin that failed might have been the
    one about to deny, and treating "we do not know" as "a human should look"
    moves a machine-checkable guarantee into a review queue that, under load,
    gets approved in bulk.

    The availability objection is real — one crashing extension can hold every
    transaction — and is answered by operator-visible extension health and a
    declared degraded state, not by softening the verdict. See
    ``docs/INVARIANTS.md``.
    """
    return PluginJudgement(verdict=PluginVerdict.DENY, reasons=(reason,), explanation=explanation)


def _evaluate_isolated(plugin: object, view: PolicyView) -> PluginJudgement:
    """One plugin's answer, or an escalation explaining why there isn't one."""
    declared = getattr(plugin, "contract_version", None)
    if declared != CONTRACT_VERSION:
        # Not consulted at all. A plugin speaking an unknown dialect might mean
        # something different by DENY, so even a well-formed answer from it is
        # discarded rather than interpreted.
        logger.warning(
            "plugin %s declares contract version %r; expected %r",
            type(plugin).__name__,
            declared,
            CONTRACT_VERSION,
        )
        return _deny(
            ReasonCode.plugin_contract_mismatch,
            "A plugin declares an unrecognised contract version and was not consulted.",
        )

    evaluate = getattr(plugin, "evaluate", None)
    if not callable(evaluate):
        return _deny(
            ReasonCode.plugin_contract_mismatch,
            "A plugin does not implement the evaluation contract.",
        )

    try:
        result = evaluate(view)
    except Exception:  # noqa: BLE001 — the runner owns plugin failure semantics
        # BaseException (KeyboardInterrupt, SystemExit, cancellation) is
        # deliberately not caught: it must unwind, and an unwind is fail-closed
        # by construction because nothing downstream runs without a decision.
        logger.warning("plugin %s raised during evaluation", type(plugin).__name__, exc_info=True)
        return _deny(
            ReasonCode.plugin_error,
            "A plugin failed during evaluation; denying.",
        )

    if not isinstance(result, PluginJudgement):
        return _deny(
            ReasonCode.plugin_invalid_result,
            "A plugin returned a value that is not a judgement.",
        )
    if result.contract_version != CONTRACT_VERSION:
        return _deny(
            ReasonCode.plugin_contract_mismatch,
            "A plugin returned a judgement in an unrecognised contract version.",
        )
    return result


def run_plugins(plugins: Iterable[object], view: PolicyView) -> PluginJudgement:
    """Consult every plugin and reduce their judgements monotonically.

    Every plugin runs even if an earlier one failed, and the reduction is a
    maximum, so the outcome does not depend on the order they were registered
    in. With no plugins installed the result is ABSTAIN — silence, not
    approval.
    """
    result = neutral()
    for plugin in plugins:
        result = combine(result, _evaluate_isolated(plugin, view))
    return result
