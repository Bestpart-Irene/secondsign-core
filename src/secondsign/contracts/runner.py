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
    Finding,
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


def _deny(reason: ReasonCode) -> PluginJudgement:
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
    return PluginJudgement(verdict=PluginVerdict.DENY, findings=(Finding(code=reason),))


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
        return _deny(ReasonCode.plugin_contract_mismatch)

    evaluate = getattr(plugin, "evaluate", None)
    if not callable(evaluate):
        return _deny(ReasonCode.plugin_contract_mismatch)

    try:
        result = evaluate(view)
    except Exception:  # noqa: BLE001 — the runner owns plugin failure semantics
        # BaseException (KeyboardInterrupt, SystemExit, cancellation) is
        # deliberately not caught: it must unwind, and an unwind is fail-closed
        # by construction because nothing downstream runs without a decision.
        logger.warning("plugin %s raised during evaluation", type(plugin).__name__, exc_info=True)
        return _deny(ReasonCode.plugin_error)

    if not isinstance(result, PluginJudgement):
        return _deny(ReasonCode.plugin_invalid_result)
    # isinstance is not enough: a subclass overriding `findings`/`sort_key`, or an
    # instance built with `model_construct`, is a `PluginJudgement` that never ran
    # a validator — re-opening the `MAX_DETAIL_MAGNITUDE` bound on `Finding.observed`
    # (the A5 identifier channel) and the "non-ABSTAIN needs findings" rule. Round-
    # tripping through `model_validate` forces every validator to run and yields a
    # canonical base instance, so what combines downstream is what the contract
    # actually permits, not what an extension asserted it built.
    try:
        result = PluginJudgement.model_validate(result.model_dump())
    except Exception:  # noqa: BLE001 — model_dump on a hostile subclass may raise anything; all of it is uncertainty
        # Not only ValidationError: `result.model_dump()` runs on the plugin's
        # own object first, and a subclass overriding model_dump (or a property
        # it touches) can raise any exception. Every one of them means the same
        # thing here — the result cannot be trusted as a judgement — so all of
        # them deny rather than letting one escape the runner.
        return _deny(ReasonCode.plugin_invalid_result)
    if result.contract_version != CONTRACT_VERSION:
        return _deny(ReasonCode.plugin_contract_mismatch)
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
