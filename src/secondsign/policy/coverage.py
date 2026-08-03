# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Deny a currency no configured limit governs.

The decision engine reads permission as the absence of a concern: a decision in
which every policy abstained is an ALLOW. `AmountWindowPolicy` abstains on a
currency mismatch, because a USD limit is not the authority on a EUR payment.
So a deployment holding only a USD limit ALLOWs an unlimited EUR payment — no
policy raised a concern, and none was had. That inverts INV-1: a currency the
deployment never configured is treated as permitted rather than as the strictest
outcome.

This policy is the concern for that gap. It carries the set of currencies a
deployment has actually configured a limit for, and denies anything outside it.
Composed beside the limits, "no limit governs this currency" becomes an explicit
denial, and the combination law is untouched — DENY is a maximum over
strictness, so adding this policy can only tighten a decision.
"""

from __future__ import annotations

from collections.abc import Iterable

from secondsign.contracts import Currency, Finding, PluginJudgement, PluginVerdict, ReasonCode
from secondsign.intent import TransactionIntent

_ABSTAIN = PluginJudgement(verdict=PluginVerdict.ABSTAIN)
_DENY = PluginJudgement(
    verdict=PluginVerdict.DENY,
    findings=(Finding(code=ReasonCode.org_policy),),
)


class CurrencyCoveragePolicy:
    """Denies any currency outside the configured coverage set.

    The reason is ``org_policy`` — the deployment has no limit for this currency,
    which is an organisational policy statement, not a threshold crossing. The
    frozen reason vocabulary carries no code for "unconfigured currency", and
    minting one is a contract change; ``org_policy`` is the honest generalisation
    and the finding names no raw value.
    """

    def __init__(self, covered: Iterable[Currency]) -> None:
        self._covered: frozenset[Currency] = frozenset(covered)

    def evaluate(self, intent: TransactionIntent, context: object) -> PluginJudgement:
        if intent.dimensions.quote_currency in self._covered:
            return _ABSTAIN
        return _DENY
