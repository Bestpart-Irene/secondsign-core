# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The DecisionEngine — where concerns become a verdict.

Each policy raises a concern in the frozen decision vocabulary (ABSTAIN, REVIEW,
DENY). The engine combines them and maps the result to a decision: no concern is
ALLOW, a review concern is REVIEW, any denial is DENY. Permission is the
*absence* of a concern, never a positive grant a single policy could assert.

Three properties are structural, not conventional:

- **Monotone.** Combination is the maximum over strictness (``contracts.combine``),
  so adding a policy can only tighten a decision. There is no code path that
  returns a verdict weaker than one of its inputs (A9).
- **Fail-closed.** A policy that raises is uncertainty, and uncertainty denies:
  its exception becomes a ``plugin_error`` DENY that is combined in, never
  swallowed (A9).
- **Digest-bound.** Every decision carries the intent's digest, so approval and
  execution bind to the same value that was decided (B1).
"""

from collections.abc import Iterable
from enum import IntEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from secondsign.contracts import (
    Finding,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
    combine,
    neutral,
)
from secondsign.intent import IntentDigest, TransactionIntent, compute_digest
from secondsign.policy import PolicyContext


class DecisionVerdict(IntEnum):
    """The engine's verdict, ordered by strictness."""

    ALLOW = 0
    REVIEW = 1
    DENY = 2


#: How a combined plugin verdict maps to a decision. ABSTAIN — no concern —
#: becomes ALLOW; the two concern levels carry across unchanged.
_VERDICT_MAP = {
    PluginVerdict.ABSTAIN: DecisionVerdict.ALLOW,
    PluginVerdict.REVIEW: DecisionVerdict.REVIEW,
    PluginVerdict.DENY: DecisionVerdict.DENY,
}


class Policy(Protocol):
    """A core policy: judges an intent against redacted context, raises a concern."""

    def evaluate(self, intent: TransactionIntent, context: PolicyContext) -> PluginJudgement: ...


class Decision(BaseModel):
    """The engine's verdict, its reasons, and the digest it binds to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: DecisionVerdict
    digest: IntentDigest
    findings: tuple[Finding, ...] = ()

    @property
    def reasons(self) -> tuple[ReasonCode, ...]:
        """Stable reason codes, de-duplicated in finding order."""
        return tuple(dict.fromkeys(finding.code for finding in self.findings))


class DecisionEngine:
    """Combines a fixed set of policies into a single, monotone decision."""

    def __init__(self, policies: Iterable[Policy]) -> None:
        self._policies: tuple[Policy, ...] = tuple(policies)

    def decide(self, intent: TransactionIntent, context: PolicyContext) -> Decision:
        combined = neutral()
        for policy in self._policies:
            combined = combine(combined, self._evaluate(policy, intent, context))
        return Decision(
            verdict=_VERDICT_MAP[combined.verdict],
            digest=compute_digest(intent),
            findings=combined.findings,
        )

    @staticmethod
    def _evaluate(
        policy: Policy, intent: TransactionIntent, context: PolicyContext
    ) -> PluginJudgement:
        try:
            result = policy.evaluate(intent, context)
        except Exception:  # noqa: BLE001 — any failure is uncertainty, and uncertainty denies
            # The failure is turned into a denial and combined in, never
            # swallowed: a policy that could not answer must not be an ALLOW.
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.plugin_error),),
            )
        # A policy that returns something other than a PluginJudgement — None, a
        # bare verdict, anything — would crash `combine` outside this catch and
        # unwind `decide` with no Decision and so no receipt (INV-11). The engine
        # is fail-closed on that too, not only on a raised exception: an
        # unrecognisable answer is uncertainty, and uncertainty denies.
        if not isinstance(result, PluginJudgement):
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.plugin_invalid_result),),
            )
        return result
