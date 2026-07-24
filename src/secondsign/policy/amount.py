# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Amount limits, judged on a sliding-window aggregate.

A limit is not "this one transaction is under X". It is "this transaction plus
everything already spent in the trailing window, against the same counterparty,
source account and rail, is under X" (B4). A single transaction is the special
case where the window's prior spend is zero. Judging the aggregate is what stops
a large payment being split into many small ones that each pass alone.

Two fail-closed choices matter here:

- The window is a rolling **duration**, never a natural-day or natural-hour
  boundary — a boundary is itself a thing to game, spending up to it twice
  either side of midnight.
- If the aggregate is missing, or was computed for a different key or window,
  the policy denies (A4). It does not fall back to a laxer default limit;
  "we could not check the velocity" is treated as "over the limit".

The policy reads the aggregate; it does not compute it. The aggregate is
control-plane state the managed agent cannot reach, supplied as context.
"""

from pydantic import BaseModel, ConfigDict, Field

from secondsign.contracts import (
    Currency,
    Finding,
    PluginJudgement,
    PluginVerdict,
    RailClass,
    ReasonCode,
)
from secondsign.intent import TransactionIntent

_ABSTAIN = PluginJudgement(verdict=PluginVerdict.ABSTAIN)


def _deny(
    code: ReasonCode, *, observed: int | None = None, limit: int | None = None
) -> PluginJudgement:
    return PluginJudgement(
        verdict=PluginVerdict.DENY,
        findings=(Finding(code=code, observed=observed, limit=limit),),
    )


class AggregateKey(BaseModel):
    """What a window aggregate is grouped by: counterparty, source, rail."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    counterparty_ref: str
    source_account_ref: str
    rail_class: RailClass

    @classmethod
    def from_intent(cls, intent: TransactionIntent) -> "AggregateKey":
        d = intent.dimensions
        return cls(
            counterparty_ref=d.counterparty_ref,
            source_account_ref=d.source_account_ref,
            rail_class=d.rail_class,
        )


class WindowAggregate(BaseModel):
    """The trailing-window spend for one key, precomputed by the control plane."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: AggregateKey
    #: The rolling window this aggregate spans, in seconds. A duration, never a
    #: calendar boundary.
    window_seconds: int = Field(gt=0)
    #: Total minor units already spent in the window for this key.
    aggregate_minor: int = Field(ge=0)
    count: int = Field(ge=0)


class AmountLimit(BaseModel):
    """A cap on the windowed aggregate for one currency."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    quote_currency: Currency
    window_seconds: int = Field(gt=0)
    #: Inclusive cap: spending exactly this much is allowed, a unit more is not.
    max_aggregate_minor: int = Field(ge=0)


class PolicyContext(BaseModel):
    """The redacted state the amount policy reads. A ``None`` aggregate means the
    control plane could not supply one — which is a denial, not a pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    window_aggregate: WindowAggregate | None = None


class AmountWindowPolicy:
    """Judges an intent's value band against a windowed aggregate limit."""

    def __init__(self, limit: AmountLimit) -> None:
        self._limit = limit

    def evaluate(self, intent: TransactionIntent, context: PolicyContext) -> PluginJudgement:
        if intent.dimensions.quote_currency != self._limit.quote_currency:
            # A limit governs one currency; another currency is a different
            # limit's concern, not this policy's. Coverage is the engine's job.
            return _ABSTAIN

        aggregate = context.window_aggregate
        if aggregate is None:
            return _deny(ReasonCode.velocity_limit)

        # The aggregate must be the one that applies to this intent, over this
        # limit's window. A mismatch is unverifiable velocity — strictest path.
        if (
            aggregate.key != AggregateKey.from_intent(intent)
            or aggregate.window_seconds != self._limit.window_seconds
        ):
            return _deny(ReasonCode.velocity_limit)

        prospective = aggregate.aggregate_minor + intent.dimensions.value_upper_minor
        if prospective > self._limit.max_aggregate_minor:
            return _deny(
                ReasonCode.value_band_exceeded,
                observed=prospective,
                limit=self._limit.max_aggregate_minor,
            )
        return _ABSTAIN
