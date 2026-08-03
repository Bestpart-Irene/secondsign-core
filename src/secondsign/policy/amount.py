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

A limit may declare a third band. Below `review_above_minor` the action is the
machine's to allow; between there and the cap it is held for a human (REVIEW);
above the cap it is denied. The review threshold is optional, and a limit whose
threshold sits at or above its cap is refused at construction rather than
producing a band no action can reach.
"""

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secondsign.contracts import (
    MAX_DETAIL_MAGNITUDE,
    Currency,
    Finding,
    PluginJudgement,
    PluginVerdict,
    RailClass,
    ReasonCode,
)
from secondsign.intent import TransactionIntent

_ABSTAIN = PluginJudgement(verdict=PluginVerdict.ABSTAIN)


def _bounded(value: int | None) -> int | None:
    """Clamp a reported quantity to the finding's magnitude ceiling.

    ``Finding.observed``/``limit`` are capped at ``MAX_DETAIL_MAGNITUDE`` (the
    A5 anti-identifier bound). A prospective window sum, or a limit, can exceed
    that — an agent naming an absurd amount is enough — and constructing the
    finding with the raw value would raise a ``ValidationError`` that the engine
    turns into a ``plugin_error`` DENY, mislabelling a limit breach (and
    collapsing a REVIEW into a DENY). Clamping keeps the finding constructible
    and honest: the value is *at least* the ceiling, which is all a reader needs
    to see it is over the limit.
    """
    if value is None:
        return None
    return min(value, MAX_DETAIL_MAGNITUDE)


def _deny(
    code: ReasonCode, *, observed: int | None = None, limit: int | None = None
) -> PluginJudgement:
    return PluginJudgement(
        verdict=PluginVerdict.DENY,
        findings=(Finding(code=code, observed=_bounded(observed), limit=_bounded(limit)),),
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
    """A cap on the windowed aggregate for one currency, and where a human
    enters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    quote_currency: Currency
    window_seconds: int = Field(gt=0)
    #: Inclusive cap: spending exactly this much is allowed, a unit more is not.
    max_aggregate_minor: int = Field(ge=0)
    #: Above this, the decision stops being the machine's to make and the action
    #: is held for a checker. Exclusive, and optional: absent means this limit
    #: has two bands rather than three, which is what every deployment before
    #: CORE-S022 had.
    review_above_minor: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _review_band_can_occur(self) -> "AmountLimit":
        if self.review_above_minor is None:
            return self
        if self.review_above_minor >= self.max_aggregate_minor:
            # At the cap, every value above the threshold is also above the cap,
            # so the band is empty and no action would ever reach a human. An
            # operator who writes this means something, and it is not this.
            raise ValueError(
                "review_above_minor must be below max_aggregate_minor, or the "
                "review band is empty and no action can reach a human"
            )
        return self


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
        review_above = self._limit.review_above_minor
        if review_above is not None and prospective > review_above:
            # Checked after the cap, so a value over both is denied rather than
            # reviewed. Combination would reach the same answer — DENY is
            # stricter than REVIEW and the algebra takes the maximum — but a
            # policy that returned REVIEW for an over-cap action would be
            # stating something false about it in its own finding.
            #
            # The code is `value_band_exceeded` rather than a review-specific
            # one because the reason vocabulary is frozen at CONTRACT_VERSION 1
            # and minting a code is a contract change. The verdict says a human
            # is needed; the finding says which band was crossed to decide that.
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW,
                findings=(
                    Finding(
                        code=ReasonCode.value_band_exceeded,
                        observed=_bounded(prospective),
                        limit=_bounded(review_above),
                    ),
                ),
            )
        return _ABSTAIN
