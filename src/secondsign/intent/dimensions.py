# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Decision dimensions — the raw, redacted facts a decision is made on.

This is the single place core is deliberately *general*: what is generic is the
set of decision dimensions, not any rail's field names. Policy reasons over a
band of value, a validity window, a counterparty class, a source account and a
rail class — never a vendor payload.

The dimensions are the raw inputs; the derived, plugin-facing
:class:`~secondsign.contracts.PolicyView` is computed from them later on the
decision path. Control-plane material (the idempotency key) is deliberately
absent: it is execution material, not a thing a decision is made on.

The field set is an exact scalar allow-list (threat A5). Every field is a
scalar or a closed enum reused from the frozen contract vocabulary; there is no
mapping, and a reference field accepts only a keyed fingerprint.
"""

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from secondsign.contracts import (
    Currency,
    Fingerprint,
    RailClass,
    Reversibility,
    SourceTrust,
)


class DecisionDimensions(BaseModel):
    """The redacted, rail-agnostic inputs to a decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Integer minor units. A band, not a scalar: a market order has no settled
    #: value at decision time, and policy must be able to judge the upper end.
    value_lower_minor: int = Field(ge=0)
    value_upper_minor: int = Field(ge=0)
    quote_currency: Currency

    counterparty_ref: Fingerprint
    source_account_ref: Fingerprint

    #: The kind of rail, never the vendor — core stays rail-agnostic.
    rail_class: RailClass

    not_before: AwareDatetime
    not_after: AwareDatetime

    reversibility: Reversibility
    #: Provenance of the instruction. Only ever downgraded, never upgraded.
    source_trust: SourceTrust
    #: The number of entities a batch action touches.
    scope_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _band_and_window_are_ordered(self) -> "DecisionDimensions":
        if self.value_upper_minor < self.value_lower_minor:
            raise ValueError("value_upper_minor cannot be below value_lower_minor")
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self
