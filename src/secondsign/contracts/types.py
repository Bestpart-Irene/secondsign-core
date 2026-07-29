# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The vocabulary a plugin speaks.

Two models cross the boundary: :class:`PolicyView` goes out, and
:class:`PluginJudgement` comes back. Both are frozen and closed, and every
field is a scalar or a closed enum.

The shape carries the security property. A plugin cannot report that a payment
is fine, because :class:`PluginVerdict` has no member for it; and a plugin
cannot be handed an account number, because a reference field accepts only a
keyed fingerprint. Neither is a rule someone has to remember to follow.
"""

from enum import IntEnum, StrEnum
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    WrapValidator,
    model_validator,
)
from pydantic_core import PydanticCustomError
from pydantic_core.core_schema import ValidatorFunctionWrapHandler

#: Version of this contract. A plugin declaring anything else is not consulted.
#: Adding a field, a verdict, or an enum member is a version change.
CONTRACT_VERSION = 1

#: Keyed-fingerprint shape. Nothing else is accepted in a reference field, so a
#: PAN, IBAN, or customer name is not representable rather than merely
#: discouraged.
FINGERPRINT_PATTERN = r"^fp:[0-9a-f]{64}$"

#: Upper bound on any numeric detail an extension may attach to a finding.
#:
#: One trillion minor units is ten billion major units — far above any genuine
#: transaction limit or velocity count, and deliberately below the magnitude of
#: a 13-or-more-digit account or card number. An extension therefore cannot
#: encode an identifier in a quantity field (threat A5).
MAX_DETAIL_MAGNITUDE = 1_000_000_000_000


def _validate_fingerprint(
    value: object,
    handler: ValidatorFunctionWrapHandler,
) -> str:
    try:
        return handler(value)
    except ValidationError:
        error = PydanticCustomError(
            "fingerprint_format",
            "Expected fp: followed by 64 hexadecimal characters; "
            "provide a fingerprint of the identifier, not the identifier itself",
        )
        raise ValidationError.from_exception_data(
            "Fingerprint",
            [
                {
                    "type": error,
                    "loc": (),
                    "input": None,
                }
            ],
            hide_input=True,
        ) from None


Fingerprint = Annotated[
    str,
    Field(pattern=FINGERPRINT_PATTERN),
    WrapValidator(_validate_fingerprint),
]


class PluginVerdict(IntEnum):
    """What a plugin is allowed to say.

    Ordered by strictness so combination is a maximum. There is deliberately no
    ``ALLOW``: a plugin can raise concern or stay silent, and permission is not
    a thing it can grant.
    """

    ABSTAIN = 0
    REVIEW = 1
    DENY = 2


class ActionClass(StrEnum):
    payment = "payment"
    refund = "refund"
    payout = "payout"
    transfer = "transfer"
    trade = "trade"
    account_change = "account_change"


class RailClass(StrEnum):
    """The kind of rail, never the vendor — core stays rail-agnostic."""

    card = "card"
    bank_transfer = "bank_transfer"
    wallet = "wallet"
    brokerage = "brokerage"
    other = "other"


class Currency(StrEnum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    JPY = "JPY"
    CHF = "CHF"
    CAD = "CAD"
    AUD = "AUD"
    CNY = "CNY"
    HKD = "HKD"
    SGD = "SGD"


class Reversibility(StrEnum):
    irreversible = "irreversible"
    delayed_reversible = "delayed_reversible"
    reversible = "reversible"


class SourceTrust(StrEnum):
    """Where the instruction came from. Only ever downgraded, never upgraded."""

    untrusted_data = "untrusted_data"
    mixed = "mixed"
    unknown = "unknown"
    trusted_instruction = "trusted_instruction"


class RiskBand(StrEnum):
    """Counterparty risk as a band, not a score.

    A band is explainable to a reviewer and to a regulator, and it does not
    carry the resolution a raw provider score would — which would make it a
    side channel.
    """

    low = "low"
    elevated = "elevated"
    high = "high"
    prohibited = "prohibited"


class MarketSession(StrEnum):
    not_applicable = "not_applicable"
    open = "open"
    closed = "closed"
    pre_market = "pre_market"
    post_market = "post_market"
    halted = "halted"


class ReasonCode(StrEnum):
    """Stable codes. Text explains; codes are what downstream systems match on."""

    velocity_limit = "velocity_limit"
    counterparty_risk = "counterparty_risk"
    jurisdiction_restricted = "jurisdiction_restricted"
    market_session_closed = "market_session_closed"
    value_band_exceeded = "value_band_exceeded"
    new_counterparty = "new_counterparty"
    org_policy = "org_policy"

    # Contract-level failures. Distinguished so an operator can tell a crash
    # from a version mismatch from a contract violation.
    plugin_error = "plugin_error"
    plugin_contract_mismatch = "plugin_contract_mismatch"
    plugin_invalid_result = "plugin_invalid_result"


class PolicyView(BaseModel):
    """The redacted, derived facts a plugin is given. Nothing else.

    Deliberately absent: the idempotency key (control-plane material), the
    rail-specific payload (vendor internals), and anything raw. A plugin judges
    risk; it does not need identity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_version: int = CONTRACT_VERSION

    action_class: ActionClass
    rail_class: RailClass

    #: Integer minor units. A band, not a scalar: a market order has no settled
    #: value at decision time, and policy must be able to judge the upper end.
    value_lower_minor: int = Field(ge=0)
    value_upper_minor: int = Field(ge=0)
    quote_currency: Currency

    counterparty_ref: Fingerprint
    source_account_ref: Fingerprint

    not_before: AwareDatetime
    not_after: AwareDatetime

    reversibility: Reversibility
    source_trust: SourceTrust
    scope_count: int = Field(ge=0)

    #: Derived aggregate over the policy window — the count, never the
    #: underlying transactions.
    recent_count_window: int = Field(ge=0)
    counterparty_risk_band: RiskBand
    new_counterparty: bool
    cross_border: bool
    market_session: MarketSession

    @model_validator(mode="after")
    def _bands_and_windows_are_ordered(self) -> "PolicyView":
        if self.value_upper_minor < self.value_lower_minor:
            raise ValueError("value_upper_minor cannot be below value_lower_minor")
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class Finding(BaseModel):
    """One thing an extension observed, in closed vocabulary.

    No prose. A bounded, screened text field is still a text field, and an
    author who wants to pass a customer name through will eventually phrase it
    within the limit. The extension states *what* it found; core writes the
    sentence (see :mod:`secondsign.contracts.render`).

    ``observed`` and ``limit`` are optional quantities that make a finding
    reviewable — "velocity 9 against a limit of 5" rather than a bare code.
    Both are bounded so a quantity cannot carry an identifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ReasonCode
    #: What the extension measured, if the finding is quantitative.
    observed: int | None = Field(default=None, ge=0, le=MAX_DETAIL_MAGNITUDE)
    #: What it was measured against.
    limit: int | None = Field(default=None, ge=0, le=MAX_DETAIL_MAGNITUDE)

    def sort_key(self) -> tuple[str, int, int]:
        """Total order over findings, so records are canonical (INV-13).

        ``-1`` stands in for absent so a finding without a quantity sorts
        before the same code with one, deterministically.
        """
        return (
            self.code.value,
            self.observed if self.observed is not None else -1,
            self.limit if self.limit is not None else -1,
        )


class PluginJudgement(BaseModel):
    """What a plugin returns.

    An ABSTAIN needs nothing. Anything stronger must carry at least one
    finding — a concern nobody can act on is not a concern.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_version: int = CONTRACT_VERSION
    verdict: PluginVerdict
    #: Tuple, not list: `frozen=True` is shallow, and an appendable collection
    #: would let a plugin rewrite the audit story after the fact.
    findings: tuple[Finding, ...] = ()

    @property
    def reasons(self) -> tuple[ReasonCode, ...]:
        """The distinct reason codes, in finding order. Derived, not stored."""
        return tuple(dict.fromkeys(finding.code for finding in self.findings))

    @model_validator(mode="after")
    def _concerns_must_be_actionable(self) -> "PluginJudgement":
        if self.verdict is not PluginVerdict.ABSTAIN and not self.findings:
            raise ValueError(f"a {self.verdict.name} judgement requires at least one finding")
        return self
