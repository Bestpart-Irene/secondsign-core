# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The wire contract, version 1: what crosses between an agent and its gateway.

This module deliberately re-declares vocabulary that also exists in
`secondsign-core`. It has to: the client depends on pydantic and nothing else
(ADR 0003 §1), so it cannot import core's definitions, and core cannot depend on
this package. Two declarations of one dialect can drift, which is why the core
repository — the one place both are visible — holds them equal member-for-member
in `tests/client/test_wire_contract.py`. Editing an enum here without its twin
fails CI there.

`WIRE_VERSION` is independent of core's `CONTRACT_VERSION` on purpose. The
plugin contract and the wire contract change for different reasons at different
times, and a peer announcing a version this module does not define is refused
rather than best-effort parsed: a peer speaking a different dialect may mean
something different by every word in it (ADR 0003 §3, mirroring ADR 0002).

The models are frozen and closed, and carry only what the boundary already
allows: closed enums, integer minor units, and opaque keyed fingerprints. There
is no field for a principal — identity comes from the TLS session, and a request
that carries its own is refused by the gateway rather than ignored (ADR 0004).
There is no field for free text either; a bounded text field is still a channel.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Version of this wire contract. Adding a field, a status, or an enum member is
#: a version change. Independent of core's plugin CONTRACT_VERSION.
WIRE_VERSION = 1

#: Keyed-fingerprint shape, identical to core's. Nothing else is accepted in a
#: reference field, so a PAN, IBAN or customer name is not representable rather
#: than merely discouraged.
FINGERPRINT_PATTERN = r"^fp:[0-9a-f]{64}$"

Fingerprint = Annotated[str, Field(pattern=FINGERPRINT_PATTERN)]


class AgentOutcomeStatus(StrEnum):
    """What an agent is told. Three states, and no fourth for uncertainty.

    An action whose authorization could not be established reads as
    ``refused``, because an agent that can distinguish "no" from "we could not
    tell" can retry against the second one (INV-1).
    """

    completed = "completed"
    refused = "refused"
    awaiting_review = "awaiting_review"


class ActionClass(StrEnum):
    payment = "payment"
    refund = "refund"
    payout = "payout"
    transfer = "transfer"
    trade = "trade"
    account_change = "account_change"


class RailClass(StrEnum):
    """The kind of rail, never the vendor."""

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


class ReasonCode(StrEnum):
    """Stable codes an agent may branch on. Never free text, and never the
    threshold that was crossed."""

    velocity_limit = "velocity_limit"
    counterparty_risk = "counterparty_risk"
    jurisdiction_restricted = "jurisdiction_restricted"
    market_session_closed = "market_session_closed"
    value_band_exceeded = "value_band_exceeded"
    new_counterparty = "new_counterparty"
    org_policy = "org_policy"
    plugin_error = "plugin_error"
    plugin_contract_mismatch = "plugin_contract_mismatch"
    plugin_invalid_result = "plugin_invalid_result"


class AuthorizationRequest(BaseModel):
    """An agent's proposal that value should move.

    A proposal, not an instruction. The agent supplies what it legitimately
    knows: the shape of the action, the amount, and opaque handles for the
    parties. It supplies no credential, no approval, and no identity — the
    gateway derives who is asking from the TLS session alone.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ActionClass
    rail: RailClass
    currency: Currency
    #: Integer minor units. Money is never a float on this boundary.
    amount_minor: int = Field(ge=0)
    reversibility: Reversibility
    counterparty_ref: Fingerprint
    source_account_ref: Fingerprint
    #: The agent's own idempotency handle, so a retried request is recognisable
    #: as the same proposal. The gateway namespaces it by the authenticated
    #: principal, so one workload cannot collide with another's (ADR 0004 §2).
    request_ref: Fingerprint


class AuthorizationOutcome(BaseModel):
    """What the agent reads back. Deliberately narrower than what core knows."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: AgentOutcomeStatus
    #: Opaque reference for support and reconciliation. Carries no rail
    #: identifier.
    decision_ref: Fingerprint
    decided_at: datetime
    #: Closed vocabulary. Never the limit that was hit.
    reasons: tuple[ReasonCode, ...] = ()


def _require_this_dialect(version: int) -> int:
    if version != WIRE_VERSION:
        raise ValueError(
            f"wire version {version!r} is not spoken here; this client speaks "
            f"{WIRE_VERSION} and refuses rather than guesses"
        )
    return version


class WireRequest(BaseModel):
    """The request envelope: the dialect announced, then the proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Strict: the string "1" is not the integer 1. Type coercion is
    #: best-effort parsing wearing a smaller costume.
    wire_version: int = Field(default=WIRE_VERSION, strict=True)
    request: AuthorizationRequest

    _version_spoken = field_validator("wire_version")(_require_this_dialect)


class WireResponse(BaseModel):
    """The response envelope. A version this module does not define fails
    validation, so an unrecognised dialect is unrepresentable, not tolerated."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    wire_version: int = Field(strict=True)
    outcome: AuthorizationOutcome

    _version_spoken = field_validator("wire_version")(_require_this_dialect)
