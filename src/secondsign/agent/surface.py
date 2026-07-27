# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The request an agent makes, and the answer it reads.

Both models are frozen and closed, and both carry only what the boundary already
allows: closed enums, integer minor units, and opaque fingerprints. Nothing here
is a channel — there is no free-text field an agent could use to pass an
instruction through to a reviewer, which is the leak the financial threat model
calls A5.

The outcome deliberately carries *less* than the control plane knows. An agent
learns whether it may proceed, an opaque reference for the decision, and closed
reason codes it can branch on. It does not learn which limit it hit, what the
limit is, who the approvers are, or what the audit record says: a denial that
explains the boundary precisely is a denial that teaches an agent how to shape
the next request to miss it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from secondsign.contracts import (
    ActionClass,
    Currency,
    Fingerprint,
    RailClass,
    ReasonCode,
    Reversibility,
)


class AgentOutcomeStatus(StrEnum):
    """What an agent is told. Three states, and no fourth for uncertainty.

    Uncertainty is not a state here. An action whose authorization could not be
    established reads as ``refused``, because an agent that can distinguish "no"
    from "we could not tell" can retry against the second one (INV-1).
    """

    #: Authorized and executed. The only status under which value has moved.
    completed = "completed"
    #: Not authorized. Covers denial, expiry, unavailability and error alike.
    refused = "refused"
    #: A human must decide. Nothing has moved, and nothing is reserved.
    awaiting_review = "awaiting_review"


class AuthorizationRequest(BaseModel):
    """An agent's proposal that value should move.

    A proposal, not an instruction — naming it this way in the type is the point.
    The agent supplies what it legitimately knows: the shape of the action, the
    amount, and opaque handles for the parties. It supplies no credential and no
    approval, because it holds neither.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ActionClass
    rail: RailClass
    currency: Currency
    #: Integer minor units. Money is never a float on this boundary.
    amount_minor: int = Field(ge=0)
    reversibility: Reversibility
    #: Opaque handles. The agent cannot mint these: fingerprinting requires the
    #: key, and the key is control plane.
    counterparty_ref: Fingerprint
    source_account_ref: Fingerprint
    #: The agent's own idempotency handle, so a retried request is recognisable
    #: as the same proposal. Not the gateway's reservation key, which the agent
    #: never sees.
    request_ref: Fingerprint


class AuthorizationOutcome(BaseModel):
    """What the agent reads back. Deliberately narrower than what core knows."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: AgentOutcomeStatus
    #: Opaque reference for support and reconciliation. Carries no rail
    #: identifier, so quoting it to a human leaks nothing about the account.
    decision_ref: Fingerprint
    decided_at: datetime
    #: Closed vocabulary the agent may branch on. Never free text, and never the
    #: threshold that was crossed.
    reasons: tuple[ReasonCode, ...] = ()


class SecondSignClient(Protocol):
    """The only verb an agent has: ask, and read the answer.

    A protocol rather than a class because the transport is the deployment's
    choice — an in-process call for development, a request to the standalone
    gateway process in production (CORE-S019). What must not vary is the shape:
    one method, taking a proposal and returning an outcome, with no parameter
    through which an agent could pass an approval, a credential or a setting.
    """

    def request_authorization(self, request: AuthorizationRequest) -> AuthorizationOutcome: ...
