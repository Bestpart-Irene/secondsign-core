# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The rail-adapter contract — the boundary where a tool call becomes an intent.

The reference implementation's largest defect was that the decision layer and
the calling layer were never connected, so the financial rules never fired. The
adapter is a first-class component, not an afterthought: it is where an agent's
tool call is turned into an immutable :class:`~secondsign.intent.TransactionIntent`,
and where three structural guarantees are established.

- **No raw identifier can enter** (A5). A call carries references only as keyed
  fingerprints; the adapter has no channel to write a raw account number into an
  intent, because the intent has no field that would hold one.
- **The idempotency key is derived, never accepted** (B2). It is computed from
  the call's content, so a caller cannot choose it — a chosen key is how a
  replay is disguised as a fresh action. The call type has no key field to set.
- **Source trust is only ever downgraded** (B9). The adapter may lower the
  declared provenance of an instruction, never raise it.

Adapters are rail-specific by design: a new rail is a new call type and a new
adapter, and the decision layer does not change to accept it (INV-8). What they
share is the redacted metadata below and the obligation to satisfy
:class:`~secondsign.conformance.RailAdapterConformance`.
"""

from enum import StrEnum
from typing import Protocol, TypeVar

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from secondsign.contracts import Fingerprint, RailClass, SourceTrust
from secondsign.intent import TransactionIntent


class ToolCall(BaseModel):
    """The redacted metadata every rail's tool call carries.

    A concrete rail extends this with its own value and payload fields. The
    references are already fingerprints: the adapter cannot fingerprint a raw
    value itself, because it never holds the fingerprint key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    counterparty_ref: Fingerprint
    source_account_ref: Fingerprint
    not_before: AwareDatetime
    not_after: AwareDatetime
    #: The provenance the calling chain claims. The adapter may only downgrade
    #: it; it can never be raised.
    declared_source_trust: SourceTrust
    scope_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _window_is_ordered(self) -> "ToolCall":
        # Rejected at construction so a well-formed call never makes `derive`
        # raise on the same window the intent would also reject.
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class RejectCode(StrEnum):
    """Why a call did not become an intent. A closed set — no free-form reason."""

    unsupported_action = "unsupported_action"
    unsupported_currency = "unsupported_currency"
    malformed_call = "malformed_call"
    outside_supported_limits = "outside_supported_limits"
    market_closed = "market_closed"
    stale_quote = "stale_quote"


class RejectReason(BaseModel):
    """A rejected derivation. Fail-closed: the adapter returns this, never a
    degraded intent, when it cannot map a call faithfully (A4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: RejectCode


#: Ordering of provenance, least to most trusted, taken from the enum's own
#: declaration order. Used only to check the no-upgrade direction (B9); how
#: mixed provenance combines is a policy concern, not the adapter's.
_TRUST_ORDER: tuple[SourceTrust, ...] = tuple(SourceTrust)


def trust_rank(trust: SourceTrust) -> int:
    """A total rank over provenance. Higher is more trusted."""
    return _TRUST_ORDER.index(trust)


CallT = TypeVar("CallT", bound=ToolCall, contravariant=True)


class RailAdapter(Protocol[CallT]):
    """A rail's mapping from its tool call to a TransactionIntent.

    Structural, not inherited: an adapter conforms by shape. It must expose the
    rail class it serves and a total ``derive`` that returns either an intent or
    a :class:`RejectReason` — never raises for a well-formed call, never returns
    a degraded intent for one it cannot map.
    """

    rail_class: RailClass

    def derive(self, call: CallT) -> TransactionIntent | RejectReason: ...
