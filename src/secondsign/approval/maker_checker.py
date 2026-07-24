# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The digest-bound maker-checker flow.

A REVIEW decision does not proceed on its own — it is held for a second human,
the checker, distinct from the maker who requested it. The approval that results
is deliberately narrow:

- **bound to one digest** (B2): it authorises exactly the intent that was
  decided, nothing else — never an agent, a session, or an action type;
- **one-shot**: a successful consume burns it, so an approval cannot be replayed;
- **expiring, with a mandatory TTL** (B5): past the expiry it is dead, and a
  *missing* expiry is treated as already expired rather than as permanent;
- **separated** (B6): the checker's subject may not be the maker's.

The maker-checker holds only which approvals have been consumed. Presentation to
the human is a provider's job (see :mod:`secondsign.approval.provider`); the
verdict it returns is validated here before anything is granted.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from secondsign.approval.identities import CheckerIdentity, MakerIdentity
from secondsign.decision import Decision, DecisionVerdict
from secondsign.intent import IntentDigest


class RejectionReason(StrEnum):
    """Why a consume did not grant. A closed set."""

    digest_mismatch = "digest_mismatch"
    expired = "expired"
    already_consumed = "already_consumed"
    self_approval = "self_approval"
    not_approved = "not_approved"


class PendingApproval(BaseModel):
    """A review awaiting a checker. Carries the decision it binds to, so what is
    shown to the human is rendered from the same object that will execute (B3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(min_length=1)
    decision: Decision
    maker: MakerIdentity
    #: Absolute expiry. ``None`` is treated as already expired, never permanent.
    expires_at: AwareDatetime | None

    @property
    def digest(self) -> IntentDigest:
        return self.decision.digest


class CheckerVerdict(BaseModel):
    """A checker's response to a pending approval, bound to the digest shown."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    checker: CheckerIdentity
    digest: IntentDigest
    approved: bool


class Grant(BaseModel):
    """A consumed approval. Authorises exactly one digest, once."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(min_length=1)
    digest: IntentDigest
    checker: CheckerIdentity


class Rejected(BaseModel):
    """A consume that did not grant, and why."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: RejectionReason


class MakerChecker:
    """Issues review approvals and consumes them, one-shot and digest-bound."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def request(
        self,
        decision: Decision,
        maker: MakerIdentity,
        *,
        approval_id: str,
        expires_at: AwareDatetime | None,
    ) -> PendingApproval:
        if decision.verdict is not DecisionVerdict.REVIEW:
            # ALLOW needs no approval; a DENY cannot be approved into permission.
            raise ValueError("only a REVIEW decision can be sent for approval")
        return PendingApproval(
            approval_id=approval_id,
            decision=decision,
            maker=maker,
            expires_at=expires_at,
        )

    def consume(
        self, pending: PendingApproval, verdict: CheckerVerdict, *, now: datetime
    ) -> Grant | Rejected:
        # A burnt approval is dead first — checked before anything else so a
        # replay cannot even reach the other branches.
        if pending.approval_id in self._consumed:
            return Rejected(reason=RejectionReason.already_consumed)
        # Missing expiry is expired, not permanent.
        if pending.expires_at is None or now >= pending.expires_at:
            return Rejected(reason=RejectionReason.expired)
        if verdict.digest != pending.digest:
            return Rejected(reason=RejectionReason.digest_mismatch)
        if verdict.checker.subject == pending.maker.subject:
            return Rejected(reason=RejectionReason.self_approval)
        if not verdict.approved:
            return Rejected(reason=RejectionReason.not_approved)

        # Only a successful grant burns the one-shot; a rejected attempt leaves
        # it available for a correct consume.
        self._consumed.add(pending.approval_id)
        return Grant(
            approval_id=pending.approval_id, digest=pending.digest, checker=verdict.checker
        )
