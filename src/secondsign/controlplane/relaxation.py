# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Loosening a control-plane setting requires authority, not a value (INV-12).

The isolation guarantee is worth exactly as much as what a configuration value
can undo. So SecondSign has no settings in the usual sense. Every control-plane
setting has a *strictest default*, and any value looser than it resolves back to
the default unless a matching, unexpired, approved record says otherwise.

The shape is deliberately the same as the approval model (B2): bound to one
thing, expiring, one authority named. That is not symmetry for its own sake — a
configuration change on the control plane is an authorization decision, and
giving it a different shape is how it ends up with weaker rules.

**A record with no expiry counts as expired.** This is the awkward case and it is
intentional. "No expiry" is the shape every temporary exception takes on its way
to becoming permanent, and an exception nobody has to renew is a control-plane
change nobody reviews a second time. Refusing it costs an operator one renewal
and removes an entire class of silent drift.

**Tightening needs no authority.** Only loosening does. A caller asking for a
value stricter than the default gets it — a control that made itself harder to
strengthen would be obeyed less, not more.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


class Setting(StrEnum):
    """Control-plane settings that have a strictest default.

    A closed vocabulary, like every other boundary enum here: a setting that is
    not on this list cannot be relaxed, because it cannot be named.
    """

    #: How long a pending approval stays valid before it must be re-obtained.
    approval_ttl_seconds = "approval_ttl_seconds"
    #: How far back the sliding-window aggregate looks when measuring activity.
    window_lookback_seconds = "window_lookback_seconds"
    #: How many times a rail dispatch may be retried after an unknown outcome.
    rail_retry_attempts = "rail_retry_attempts"


#: The strictest value each setting can hold. Resolution returns one of these
#: whenever authority is missing, so these are the values the system runs on when
#: anything at all is wrong — which is the definition of a fail-closed default.
_STRICTEST: Final[dict[Setting, int]] = {
    # Short enough that an approval cannot outlive the context it was given in.
    Setting.approval_ttl_seconds: 300,
    # A short window is stricter: less past activity is forgotten, so the
    # aggregate that limits are measured against is larger, not smaller.
    Setting.window_lookback_seconds: 86_400,
    # Zero retries. An unknown outcome resolves by reconciliation, never by
    # sending again and hoping the first one did not land.
    Setting.rail_retry_attempts: 0,
}


class Relaxation(BaseModel):
    """An approved permission to hold one setting looser than its default.

    Frozen and closed, because this record is the authority a relaxation cites:
    a mutable one could be widened after approval, which is the same defect
    digest-bound approval exists to prevent on the transaction path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    setting: Setting
    #: The single value approved. A ceiling, not a licence to loosen further.
    relaxed_to: int = Field(ge=0)
    #: Fingerprint or opaque handle for the approving checker. Never a name or
    #: an email — this record reaches the audit trail (INV-11).
    approver_ref: str = Field(min_length=1)
    approved_at: datetime
    #: ``None`` counts as expired. See this module's docstring.
    expires_at: datetime | None = None

    def authorises(self, setting: Setting, value: int, now: datetime) -> bool:
        """True only if this record permits exactly ``value`` for ``setting`` now."""
        if self.setting is not setting:
            return False
        if self.expires_at is None or now >= self.expires_at:
            return False
        return value <= self.relaxed_to


class RelaxationDecision(BaseModel):
    """The resolved value, and what authorised it.

    Returned instead of a bare integer so that a relaxation is always
    attributable. An unattributable loosening is indistinguishable from a bypass,
    and the audit trail cannot record the difference after the fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    setting: Setting
    value: int = Field(ge=0)
    #: True only when the resolved value is looser than the strictest default.
    relaxed: bool = False
    #: The record that authorised it, or ``None`` when nothing was loosened.
    authority: Relaxation | None = None


def strictest(setting: Setting) -> int:
    """The value ``setting`` falls back to whenever authority is absent."""
    return _STRICTEST[setting]


def is_looser(setting: Setting, value: int) -> bool:
    """Whether ``value`` is weaker than ``setting``'s strictest default.

    Public because the direction is part of the contract and is *not* guessable
    from the number: a *longer* TTL is looser, and a *shorter* lookback window is
    looser, because forgetting more past activity makes the aggregate a limit is
    measured against smaller. A caller — or a test — that assumes "bigger is
    looser" is wrong for half of these settings.
    """
    if setting is Setting.window_lookback_seconds:
        return value < _STRICTEST[setting]
    return value > _STRICTEST[setting]


def resolve(
    setting: Setting,
    *,
    requested: int,
    records: tuple[Relaxation, ...],
    now: datetime,
) -> RelaxationDecision:
    """Resolve ``setting``, falling back to strictest unless authority permits.

    Never raises on a missing, expired or mismatched record: an exception would
    have to be handled by a caller, and a caller handling it is a caller that can
    handle it wrongly. The strict value is always a valid answer, so returning it
    is safer than making the failure someone else's decision.
    """
    if not is_looser(setting, requested):
        # Tightening, or asking for the default. No authority needed.
        return RelaxationDecision(setting=setting, value=requested)

    permitting = [record for record in records if record.authorises(setting, requested, now)]
    if not permitting:
        return RelaxationDecision(setting=setting, value=strictest(setting))

    # The narrowest sufficient record, so a broad old exception does not outrank a
    # narrow deliberate one and the decision names the authority actually relied
    # on. Ties break on the approver handle to keep resolution deterministic.
    authority = min(permitting, key=lambda record: (record.relaxed_to, record.approver_ref))
    return RelaxationDecision(setting=setting, value=requested, relaxed=True, authority=authority)
