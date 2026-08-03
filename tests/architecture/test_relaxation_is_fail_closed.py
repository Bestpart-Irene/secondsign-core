# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""INV-12, third property — a setting cannot be loosened by setting it.

The isolation guarantee is only as strong as what a configuration value can undo.
So SecondSign has no settings in the ordinary sense: every control-plane setting
has a strictest default, and reaching anything looser requires a matching,
unexpired, approved record in the control-plane ledger. Absent that record,
resolution returns the strictest value.

The awkward case is deliberate. **A record with no expiry counts as expired**,
because "no expiry" is the shape every temporary exception takes on its way to
becoming permanent — and a control-plane exception nobody has to renew is a
control-plane change nobody reviews again.

These tests live with the architecture suite rather than with unit tests because
what they enforce is the invariant, not the function: the interesting assertions
are the ones about what *cannot* happen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from secondsign.controlplane.relaxation import (
    Relaxation,
    RelaxationDecision,
    Resolution,
    Setting,
    is_looser,
    resolve,
    strictest,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def _approved(
    setting: Setting,
    *,
    value: int,
    expires_at: datetime | None,
    approver: str = "checker-1",
) -> Relaxation:
    return Relaxation(
        setting=setting,
        relaxed_to=value,
        approver_ref=approver,
        approved_at=NOW - timedelta(hours=1),
        expires_at=expires_at,
    )


# --------------------------------------------------------------------------
# The default direction.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("setting", list(Setting))
def test_every_setting_has_a_strictest_default(setting):
    """A setting with no strictest value has nothing to fall back to."""
    assert strictest(setting) is not None


def _looser_than_default(setting: Setting) -> int:
    """A value weaker than the default, in this setting's own direction.

    The direction is asked rather than assumed. An earlier version of this file
    used a large number for every setting and passed a *stricter* value to the
    inverted one, so two tests asserted the opposite of what they claimed.
    """
    default = strictest(setting)
    candidate = default // 2 if is_looser(setting, default - 1) else default * 2 + 1
    assert is_looser(setting, candidate), f"{candidate} is not looser for {setting}"
    return candidate


@pytest.mark.parametrize("setting", list(Setting))
def test_no_records_resolves_to_strictest(setting):
    decision = resolve(setting, requested=_looser_than_default(setting), records=(), now=NOW)
    assert decision.value == strictest(setting)
    assert not decision.relaxed


@pytest.mark.parametrize("setting", list(Setting))
def test_a_request_at_the_default_needs_no_authority(setting):
    decision = resolve(setting, requested=strictest(setting), records=(), now=NOW)
    assert decision.value == strictest(setting)
    assert not decision.relaxed


@pytest.mark.parametrize("setting", list(Setting))
def test_a_request_stricter_than_the_default_is_honoured(setting):
    """Tightening needs no approval. Only loosening does."""
    default = strictest(setting)
    tighter = default + 1 if is_looser(setting, default - 1) else default - 1
    if tighter < 0:
        pytest.skip(f"{setting} is already at its strictest possible value")
    assert not is_looser(setting, tighter)
    decision = resolve(setting, requested=tighter, records=(), now=NOW)
    assert decision.value == tighter
    assert not decision.relaxed


# --------------------------------------------------------------------------
# What it takes to loosen.
# --------------------------------------------------------------------------


def test_a_matching_unexpired_record_permits_exactly_what_it_approved():
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert decision.value == 900
    assert decision.relaxed
    assert decision.authority is record


def test_a_record_does_not_permit_more_than_it_approved():
    """The record is the ceiling, not a licence to loosen further."""
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(setting, requested=3600, records=(record,), now=NOW)
    assert decision.value == strictest(setting)
    assert not decision.relaxed


def test_a_record_for_another_setting_does_not_transfer():
    record = _approved(Setting.approval_ttl_seconds, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(Setting.window_lookback_seconds, requested=900, records=(record,), now=NOW)
    assert decision.value == strictest(Setting.window_lookback_seconds)
    assert not decision.relaxed


# --------------------------------------------------------------------------
# Every way a record fails to authorise anything.
# --------------------------------------------------------------------------


def test_an_expired_record_authorises_nothing():
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW - timedelta(seconds=1))
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert decision.value == strictest(setting)
    assert not decision.relaxed


def test_a_record_expiring_exactly_now_authorises_nothing():
    """The boundary resolves strict. An exception is over the instant it is over."""
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW)
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert not decision.relaxed


def test_a_record_with_no_expiry_counts_as_expired():
    """The named case. A permanent exception is not an exception."""
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=None)
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert decision.value == strictest(setting), (
        "a record with no expiry loosened a setting — that is how a temporary "
        "exception becomes permanent"
    )
    assert not decision.relaxed


def test_a_record_cannot_be_constructed_without_an_approver():
    with pytest.raises(ValidationError):
        Relaxation(
            setting=Setting.approval_ttl_seconds,
            relaxed_to=900,
            approver_ref="",
            approved_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )


def test_the_strictest_default_cannot_be_loosened_by_a_record_alone():
    """A record is permission for a request, not a new default.

    Nothing about holding an approved record changes what an unasked-for
    resolution returns — otherwise one approval silently re-bases the system.
    """
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(setting, requested=strictest(setting), records=(record,), now=NOW)
    assert decision.value == strictest(setting)
    assert not decision.relaxed


# --------------------------------------------------------------------------
# The decision is itself a record, not a bare value.
# --------------------------------------------------------------------------


def test_a_relaxed_decision_names_the_record_that_authorised_it():
    """An unattributable relaxation is indistinguishable from a bypass."""
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert decision.relaxed and decision.authority is not None


def test_a_strict_decision_names_no_authority():
    decision = resolve(Setting.approval_ttl_seconds, requested=900, records=(), now=NOW)
    assert decision.authority is None


def test_the_decision_is_immutable():
    decision = resolve(Setting.approval_ttl_seconds, requested=900, records=(), now=NOW)
    with pytest.raises(ValidationError):
        decision.value = 999_999  # type: ignore[misc]


def test_resolution_is_deterministic():
    setting = Setting.approval_ttl_seconds
    records = (
        _approved(setting, value=900, expires_at=NOW + timedelta(days=1), approver="checker-a"),
        _approved(setting, value=1800, expires_at=NOW + timedelta(days=1), approver="checker-b"),
    )
    first = resolve(setting, requested=900, records=records, now=NOW)
    second = resolve(setting, requested=900, records=tuple(reversed(records)), now=NOW)
    assert first.value == second.value
    assert first.relaxed == second.relaxed


def test_the_narrowest_sufficient_record_is_the_one_used():
    """With several records that would do, the least permissive is chosen.

    Otherwise a broad old exception outranks a narrow deliberate one, and the
    audit trail names the wrong authority.
    """
    setting = Setting.approval_ttl_seconds
    broad = _approved(setting, value=3600, expires_at=NOW + timedelta(days=1), approver="broad")
    narrow = _approved(setting, value=900, expires_at=NOW + timedelta(days=1), approver="narrow")
    decision = resolve(setting, requested=900, records=(broad, narrow), now=NOW)
    assert decision.authority is not None
    assert decision.authority.approver_ref == "narrow"


def test_a_relaxation_decision_carries_no_free_text():
    """INV-3 applies here too: this record reaches the audit trail."""
    for field in RelaxationDecision.model_fields:
        assert "reason" not in field and "note" not in field and "message" not in field


# --------------------------------------------------------------------------
# Failing closed is not enough on its own — the refusal has to be visible.
# --------------------------------------------------------------------------


def test_a_lapsed_exception_is_distinguishable_from_never_having_had_one():
    """The defect this section exists for.

    An earlier version returned the same shape whether nobody had asked for a
    relaxation or a legitimate one had silently expired. Both fell back to
    strictest, which is the right value — and nobody was told the exception had
    lapsed. Failing closed without a signal is drift in the safer direction, and
    it is the same objection INV-1 answers with an operator-visible state rather
    than with silence.
    """
    setting = Setting.approval_ttl_seconds
    lapsed = _approved(setting, value=900, expires_at=NOW - timedelta(days=1))

    expired = resolve(setting, requested=900, records=(lapsed,), now=NOW)
    never_had = resolve(setting, requested=900, records=(), now=NOW)

    assert expired.value == never_had.value == strictest(setting)
    assert expired.refused and never_had.refused
    assert expired.resolution is Resolution.refused_expired
    assert never_had.resolution is Resolution.refused_no_record
    assert expired.resolution is not never_had.resolution, (
        "an operator cannot tell a lapsed exception from one that never existed"
    )


def test_a_record_with_no_expiry_reads_as_expired_not_as_missing():
    """The never-renewed exception is the lapsed case, not the absent one.

    It is the one an operator is most likely to have believed was working.
    """
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=None)
    decision = resolve(setting, requested=900, records=(record,), now=NOW)
    assert decision.resolution is Resolution.refused_expired


def test_asking_for_more_than_approved_is_its_own_refusal():
    """Distinct because the action is different: widen, not renew."""
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    decision = resolve(setting, requested=3600, records=(record,), now=NOW)
    assert decision.resolution is Resolution.refused_insufficient
    assert decision.value == strictest(setting)


def test_a_live_narrow_record_outranks_an_expired_broad_one_in_the_reason():
    """With both present, the reported reason is the one nearer to authority."""
    setting = Setting.approval_ttl_seconds
    decision = resolve(
        setting,
        requested=3600,
        records=(
            _approved(setting, value=7200, expires_at=NOW - timedelta(days=1), approver="old"),
            _approved(setting, value=900, expires_at=NOW + timedelta(days=1), approver="live"),
        ),
        now=NOW,
    )
    assert decision.resolution is Resolution.refused_insufficient


def test_a_record_for_another_setting_does_not_colour_the_reason():
    """A live record elsewhere must not make this setting look nearly-authorised."""
    other = _approved(
        Setting.window_lookback_seconds, value=900, expires_at=NOW + timedelta(days=1)
    )
    decision = resolve(Setting.approval_ttl_seconds, requested=3600, records=(other,), now=NOW)
    assert decision.resolution is Resolution.refused_no_record


def test_not_asking_is_never_reported_as_a_refusal():
    """Silence stays silent when nothing was sought — no false operator signal."""
    for setting in Setting:
        decision = resolve(setting, requested=strictest(setting), records=(), now=NOW)
        assert decision.resolution is Resolution.as_requested
        assert not decision.refused and not decision.relaxed


def test_relaxed_and_refused_are_never_both_true():
    setting = Setting.approval_ttl_seconds
    record = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    for requested in (strictest(setting), 900, 3600):
        decision = resolve(setting, requested=requested, records=(record,), now=NOW)
        assert not (decision.relaxed and decision.refused)


@pytest.mark.parametrize("resolution", list(Resolution))
def test_every_resolution_is_reachable(resolution):
    """A member no input can produce is a vocabulary that lies about the states."""
    setting = Setting.approval_ttl_seconds
    live = _approved(setting, value=900, expires_at=NOW + timedelta(days=1))
    dead = _approved(setting, value=900, expires_at=NOW - timedelta(days=1))
    produced = {
        resolve(setting, requested=strictest(setting), records=(), now=NOW).resolution,
        resolve(setting, requested=900, records=(live,), now=NOW).resolution,
        resolve(setting, requested=900, records=(), now=NOW).resolution,
        resolve(setting, requested=900, records=(dead,), now=NOW).resolution,
        resolve(setting, requested=3600, records=(live,), now=NOW).resolution,
    }
    assert resolution in produced, f"{resolution} cannot be produced by any input"


# --------------------------------------------------------------------------
# Direction-aware authority: a record is a ceiling on looseness in the
# setting's own direction, not a bigger-is-looser threshold.
# --------------------------------------------------------------------------


def test_a_lookback_record_does_not_authorise_a_far_looser_window():
    """The inverted-direction trap. `window_lookback_seconds` is looser the
    *smaller* it is, so a record approving a shortening to 12h (43_200) must not
    green-light a shortening to 60 seconds — which forgets almost all history
    and is far looser than what was approved. The old `value <= relaxed_to`
    reading let it through (`60 <= 43_200`)."""
    setting = Setting.window_lookback_seconds
    record = _approved(setting, value=43_200, expires_at=NOW + timedelta(hours=1))

    decision = resolve(setting, requested=60, records=(record,), now=NOW)

    assert decision.value == strictest(setting), (
        "a lookback record authorised a window far looser than it approved"
    )
    assert decision.refused
    assert decision.authority is None


def test_a_lookback_record_authorises_exactly_what_it_approved():
    setting = Setting.window_lookback_seconds
    record = _approved(setting, value=43_200, expires_at=NOW + timedelta(hours=1))

    decision = resolve(setting, requested=43_200, records=(record,), now=NOW)

    assert decision.relaxed
    assert decision.value == 43_200


def test_a_lookback_record_authorises_a_less_loose_request_within_its_ceiling():
    """A request looser than the default but tighter than what was approved is
    within the ceiling — 50_000 is between the approved 43_200 and the strictest
    86_400, i.e. less loose than approved."""
    setting = Setting.window_lookback_seconds
    record = _approved(setting, value=43_200, expires_at=NOW + timedelta(hours=1))

    decision = resolve(setting, requested=50_000, records=(record,), now=NOW)

    assert decision.relaxed
    assert decision.value == 50_000


def test_the_narrowest_lookback_record_is_named_as_authority():
    """The selected authority is the *least loose* sufficient record. For
    lookback that is the one with the largest relaxed_to, not the smallest."""
    setting = Setting.window_lookback_seconds
    broad = _approved(setting, value=30_000, expires_at=NOW + timedelta(hours=1), approver="broad")
    narrow = _approved(
        setting, value=60_000, expires_at=NOW + timedelta(hours=1), approver="narrow"
    )

    decision = resolve(setting, requested=70_000, records=(broad, narrow), now=NOW)

    assert decision.relaxed
    assert decision.authority is not None
    assert decision.authority.approver_ref == "narrow", (
        "the loosest record was named authority instead of the narrowest sufficient one"
    )
