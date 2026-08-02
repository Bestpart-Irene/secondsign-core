# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""INV-10 — what a human approves, as a value that can be compared.

The intent digest binds execution to the decided value, and it covers the
validity window. A human cannot answer inside a five-minute window, so an
approval bound to that digest is an approval that can never be spent (ADR 0005).
The proposal digest is the same hash over the same intent, minus the window and
minus nothing else.

The two cases that carry the guarantee are the field-enumerating one and the
window-name one. The first says every field that is not the window changes the
digest, so a field added to `DecisionDimensions` next year is covered without
anyone remembering this file. The second says the excluded names exist, so
renaming `not_after` fails here rather than silently widening what a human is
deemed to have approved — a hash that quietly stops covering a field is the one
failure mode this design has, and it is invisible in every other test.
"""

from datetime import timedelta

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from secondsign.intent import (
    DecisionDimensions,
    IntentDigest,
    ProposalDigest,
    compute_digest,
    compute_proposal_digest,
)
from secondsign.intent.digest import PROPOSAL_DIGEST_VERSION, WINDOW_FIELDS
from tests.intent.conftest import make_dimensions, make_intent, make_payment

#: Every material field of an intent, and a different value for each. Written
#: out so the enumerating test can assert it is exhaustive against the models
#: themselves — a field added without a line here fails that assertion.
DIMENSION_CHANGES = {
    "value_lower_minor": 1,
    "value_upper_minor": 999_999,
    "quote_currency": "EUR",
    "counterparty_ref": "fp:" + "c3" * 32,
    "source_account_ref": "fp:" + "d4" * 32,
    "rail_class": "card",
    "reversibility": "reversible",
    "source_trust": "untrusted_data",
    "scope_count": 7,
}

PAYLOAD_CHANGES = {
    "target_kind": "card",
    "new_beneficiary": True,
    "cross_border": True,
    "settlement_priority": "express",
}


class _Approved(BaseModel):
    """A field that means "the human approved this"."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest: ProposalDigest


class _Executed(BaseModel):
    """A field that means "this is what was dispatched"."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest: IntentDigest


def test_the_proposal_digest_is_a_versioned_sha256(intent) -> None:
    digest = compute_proposal_digest(intent)

    assert digest.digest_version == PROPOSAL_DIGEST_VERSION
    assert len(digest.value) == 64
    assert int(digest.value, 16) >= 0


def test_the_proposal_digest_is_deterministic() -> None:
    assert compute_proposal_digest(make_intent()) == compute_proposal_digest(make_intent())


def test_the_window_is_the_only_thing_it_ignores(intent) -> None:
    """The whole point, stated once: move the window, keep the digest."""
    later = make_intent(
        dimensions=make_dimensions(
            not_before=intent.dimensions.not_before + timedelta(hours=6),
            not_after=intent.dimensions.not_after + timedelta(hours=6),
        )
    )

    assert compute_proposal_digest(later) == compute_proposal_digest(intent)
    assert compute_digest(later) != compute_digest(intent), (
        "the intent digest must still cover the window — execution binds to it"
    )


@pytest.mark.parametrize(("field", "value"), sorted(DIMENSION_CHANGES.items()))
def test_every_dimension_but_the_window_changes_the_proposal_digest(
    intent, field: str, value: object
) -> None:
    changed = make_intent(dimensions=make_dimensions(**{field: value}))

    assert compute_proposal_digest(changed) != compute_proposal_digest(intent), (
        f"{field} does not change the proposal digest, so a human approving one "
        f"value would have approved every other value of it"
    )


@pytest.mark.parametrize(("field", "value"), sorted(PAYLOAD_CHANGES.items()))
def test_every_payload_field_changes_the_proposal_digest(intent, field: str, value: object) -> None:
    changed = make_intent(payload=make_payment(**{field: value}))

    assert compute_proposal_digest(changed) != compute_proposal_digest(intent)


def test_the_idempotency_key_changes_the_proposal_digest(intent) -> None:
    changed = make_intent(idempotency_key="idem-1111111111111111")

    assert compute_proposal_digest(changed) != compute_proposal_digest(intent)


def test_the_enumerated_fields_are_exhaustive() -> None:
    """The parametrised cases above cover the model, not a snapshot of it.

    Without this, adding a field to `DecisionDimensions` leaves the enumeration
    silently short and the suite still green — which is exactly the state this
    file exists to make impossible.
    """
    covered = set(DIMENSION_CHANGES) | set(WINDOW_FIELDS)

    assert covered == set(DecisionDimensions.model_fields), (
        "DecisionDimensions has a field that is neither enumerated above nor "
        "declared as part of the validity window"
    )


def test_the_excluded_window_fields_exist_on_the_model() -> None:
    """A rename must fail here, not widen the approval in silence."""
    for field in WINDOW_FIELDS:
        assert field in DecisionDimensions.model_fields, (
            f"the proposal digest excludes {field!r}, which DecisionDimensions no "
            f"longer has — the exclusion now removes nothing and the name is a lie"
        )


def test_the_two_digests_of_one_intent_differ(intent) -> None:
    """Different questions, different answers, even over the same object."""
    assert compute_proposal_digest(intent).value != compute_digest(intent).value


def test_neither_digest_validates_where_the_other_is_expected(intent) -> None:
    """Two hex strings that mean different things must not be one type.

    A system with two digests and one type is a system with one digest and a
    call site waiting to confuse them.
    """
    proposal = compute_proposal_digest(intent)
    execution = compute_digest(intent)

    with pytest.raises(ValidationError):
        _Approved(digest=execution)
    with pytest.raises(ValidationError):
        _Executed(digest=proposal)


def test_the_proposal_digest_is_frozen(intent) -> None:
    digest = compute_proposal_digest(intent)

    with pytest.raises(ValidationError):
        digest.value = "0" * 64


def test_changing_the_algorithm_version_changes_the_proposal_digest(intent) -> None:
    assert compute_proposal_digest(intent, version=2) != compute_proposal_digest(intent)
