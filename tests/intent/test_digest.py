# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The IntentDigest — the single value decision, approval and execution bind to.

Its whole job is to be a total, deterministic, versioned fingerprint of every
material field of an intent (B1, B2). If two runs of the same intent produced
different digests, an approval could not be re-verified before dispatch; if a
changed field produced the same digest, a decision could be bound to one value
and executed as another. Both are tested here as properties.
"""

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from secondsign.intent import DIGEST_VERSION, IntentDigest, compute_digest
from tests.intent.conftest import make_dimensions, make_intent, make_payment


def test_digest_is_a_versioned_sha256():
    d = compute_digest(make_intent())
    assert isinstance(d, IntentDigest)
    assert d.digest_version == DIGEST_VERSION
    assert len(d.value) == 64 and all(c in "0123456789abcdef" for c in d.value)


def test_digest_is_deterministic():
    """Two independently built but equal intents digest byte-identically."""
    assert compute_digest(make_intent()) == compute_digest(make_intent())


def test_changing_the_algorithm_version_changes_the_digest():
    intent = make_intent()
    assert compute_digest(intent, version=1).value != compute_digest(intent, version=2).value


def test_changing_a_dimension_changes_the_digest():
    base = compute_digest(make_intent()).value
    changed = compute_digest(
        make_intent(dimensions=make_dimensions(value_upper_minor=999_999))
    ).value
    assert base != changed


def test_changing_the_payload_changes_the_digest():
    base = compute_digest(make_intent()).value
    changed = compute_digest(make_intent(payload=make_payment(cross_border=True))).value
    assert base != changed


def test_changing_the_idempotency_key_changes_the_digest():
    base = compute_digest(make_intent()).value
    changed = compute_digest(make_intent(idempotency_key="idem-1111111111111111")).value
    assert base != changed


def test_digest_is_frozen():
    d = compute_digest(make_intent())
    with pytest.raises(ValidationError):
        d.value = "0" * 64


@given(
    lower=st.integers(min_value=0, max_value=10**9),
    span=st.integers(min_value=0, max_value=10**9),
    minutes=st.integers(min_value=1, max_value=1440),
    cross_border=st.booleans(),
    key=st.text(alphabet="0123456789abcdef", min_size=1, max_size=32),
)
def test_equal_intents_always_share_a_digest(lower, span, minutes, cross_border, key):
    """Determinism over the input space: same material fields, same digest, total."""
    now = make_dimensions().not_before

    def build():
        return make_intent(
            dimensions=make_dimensions(
                value_lower_minor=lower,
                value_upper_minor=lower + span,
                not_before=now,
                not_after=now + timedelta(minutes=minutes),
            ),
            payload=make_payment(cross_border=cross_border),
            idempotency_key=key,
        )

    assert compute_digest(build()) == compute_digest(build())
