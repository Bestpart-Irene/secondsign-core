# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The fingerprint key — INV-12's fifth asset, and the one with no second line
of defence.

A digest can be re-derived, a limit can be re-imposed, an approval can be
revoked. A leaked fingerprint key cannot be un-leaked: every reference that
deployment ever emitted becomes checkable against a guess, forever, and the
references are the whole of what makes the audit trail safe to hold.

So the cases here are about the ways a key escapes without anybody deciding to
release it — a repr in a traceback, a str in a log line — and about the property
that makes the fingerprint worth having at all.
"""

from __future__ import annotations

import pytest

from secondsign.contracts import FINGERPRINT_PATTERN
from secondsign.controlplane.fingerprint import (
    DECISION_DOMAIN,
    KEY_BYTES,
    PRINCIPAL_DOMAIN,
    FingerprintKey,
)

SECRET = b"k" * KEY_BYTES
PRINCIPAL = "spiffe://secondsign.example/agent/reference"


class TestTheKeyDoesNotRender:
    """Every one of these is a real path a secret takes out of a process."""

    def test_repr_says_nothing(self) -> None:
        assert repr(FingerprintKey(SECRET)) == "FingerprintKey(<redacted>)"

    def test_str_says_nothing(self) -> None:
        assert "k" * 8 not in str(FingerprintKey(SECRET))

    def test_an_f_string_says_nothing(self) -> None:
        """The most common accidental disclosure in the language."""
        assert "kkkk" not in f"{FingerprintKey(SECRET)}"

    def test_there_is_no_attribute_holding_it_in_the_open(self) -> None:
        """`__slots__` means no `__dict__`, so no `vars()` and no accidental
        serialisation by a library that walks instance attributes."""
        with pytest.raises(TypeError):
            vars(FingerprintKey(SECRET))


class TestTheKeyIsWorthHaving:
    def test_a_short_key_is_refused_rather_than_padded(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            FingerprintKey(b"too short")

    def test_generate_produces_a_usable_key(self) -> None:
        assert FingerprintKey.generate().fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL)

    def test_two_generated_keys_differ(self) -> None:
        a = FingerprintKey.generate().fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL)
        b = FingerprintKey.generate().fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL)

        assert a != b, "a reference must be meaningless outside its own deployment"

    def test_the_shape_is_what_a_reference_field_accepts(self) -> None:
        import re

        value = FingerprintKey(SECRET).fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL)

        assert re.match(FINGERPRINT_PATTERN, value)

    def test_the_same_value_fingerprints_stably(self) -> None:
        key = FingerprintKey(SECRET)

        assert key.fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL) == key.fingerprint(
            PRINCIPAL_DOMAIN, PRINCIPAL
        )

    def test_domains_do_not_share_a_fingerprint(self) -> None:
        """A principal and a decision that happen to be the same string must not
        fingerprint alike, or a reference an agent already holds could be used
        to confirm a workload identity it is guessing at."""
        key = FingerprintKey(SECRET)
        shared = "abc"

        assert key.fingerprint(PRINCIPAL_DOMAIN, shared) != key.fingerprint(DECISION_DOMAIN, shared)

    def test_the_domain_separator_cannot_be_faked_from_the_value(self) -> None:
        """Concatenation without a separator is the classic way two distinct
        inputs collide: ("ab", "c") and ("a", "bc") must not hash alike."""
        key = FingerprintKey(SECRET)

        assert key.fingerprint("ab", "c") != key.fingerprint("a", "bc")

    def test_the_raw_value_is_not_recoverable_from_the_fingerprint(self) -> None:
        value = FingerprintKey(SECRET).fingerprint(PRINCIPAL_DOMAIN, PRINCIPAL)

        assert PRINCIPAL not in value
        assert "secondsign.example" not in value
