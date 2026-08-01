# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Certifying the minimal client, and watching the kit catch the broken ones.

The certification is the subclass at the top: override ``attempt``, three
lines, nothing else about the client's API prescribed — what is certified is
the protocol, not an implementation of it. The inherited suite stands up its
own probe gateway and exercises both halves of the contract: what the client
sends, and what it does with well-formed, malformed, foreign-dialect and
absent answers.

The second half of this file runs the kit against the two deliberately
non-conformant clients and asserts the certification *fails*, quoting the
failure it reports. An example that only showed the happy path would teach the
wrong half — the kit's own acceptance criterion is the non-conformant
candidates it must catch.
"""

from __future__ import annotations

import pytest

from examples.wire_client.minimal_client import MinimalWireClient
from examples.wire_client.non_conformant import DialectBlindClient, OptimistClient
from secondsign.conformance import WireClientConformance


class TestMinimalWireClient(WireClientConformance):
    """The entire integration a third party performs."""

    def attempt(self, host: str, port: int, request: dict[str, object]) -> str:
        client = MinimalWireClient(host=host, port=port)
        return client.authorize(request)


class _DialectBlindCertification(WireClientConformance):
    def attempt(self, host: str, port: int, request: dict[str, object]) -> str:
        return DialectBlindClient(host=host, port=port).authorize(request)


class _OptimistCertification(WireClientConformance):
    def attempt(self, host: str, port: int, request: dict[str, object]) -> str:
        return OptimistClient(host=host, port=port).authorize(request)


def test_the_kit_catches_a_client_that_ignores_the_dialect() -> None:
    """A response announcing an unspoken wire version must read as refused;
    the dialect-blind client parses it anyway, and the kit says so."""
    certification = _DialectBlindCertification()
    with pytest.raises(AssertionError, match="wire version"):
        certification.test_a_foreign_dialect_is_refused_rather_than_parsed()


def test_the_kit_catches_a_client_that_treats_garbage_as_success() -> None:
    """An HTML error page must read as refused; the optimist reports a
    completed payment, and the kit says so."""
    certification = _OptimistCertification()
    with pytest.raises(AssertionError, match="unparseable"):
        certification.test_an_unparseable_answer_is_refused()


def test_the_broken_clients_still_pass_the_happy_path() -> None:
    """Why the malformed-answer cases exist at all: on a well-formed answer
    the broken clients are indistinguishable from the conformant one. A kit
    that only exercised the happy path would certify all three."""
    for certification in (_DialectBlindCertification(), _OptimistCertification()):
        certification.test_relays_the_gateway_answer_unchanged()
