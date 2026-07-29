# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The wire contract: one dialect, versioned on its own, closed on both sides.

The client cannot import core and core cannot depend on the client, so the
vocabulary each speaks is declared twice by design. Twice-declared means it can
drift, and drift on a security boundary is not a style problem — a peer speaking
a different dialect may mean something different by `refused` (ADR 0002's
argument, applied to the wire in ADR 0003 §3). This repository is the one place
both declarations are visible, so this is where they are held equal.

`WIRE_VERSION` is deliberately independent of `CONTRACT_VERSION`. The plugin
contract and the wire contract version for different reasons at different
times: adding a policy enum member revs the first, adding a transport field
revs the second, and coupling them would force a release of one surface to
announce a change in the other.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from secondsign_client import wire

from secondsign import contracts as core_contracts
from secondsign.agent import surface as core_agent
from secondsign.gateway.server import SUPPORTED_WIRE_VERSIONS

FINGERPRINT = "fp:" + "ab" * 32


def make_wire_request(**overrides):
    fields = {
        "action": wire.ActionClass.payment,
        "rail": wire.RailClass.card,
        "currency": wire.Currency.USD,
        "amount_minor": 5_000,
        "reversibility": wire.Reversibility.irreversible,
        "counterparty_ref": FINGERPRINT,
        "source_account_ref": FINGERPRINT,
        "request_ref": FINGERPRINT,
    }
    fields.update(overrides)
    return wire.AuthorizationRequest(**fields)


class TestTheMirrorsHoldEqual:
    """Every enum the wire carries, member-for-member against core's."""

    @pytest.mark.parametrize(
        ("client_enum", "core_enum"),
        [
            (wire.ActionClass, core_contracts.ActionClass),
            (wire.RailClass, core_contracts.RailClass),
            (wire.Currency, core_contracts.Currency),
            (wire.Reversibility, core_contracts.Reversibility),
            (wire.ReasonCode, core_contracts.ReasonCode),
            (wire.AgentOutcomeStatus, core_agent.AgentOutcomeStatus),
        ],
    )
    def test_member_maps_are_identical(self, client_enum, core_enum) -> None:
        client_members = {member.name: member.value for member in client_enum}
        core_members = {member.name: member.value for member in core_enum}

        assert client_members == core_members, (
            f"{client_enum.__name__} has drifted from core's {core_enum.__name__}; "
            "the wire speaks one dialect or none"
        )

    def test_the_fingerprint_pattern_is_the_same_shape(self) -> None:
        assert wire.FINGERPRINT_PATTERN == core_contracts.FINGERPRINT_PATTERN

    def test_the_request_mirrors_the_agent_surface_field_for_field(self) -> None:
        assert set(wire.AuthorizationRequest.model_fields) == set(
            core_agent.AuthorizationRequest.model_fields
        )

    def test_the_outcome_mirrors_the_agent_surface_field_for_field(self) -> None:
        assert set(wire.AuthorizationOutcome.model_fields) == set(
            core_agent.AuthorizationOutcome.model_fields
        )


class TestTheVersionIsItsOwn:
    def test_wire_version_is_one(self) -> None:
        assert wire.WIRE_VERSION == 1

    def test_the_gateway_speaks_the_dialect_the_client_announces(self) -> None:
        """Both sides declare the version independently — neither may import
        the other — so this repository, the one place both are visible, holds
        the declarations equal."""
        assert wire.WIRE_VERSION in SUPPORTED_WIRE_VERSIONS

    def test_independence_from_the_plugin_contract_is_structural(self) -> None:
        """`WIRE_VERSION` cannot be derived from `CONTRACT_VERSION`, because no
        client module imports core at all — asserted over the AST in
        `test_distribution.py`. What is asserted here is merely that both
        constants exist as their own integers, so a refactor that deleted one
        in favour of the other fails loudly."""
        assert isinstance(wire.WIRE_VERSION, int)
        assert isinstance(core_contracts.CONTRACT_VERSION, int)

    def test_a_request_envelope_refuses_a_foreign_version_too(self) -> None:
        """Refusal is symmetric: the client will not *send* a dialect it does
        not speak any more than it will parse one."""
        with pytest.raises(ValidationError):
            wire.WireRequest.model_validate(
                {"wire_version": 2, "request": make_wire_request().model_dump()}
            )

        with pytest.raises(ValidationError):
            wire.WireRequest.model_validate(
                {"wire_version": "1", "request": make_wire_request().model_dump()}
            )


class TestTheEnvelopeIsClosed:
    def test_a_round_trip_preserves_the_request(self) -> None:
        envelope = wire.WireRequest(request=make_wire_request())

        parsed = wire.WireRequest.model_validate_json(envelope.model_dump_json())

        assert parsed == envelope
        assert parsed.wire_version == wire.WIRE_VERSION

    def test_a_principal_is_not_representable_in_the_envelope(self) -> None:
        """The gateway refuses a body-supplied principal at the wire; the
        sanctioned client cannot even express one. Both directions matter — the
        first constrains an attacker, this one keeps the field from ever
        existing for a later change to start honouring."""
        envelope = wire.WireRequest(request=make_wire_request())
        payload = envelope.model_dump()
        payload["client_principal"] = "spiffe://impersonated"

        with pytest.raises(ValidationError):
            wire.WireRequest.model_validate(payload)

    def test_nor_inside_the_request(self) -> None:
        payload = wire.WireRequest(request=make_wire_request()).model_dump()
        payload["request"]["principal"] = "spiffe://impersonated"

        with pytest.raises(ValidationError):
            wire.WireRequest.model_validate(payload)

    def test_an_unrecognised_response_version_does_not_parse(self) -> None:
        outcome = {
            "status": "completed",
            "decision_ref": FINGERPRINT,
            "decided_at": "2026-07-28T12:00:00Z",
            "reasons": [],
        }

        with pytest.raises(ValidationError):
            wire.WireResponse.model_validate({"wire_version": 99, "outcome": outcome})

    def test_money_is_integer_minor_units(self) -> None:
        with pytest.raises(ValidationError):
            make_wire_request(amount_minor=12.5)

    def test_a_raw_account_number_is_not_representable(self) -> None:
        """Reference fields accept the keyed-fingerprint shape and nothing
        else, so a PAN or IBAN is unrepresentable rather than discouraged."""
        with pytest.raises(ValidationError):
            make_wire_request(counterparty_ref="DE89370400440532013000")
