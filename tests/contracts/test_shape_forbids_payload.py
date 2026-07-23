"""Threat A5 — the contract must have nowhere to hide a payload.

These are the tests that define "done" for this slice: an enterprise plugin
author must be unable to find a route back to free-form metadata, and no field
may be able to carry a PAN, account number, customer name, or payment
instruction.
"""

import typing
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from secondsign.contracts import Finding, PluginJudgement, PluginVerdict, PolicyView, ReasonCode

from .conftest import FINGERPRINT_A, make_view

#: Every model that crosses the plugin boundary.
PUBLIC_CONTRACT_MODELS = (PolicyView, PluginJudgement, Finding)

#: Field-name fragments that would imply a raw financial or personal value.
FORBIDDEN_NAME_FRAGMENTS = (
    "pan",
    "card",
    "account_number",
    "iban",
    "swift",
    "routing",
    "name",
    "address",
    "email",
    "phone",
    "memo",
    "description",
    "instruction",
    "note",
    "metadata",
    "extra",
    "payload",
    "raw",
    "context",
    "attributes",
    "properties",
)


@pytest.mark.parametrize("model", PUBLIC_CONTRACT_MODELS)
def test_rejects_unknown_fields(model):
    """extra="forbid" — a plugin cannot smuggle data through an unknown key."""
    if model is PolicyView:
        payload = make_view().model_dump()
    elif model is Finding:
        payload = {"code": ReasonCode.org_policy}
    else:
        payload = {"verdict": PluginVerdict.ABSTAIN}
    payload["customer_note"] = "Beneficiary: Jane Roe, acct 4111111111111111"
    with pytest.raises(ValidationError):
        model(**payload)


@pytest.mark.parametrize("model", PUBLIC_CONTRACT_MODELS)
def test_no_field_accepts_arbitrary_values(model):
    """No field may be typed as a mapping, Any, or object.

    A single `dict[str, Any]` field would defeat every other control in this
    file, so the ban is asserted against the annotations themselves rather
    than against a sample value.
    """
    for field_name, field in model.model_fields.items():
        annotation = field.annotation
        origin = typing.get_origin(annotation) or annotation
        assert annotation is not typing.Any, f"{model.__name__}.{field_name} is Any"
        assert origin is not object, f"{model.__name__}.{field_name} is object"
        assert not (isinstance(origin, type) and issubclass(origin, dict)), (
            f"{model.__name__}.{field_name} is a mapping — free-form payload channel"
        )


@pytest.mark.parametrize("model", PUBLIC_CONTRACT_MODELS)
def test_no_field_name_implies_raw_financial_data(model):
    for field_name in model.model_fields:
        lowered = field_name.lower()
        for fragment in FORBIDDEN_NAME_FRAGMENTS:
            assert fragment not in lowered, (
                f"{model.__name__}.{field_name} suggests a raw value slot ({fragment!r})"
            )


@pytest.mark.parametrize("model", PUBLIC_CONTRACT_MODELS)
def test_serialized_schema_exposes_no_free_form_object(model):
    """The published JSON schema must not offer an open object anywhere."""
    schema = model.model_json_schema()
    for name, spec in schema.get("properties", {}).items():
        assert spec.get("type") != "object", f"{model.__name__}.{name} serializes as an open object"
        assert "additionalProperties" not in spec, (
            f"{model.__name__}.{name} allows additional properties"
        )


def test_reference_fields_reject_anything_but_a_keyed_fingerprint():
    """A raw account number must be structurally unrepresentable."""
    for raw in (
        "4111111111111111",
        "GB29NWBK60161331926819",
        "Jane Roe",
        "acct_1234567890",
        "fp:short",
        "fp:" + "zz" * 32,
    ):
        with pytest.raises(ValidationError):
            make_view(counterparty_ref=raw)


def test_no_free_text_channel_exists_at_all():
    """Superseded by CORE-S004: prose no longer crosses the boundary.

    Detail is closed vocabulary plus bounded quantities, so there is nothing
    to screen — see tests/contracts/test_structured_findings.py.
    """
    with pytest.raises(ValidationError):
        PluginJudgement(
            verdict=PluginVerdict.DENY,
            findings=(Finding(code=ReasonCode.counterparty_risk),),
            explanation="blocked for account 4111111111111111",
        )


def test_view_carries_no_idempotency_key_or_rail_payload():
    """Plugins judge risk; they do not need control-plane or rail internals."""
    fields = set(PolicyView.model_fields)
    assert "idempotency_key" not in fields
    assert not any(f.startswith("rail_payload") for f in fields)


def test_public_contract_field_sets_are_ratcheted():
    """Pin the surface. Any new field must be added here deliberately."""
    assert set(PolicyView.model_fields) == {
        "contract_version",
        "action_class",
        "rail_class",
        "value_lower_minor",
        "value_upper_minor",
        "quote_currency",
        "counterparty_ref",
        "source_account_ref",
        "not_before",
        "not_after",
        "reversibility",
        "source_trust",
        "scope_count",
        "recent_count_window",
        "counterparty_risk_band",
        "new_counterparty",
        "cross_border",
        "market_session",
    }
    assert set(PluginJudgement.model_fields) == {
        "contract_version",
        "verdict",
        "findings",
    }
    assert set(Finding.model_fields) == {"code", "observed", "limit"}


def test_money_is_integer_minor_units_only():
    with pytest.raises(ValidationError):
        make_view(value_lower_minor=1250.75)
    with pytest.raises(ValidationError):
        make_view(value_lower_minor=-1)


def test_value_band_must_be_ordered():
    with pytest.raises(ValidationError):
        make_view(value_lower_minor=200, value_upper_minor=100)


def test_validity_window_must_be_ordered_and_aware():
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ValidationError):
        make_view(not_before=now, not_after=now)
    with pytest.raises(ValidationError):
        make_view(not_before=datetime(2026, 7, 23, 12, 0))  # noqa: DTZ001 — naive on purpose


def test_fingerprints_survive_round_trip_unchanged():
    assert make_view().counterparty_ref == FINGERPRINT_A
