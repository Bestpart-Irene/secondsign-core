# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""INV-15 — the published Policy Plugin API v1 surface is frozen.

This is a *ratchet*: the frozen surface is written out here as a literal
baseline, and the test compares the live package against it. Adding, removing,
renaming, or retyping a published symbol, an enum member, or a model field
fails this test, and the failure cannot be resolved by editing the code alone —
the baseline below has to change in the same pull request, which is exactly the
deliberate, reviewable act the compatibility policy requires (see
`docs/EXTENSION_CONTRACTS.md`). Changing the surface means changing
`CONTRACT_VERSION`; this test is what makes "means" enforceable rather than
aspirational.

What is locked here is the *structure* of the surface. Behavioural guarantees —
that money is integer minor units, that boundary models are frozen, that
combination is monotone — are held by the contract and property suites; the one
bound this file also pins is the finding-quantity ceiling, because it is a
structural anti-identifier control (threat A5), not a mere validation.
"""

import types
import typing
from enum import Enum

import pytest
from pydantic import BaseModel

import secondsign.contracts as contracts

# --- The frozen v1 surface -------------------------------------------------

#: `CONTRACT_VERSION` for Policy Plugin API v1. Bumping it is the *only*
#: sanctioned way to change anything else in this file.
FROZEN_CONTRACT_VERSION = 1

#: Published constants and their exact values.
FROZEN_CONSTANTS = {
    "CONTRACT_VERSION": 1,
    "FINGERPRINT_PATTERN": r"^fp:[0-9a-f]{64}$",
    "MAX_DETAIL_MAGNITUDE": 1_000_000_000_000,
}

#: Every name `secondsign.contracts` publishes. Order-independent.
FROZEN_ALL = frozenset(
    {
        "CONTRACT_VERSION",
        "FINGERPRINT_PATTERN",
        "MAX_DETAIL_MAGNITUDE",
        "ActionClass",
        "Currency",
        "Finding",
        "Fingerprint",
        "MarketSession",
        "PluginJudgement",
        "PluginVerdict",
        "PolicyPlugin",
        "PolicyView",
        "RailClass",
        "ReasonCode",
        "Reversibility",
        "RiskBand",
        "SourceTrust",
        "combine",
        "neutral",
        "render",
        "render_finding",
        "run_plugins",
    }
)

#: Every published enum and its members, name to value.
FROZEN_ENUMS = {
    "PluginVerdict": {"ABSTAIN": 0, "REVIEW": 1, "DENY": 2},
    "ActionClass": {
        "payment": "payment",
        "refund": "refund",
        "payout": "payout",
        "transfer": "transfer",
        "trade": "trade",
        "account_change": "account_change",
    },
    "RailClass": {
        "card": "card",
        "bank_transfer": "bank_transfer",
        "wallet": "wallet",
        "brokerage": "brokerage",
        "other": "other",
    },
    "Currency": {
        "USD": "USD",
        "EUR": "EUR",
        "GBP": "GBP",
        "JPY": "JPY",
        "CHF": "CHF",
        "CAD": "CAD",
        "AUD": "AUD",
        "CNY": "CNY",
        "HKD": "HKD",
        "SGD": "SGD",
    },
    "Reversibility": {
        "irreversible": "irreversible",
        "delayed_reversible": "delayed_reversible",
        "reversible": "reversible",
    },
    "SourceTrust": {
        "untrusted_data": "untrusted_data",
        "mixed": "mixed",
        "unknown": "unknown",
        "trusted_instruction": "trusted_instruction",
    },
    "RiskBand": {
        "low": "low",
        "elevated": "elevated",
        "high": "high",
        "prohibited": "prohibited",
    },
    "MarketSession": {
        "not_applicable": "not_applicable",
        "open": "open",
        "closed": "closed",
        "pre_market": "pre_market",
        "post_market": "post_market",
        "halted": "halted",
    },
    "ReasonCode": {
        "velocity_limit": "velocity_limit",
        "counterparty_risk": "counterparty_risk",
        "jurisdiction_restricted": "jurisdiction_restricted",
        "market_session_closed": "market_session_closed",
        "value_band_exceeded": "value_band_exceeded",
        "new_counterparty": "new_counterparty",
        "org_policy": "org_policy",
        "plugin_error": "plugin_error",
        "plugin_contract_mismatch": "plugin_contract_mismatch",
        "plugin_invalid_result": "plugin_invalid_result",
    },
}

#: Every published model and its fields: name -> (required, type token).
FROZEN_MODEL_FIELDS = {
    "Finding": {
        "code": (True, "ReasonCode"),
        "observed": (False, "int | None"),
        "limit": (False, "int | None"),
    },
    "PluginJudgement": {
        "contract_version": (False, "int"),
        "verdict": (True, "PluginVerdict"),
        "findings": (False, "tuple[Finding, ...]"),
    },
    "PolicyView": {
        "contract_version": (False, "int"),
        "action_class": (True, "ActionClass"),
        "rail_class": (True, "RailClass"),
        "value_lower_minor": (True, "int"),
        "value_upper_minor": (True, "int"),
        "quote_currency": (True, "Currency"),
        "counterparty_ref": (True, "str"),
        "source_account_ref": (True, "str"),
        "not_before": (True, "AwareDatetime"),
        "not_after": (True, "AwareDatetime"),
        "reversibility": (True, "Reversibility"),
        "source_trust": (True, "SourceTrust"),
        "scope_count": (True, "int"),
        "recent_count_window": (True, "int"),
        "counterparty_risk_band": (True, "RiskBand"),
        "new_counterparty": (True, "bool"),
        "cross_border": (True, "bool"),
        "market_session": (True, "MarketSession"),
    },
}


def _type_token(annotation: object) -> str:
    """A stable, module-path-independent string for a field annotation.

    Reduced to bare class names so the baseline does not move when pydantic
    relocates a type between patch releases — the ratchet locks the shape of
    the surface, not the internal home of a helper type.
    """
    if annotation is type(None):
        return "None"
    origin = typing.get_origin(annotation)
    if origin is None:
        return getattr(annotation, "__name__", str(annotation))
    args = typing.get_args(annotation)
    if origin is types.UnionType or origin is typing.Union:
        return " | ".join(_type_token(arg) for arg in args)
    name = getattr(origin, "__name__", str(origin))
    inner = ", ".join("..." if arg is Ellipsis else _type_token(arg) for arg in args)
    return f"{name}[{inner}]"


# --- The ratchet -----------------------------------------------------------


def test_contract_version_is_frozen():
    """The version pin. Changing it is the deliberate act every other change needs."""
    assert contracts.CONTRACT_VERSION == FROZEN_CONTRACT_VERSION


def test_published_constants_are_frozen():
    for name, value in FROZEN_CONSTANTS.items():
        assert getattr(contracts, name) == value, f"{name} changed value"


def test_public_surface_is_exactly_the_frozen_set():
    """`__all__` is the promise; it may neither grow nor shrink without a version bump."""
    published = set(contracts.__all__)
    assert published == set(FROZEN_ALL), {
        "added": sorted(published - FROZEN_ALL),
        "removed": sorted(FROZEN_ALL - published),
    }


def test_every_published_name_resolves():
    """`__all__` cannot promise a symbol the package does not actually expose."""
    for name in FROZEN_ALL:
        assert hasattr(contracts, name), f"{name} is in __all__ but not importable"


@pytest.mark.parametrize("enum_name", sorted(FROZEN_ENUMS))
def test_enum_members_are_frozen(enum_name):
    enum_cls = getattr(contracts, enum_name)
    assert isinstance(enum_cls, type) and issubclass(enum_cls, Enum)
    live = {member.name: member.value for member in enum_cls}
    assert live == FROZEN_ENUMS[enum_name], f"{enum_name} members changed"


@pytest.mark.parametrize("model_name", sorted(FROZEN_MODEL_FIELDS))
def test_model_fields_are_frozen(model_name):
    model = getattr(contracts, model_name)
    assert isinstance(model, type) and issubclass(model, BaseModel)
    live = {
        field_name: (field.is_required(), _type_token(field.annotation))
        for field_name, field in model.model_fields.items()
    }
    assert live == FROZEN_MODEL_FIELDS[model_name], f"{model_name} fields changed"


def test_finding_quantity_bounds_are_frozen():
    """The A5 anti-identifier ceiling is part of the surface, not just validation.

    A quantity that could reach account-number magnitude would let an extension
    smuggle an identifier through a number. Loosening these bounds is a surface
    change, so it is locked here rather than only in a behavioural test.
    """
    fields = contracts.Finding.model_fields
    for name in ("observed", "limit"):
        metadata = fields[name].metadata
        constraints = {type(item).__name__.lower(): item for item in metadata}
        ge = getattr(constraints.get("ge"), "ge", None)
        le = getattr(constraints.get("le"), "le", None)
        assert ge == 0, f"Finding.{name} lower bound moved off 0"
        assert le == contracts.MAX_DETAIL_MAGNITUDE, f"Finding.{name} ceiling moved off the cap"
