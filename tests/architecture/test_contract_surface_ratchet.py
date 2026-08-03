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

What is locked here is the *structure* of the surface: published names, enum
members, model fields, and — for every published callable — its signature
(parameter names, kinds, order, defaults, and return annotation). A signature is
as much a compatibility promise as a name is: renaming a parameter, making one
keyword-only, or changing a return type breaks a caller just as surely as
removing the function, so it too must not move without a `CONTRACT_VERSION` bump.
The callables are discovered from the published surface rather than listed by
hand, so a newly exported function is caught here until it is deliberately
baselined.

Behavioural guarantees — that money is integer minor units, that boundary models
are frozen, that combination is monotone — are held by the contract and property
suites; the two this file also pins are the finding-quantity ceiling (a
structural anti-identifier control, threat A5) and a golden result for `combine`,
the callable most of the extension surface routes through.
"""

import inspect
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

#: Sentinel for a parameter with no default. A distinct string, so "no default"
#: can never be confused with a real default that happens to serialise oddly.
NO_DEFAULT = "<no default>"

#: Every published callable and its frozen signature. Each parameter is
#: ``(name, kind, type token, default token)`` in declaration order, and the
#: return annotation is a type token in the same vocabulary as the model fields.
#: The kind names come from :class:`inspect.Parameter` (``POSITIONAL_OR_KEYWORD``,
#: ``KEYWORD_ONLY``, ``VAR_POSITIONAL``, …), so making a parameter keyword-only or
#: reordering two positional ones is a change the ratchet catches.
FROZEN_CALLABLES = {
    "combine": {
        "params": (
            ("left", "POSITIONAL_OR_KEYWORD", "PluginJudgement", NO_DEFAULT),
            ("right", "POSITIONAL_OR_KEYWORD", "PluginJudgement", NO_DEFAULT),
        ),
        "returns": "PluginJudgement",
    },
    "neutral": {
        "params": (),
        "returns": "PluginJudgement",
    },
    "render": {
        "params": (("judgement", "POSITIONAL_OR_KEYWORD", "PluginJudgement", NO_DEFAULT),),
        "returns": "str",
    },
    "render_finding": {
        "params": (("finding", "POSITIONAL_OR_KEYWORD", "Finding", NO_DEFAULT),),
        "returns": "str",
    },
    "run_plugins": {
        "params": (
            ("plugins", "POSITIONAL_OR_KEYWORD", "Iterable[object]", NO_DEFAULT),
            ("view", "POSITIONAL_OR_KEYWORD", "PolicyView", NO_DEFAULT),
        ),
        "returns": "PluginJudgement",
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


def _annotation_token(annotation: object) -> str:
    """A type token for a signature annotation, tolerating an unannotated slot.

    ``inspect`` uses one sentinel for a missing parameter or return annotation;
    reduce it to a stable string so *removing* an annotation is itself a change
    the ratchet reports, rather than a crash.
    """
    if annotation is inspect.Signature.empty:
        return "<unannotated>"
    return _type_token(annotation)


def _signature_token(func: object) -> dict[str, object]:
    """The frozen-comparable shape of a callable's signature.

    Annotations are resolved (``eval_str=True``) and reduced to the same
    module-path-independent tokens the model-field baseline uses, so the shape is
    stable across pydantic and typing internals while still pinning parameter
    names, kinds, order, defaults and the return type.
    """
    signature = inspect.signature(func, eval_str=True)
    params = tuple(
        (
            parameter.name,
            parameter.kind.name,
            _annotation_token(parameter.annotation),
            NO_DEFAULT if parameter.default is inspect.Parameter.empty else repr(parameter.default),
        )
        for parameter in signature.parameters.values()
    )
    return {"params": params, "returns": _annotation_token(signature.return_annotation)}


def _published_callables() -> dict[str, object]:
    """Every plain function `secondsign.contracts` publishes, discovered by shape.

    Only ``inspect.isfunction`` symbols are returned: classes (enums, models, the
    ``PolicyPlugin`` protocol) and the ``Fingerprint`` alias are locked by the
    name, enum and field baselines — and, for ``PolicyPlugin``, by
    ``test_policy_plugin_protocol_surface_is_frozen``, which pins its method
    signature. A pydantic model's generated ``__init__`` is already pinned
    field-by-field. Discovery — rather than a hand-list — is
    what makes a newly published function fail the set check below until it is
    deliberately baselined.
    """
    return {
        name: getattr(contracts, name)
        for name in contracts.__all__
        if inspect.isfunction(getattr(contracts, name))
    }


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
    # Order is part of the frozen surface, not only the member set. Declaration
    # order is load-bearing where code reads a member positionally — the
    # gateway's strictest source-trust/reversibility defaults, the strictness
    # rank a trust lattice would derive — and a dict comparison is
    # order-insensitive, so a reorder that flips "strictest" to "loosest" would
    # slip through the check above. Comparing the ordered member names catches it.
    assert list(live) == list(FROZEN_ENUMS[enum_name]), (
        f"{enum_name} members were reordered — declaration order is frozen because "
        "positional readers (strictest-default, strictness rank) depend on it"
    )


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


def test_policy_view_numeric_bounds_are_frozen():
    """PolicyView's minor-unit and count fields are non-negative — that is surface.

    The field baseline records only ``(required, type token)``, so loosening
    ``value_lower_minor: int = Field(ge=0)`` to ``Field(ge=-1_000_000_000)`` —
    re-opening negative money on the plugin boundary — passes it unseen. The lower
    bounds are locked here so reopening one is a surface change a version bump has
    to acknowledge, not a quiet edit.
    """
    fields = contracts.PolicyView.model_fields
    for name in ("value_lower_minor", "value_upper_minor", "scope_count", "recent_count_window"):
        constraints = {type(item).__name__.lower(): item for item in fields[name].metadata}
        ge = getattr(constraints.get("ge"), "ge", None)
        assert ge == 0, f"PolicyView.{name} lower bound moved off 0"


def test_policy_plugin_protocol_surface_is_frozen():
    """INV-15. The ``PolicyPlugin`` Protocol is the third-party contract, so its
    method surface is a compatibility promise — not only its name.

    The published-name set locks that ``PolicyPlugin`` exists; it does not lock its
    shape. Renaming ``evaluate`` to ``assess``, or changing its
    ``(view) -> PluginJudgement`` signature, breaks every extension while passing
    the name check. The runner's docstring says this surface is locked; pinning it
    here is what makes that claim true.
    """
    plugin = contracts.PolicyPlugin
    assert _type_token(plugin.__annotations__["contract_version"]) == "int", (
        "PolicyPlugin.contract_version attribute type changed"
    )
    assert _signature_token(plugin.evaluate) == {
        "params": (
            ("self", "POSITIONAL_OR_KEYWORD", "<unannotated>", NO_DEFAULT),
            ("view", "POSITIONAL_OR_KEYWORD", "PolicyView", NO_DEFAULT),
        ),
        "returns": "PluginJudgement",
    }, "PolicyPlugin.evaluate signature changed"


def test_published_callables_are_exactly_the_frozen_set():
    """The set of published functions may neither grow nor shrink without a bump.

    Discovered from the surface, so a newly exported function fails here until it
    is baselined in `FROZEN_CALLABLES` — the ratchet covers new symbols on its
    own, rather than silently omitting the ones nobody remembered to add.
    """
    discovered = set(_published_callables())
    assert discovered == set(FROZEN_CALLABLES), {
        "added": sorted(discovered - set(FROZEN_CALLABLES)),
        "removed": sorted(set(FROZEN_CALLABLES) - discovered),
    }


@pytest.mark.parametrize("callable_name", sorted(FROZEN_CALLABLES))
def test_callable_signatures_are_frozen(callable_name):
    """A published signature is a compatibility promise; lock its exact shape.

    Renaming a parameter, reordering two, making one keyword-only, adding a
    default, or changing the return type all fail this — the message says which
    symbol moved and how, because the frozen and live shapes are both reported.
    """
    func = getattr(contracts, callable_name)
    assert inspect.isfunction(func), f"{callable_name} is no longer a plain function"
    live = _signature_token(func)
    assert live == FROZEN_CALLABLES[callable_name], {
        "symbol": callable_name,
        "frozen": FROZEN_CALLABLES[callable_name],
        "live": live,
    }


def test_combine_is_behaviourally_stable():
    """A golden result for `combine` — identical inputs, identical serialised output.

    The signature check pins `combine`'s shape; this pins what it *does*. Because
    combination is the one place two judgements meet, a silent change to how it
    merges verdicts or orders findings would alter every audit record without
    touching a name or a type. Locking the serialised result makes that change
    fail here too, alongside the property suite that proves the algebra's laws.
    """
    left = contracts.PluginJudgement(
        verdict=contracts.PluginVerdict.REVIEW,
        findings=(contracts.Finding(code=contracts.ReasonCode.org_policy),),
    )
    right = contracts.PluginJudgement(
        verdict=contracts.PluginVerdict.DENY,
        findings=(
            contracts.Finding(code=contracts.ReasonCode.velocity_limit, observed=9, limit=5),
        ),
    )
    expected = {
        "contract_version": 1,
        "verdict": 2,  # DENY — the stricter of REVIEW and DENY
        "findings": [
            {"code": "org_policy", "observed": None, "limit": None},
            {"code": "velocity_limit", "observed": 9, "limit": 5},
        ],
    }
    assert contracts.combine(left, right).model_dump(mode="json") == expected
    # Commutative: the serialised record does not depend on argument order.
    assert contracts.combine(right, left).model_dump(mode="json") == expected
