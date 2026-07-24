# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Architecture invariants, enforced against the whole package.

These tests discover every model in `secondsign` rather than naming a fixed
list, so a model added in a future slice is subject to the invariants the
moment it exists. That is the point: a contributor should not be able to
introduce a payload channel by adding a file nobody thought to add to a test.

Each test names the invariant it enforces. See `docs/INVARIANTS.md`.
"""

import importlib
import pkgutil
import typing

import pytest
from pydantic import BaseModel

import secondsign

#: Field-name fragments that would imply a raw financial or personal value.
FORBIDDEN_NAME_FRAGMENTS = (
    "pan",
    "card",
    "account_number",
    "iban",
    "swift",
    "routing",
    "holder",
    "address",
    "email",
    "phone",
    "memo",
    "description",
    "instruction",
    "note",
    "metadata",
    "extra",
    "payload_data",
    "raw",
    "blob",
    "attributes",
    "properties",
    "arbitrary",
)

#: Substrings a *money* field must not be typed around. Money is integer minor
#: units; a float amount is a rounding defect waiting for a reconciliation.
MONEY_FIELD_HINTS = ("value_", "amount", "minor", "price", "fee", "balance")


def _all_models() -> list[type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for module_info in pkgutil.walk_packages(secondsign.__path__, f"{secondsign.__name__}."):
        module = importlib.import_module(module_info.name)
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, BaseModel) and obj is not BaseModel:
                if obj.__module__.startswith("secondsign."):
                    found[f"{obj.__module__}.{obj.__qualname__}"] = obj
    return sorted(found.values(), key=lambda m: (m.__module__, m.__qualname__))


MODELS = _all_models()


def test_the_discovery_itself_works():
    """A silent discovery failure would make every test below vacuous."""
    assert MODELS, "no models discovered — the architecture suite is not testing anything"


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv3_no_free_form_field(model):
    """INV-3 — no mapping, Any, or object field on any model."""
    for field_name, field in model.model_fields.items():
        annotation = field.annotation
        origin = typing.get_origin(annotation) or annotation
        assert annotation is not typing.Any, f"{model.__qualname__}.{field_name} is Any"
        assert origin is not object, f"{model.__qualname__}.{field_name} is object"
        assert not (isinstance(origin, type) and issubclass(origin, dict)), (
            f"{model.__qualname__}.{field_name} is a mapping — a free-form payload channel"
        )


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv3_unknown_fields_are_rejected(model):
    """INV-3 — extra="forbid" everywhere, so nothing rides along unnoticed."""
    assert model.model_config.get("extra") == "forbid", (
        f"{model.__qualname__} accepts unknown fields"
    )


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv4_models_are_frozen(model):
    """INV-4 — no layer may mutate a decision object after it is built."""
    assert model.model_config.get("frozen") is True, f"{model.__qualname__} is mutable"


def _names_a_mutable_collection(annotation_repr: str) -> bool:
    """True if an annotation is an appendable builtin collection.

    ``frozenset`` is immutable and must not be flagged, even though its repr
    contains the substring ``set[`` — that substring match was a false positive
    that would have rejected a legitimately-immutable frozenset field.
    """
    normalized = annotation_repr.replace("frozenset[", "").replace("FrozenSet[", "")
    return "list[" in normalized or "set[" in normalized or "Set[" in normalized


@pytest.mark.parametrize(
    ("annotation_repr", "is_mutable"),
    [
        ("list[int]", True),
        ("set[str]", True),
        ("typing.Set[int]", True),
        ("frozenset[int]", False),
        ("FrozenSet[int]", False),
        ("tuple[int, ...]", False),
        ("int | None", False),
    ],
)
def test_mutable_collection_detector(annotation_repr, is_mutable):
    """The detector accepts frozenset and rejects the mutable builtins."""
    assert _names_a_mutable_collection(annotation_repr) is is_mutable


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv4_collections_are_immutable(model):
    """INV-4 — frozen is shallow; a list or set field is still mutable."""
    for field_name, field in model.model_fields.items():
        assert not _names_a_mutable_collection(repr(field.annotation)), (
            f"{model.__qualname__}.{field_name} is a mutable collection — "
            "frozen=True does not protect it"
        )


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv5_no_field_name_implies_raw_data(model):
    """INV-5 — raw financial and personal data is unrepresentable."""
    for field_name in model.model_fields:
        lowered = field_name.lower()
        for fragment in FORBIDDEN_NAME_FRAGMENTS:
            assert fragment not in lowered, (
                f"{model.__qualname__}.{field_name} suggests a raw value slot ({fragment!r})"
            )


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv5_money_is_never_floating_point(model):
    """INV-5 — integer minor units only."""
    for field_name, field in model.model_fields.items():
        if any(hint in field_name.lower() for hint in MONEY_FIELD_HINTS):
            assert field.annotation is not float, (
                f"{model.__qualname__}.{field_name} is a float — money is integer minor units"
            )


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__qualname__)
def test_inv3_published_schema_offers_no_open_object(model):
    """INV-3 — the guarantee must survive serialization, not just typing."""
    schema = model.model_json_schema()
    for name, spec in schema.get("properties", {}).items():
        assert spec.get("type") != "object", f"{model.__qualname__}.{name} serializes as an object"
        assert "additionalProperties" not in spec, (
            f"{model.__qualname__}.{name} permits additional properties"
        )


def test_inv7_core_does_not_import_enterprise():
    """INV-7 — checked here too, so it fails even without the import linter."""
    for module_info in pkgutil.walk_packages(secondsign.__path__, f"{secondsign.__name__}."):
        module = importlib.import_module(module_info.name)
        source = getattr(module, "__file__", None)
        if not source:
            continue
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        assert "secondsign_enterprise" not in text, f"{module_info.name} references enterprise"


def test_no_module_reaches_outside_the_repository():
    """No module may hard-code a path outside this repository.

    A package that names a directory on someone's machine is a package that
    does not build anywhere else, and a decision path that can read a file
    outside its own tree is one more place for configuration to arrive from.
    Both failures start as an absolute home-directory path in a source file.
    """
    outside = ("/users/", "/home/", "~/", "c:\\users")
    for module_info in pkgutil.walk_packages(secondsign.__path__, f"{secondsign.__name__}."):
        module = importlib.import_module(module_info.name)
        source = getattr(module, "__file__", None)
        if not source:
            continue
        with open(source, encoding="utf-8") as handle:
            text = handle.read().lower()
        for marker in outside:
            assert marker not in text, f"{module_info.name} hard-codes an external path: {marker}"
