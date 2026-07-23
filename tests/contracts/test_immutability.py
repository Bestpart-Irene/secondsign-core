"""Immutability, including through nested containers.

`frozen=True` is shallow in pydantic: it stops attribute rebinding but not
mutation of a mutable value already held by a field. A plugin that can append
to a reason list can rewrite the audit story after the fact, so every
collection field must be an immutable container.
"""

import pytest
from pydantic import ValidationError

from secondsign.contracts import PluginJudgement, PluginVerdict, PolicyView, ReasonCode

from .conftest import make_view


def test_view_attributes_cannot_be_rebound(view):
    with pytest.raises(ValidationError):
        view.value_upper_minor = 1


def test_judgement_attributes_cannot_be_rebound():
    judgement = PluginJudgement(
        verdict=PluginVerdict.REVIEW,
        reasons=(ReasonCode.velocity_limit,),
        explanation="velocity above the configured window",
    )
    with pytest.raises(ValidationError):
        judgement.verdict = PluginVerdict.ABSTAIN


def test_reason_collection_is_an_immutable_container():
    judgement = PluginJudgement(
        verdict=PluginVerdict.DENY,
        reasons=(ReasonCode.counterparty_risk,),
        explanation="counterparty band above policy",
    )
    assert isinstance(judgement.reasons, tuple)
    with pytest.raises(TypeError):
        judgement.reasons[0] = ReasonCode.velocity_limit
    with pytest.raises(AttributeError):
        judgement.reasons.append(ReasonCode.velocity_limit)


def test_a_supplied_list_cannot_alias_into_the_model():
    """Passing a list must copy, not alias — else the caller keeps a handle."""
    supplied = [ReasonCode.velocity_limit]
    judgement = PluginJudgement(
        verdict=PluginVerdict.REVIEW,
        reasons=supplied,
        explanation="velocity above the configured window",
    )
    supplied.append(ReasonCode.counterparty_risk)
    assert judgement.reasons == (ReasonCode.velocity_limit,)


@pytest.mark.parametrize(
    "model_fields",
    [PolicyView.model_fields, PluginJudgement.model_fields],
    ids=["PolicyView", "PluginJudgement"],
)
def test_no_field_is_a_mutable_container(model_fields):
    for name, field in model_fields.items():
        annotation = repr(field.annotation)
        assert "list[" not in annotation, f"{name} is a list — mutable"
        assert "set[" not in annotation, f"{name} is a set — mutable"


def test_every_model_declares_frozen_and_forbid():
    for model in (PolicyView, PluginJudgement):
        assert model.model_config.get("frozen") is True, model.__name__
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_model_copy_produces_a_new_object_not_a_mutation(view):
    tightened = view.model_copy(update={"scope_count": 9})
    assert view.scope_count == 1
    assert tightened.scope_count == 9
    assert tightened is not view


def test_equal_views_are_interchangeable():
    assert make_view() == make_view()
