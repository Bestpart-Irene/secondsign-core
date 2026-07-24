# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for rail adapters.

A rail proves its adapter is safe to install by inheriting from
:class:`RailAdapterConformance`, naming the subclass ``Test...``, and supplying
an adapter plus a corpus of well-formed calls it should map:

.. code-block:: python

    from secondsign.conformance import RailAdapterConformance
    from my_package import MyRailAdapter, a_call, another_call


    class TestMyRailAdapter(RailAdapterConformance):
        adapter = MyRailAdapter()
        valid_calls = (a_call(), another_call())

The suite then checks the guarantees the adapter boundary exists to make: every
well-formed call maps to an immutable intent, derivation is deterministic and
side-effect-free, the idempotency key is derived rather than accepted, and
source trust is never raised (B2, B9, A5). Passing it is what "safe rail
adapter" means, so the security argument is not re-run in review each time.

Like the policy-plugin kit, this module imports no test framework — the methods
are plain assertions pytest collects from the subclass.
"""

from secondsign.adapters.contract import RejectReason, ToolCall, trust_rank
from secondsign.contracts import RailClass
from secondsign.intent import TransactionIntent


class RailAdapterConformance:
    """Inherit, set ``adapter`` and ``valid_calls``. Name the subclass ``Test...``."""

    #: The adapter under test. Subclasses must set this.
    adapter: object = None
    #: Well-formed calls the adapter is expected to map to intents.
    valid_calls: tuple[ToolCall, ...] = ()

    # -- helpers ------------------------------------------------------------

    def _adapter(self) -> object:
        if self.adapter is None:
            raise AssertionError(
                f"{type(self).__name__} must set an `adapter` attribute to the "
                "adapter instance being certified"
            )
        return self.adapter

    def _calls(self) -> tuple[ToolCall, ...]:
        if not self.valid_calls:
            raise AssertionError(
                f"{type(self).__name__} must set `valid_calls` to a non-empty "
                "corpus of well-formed calls the adapter should map"
            )
        return self.valid_calls

    def _intents(self):
        adapter = self._adapter()
        for call in self._calls():
            result = adapter.derive(call)
            assert isinstance(result, TransactionIntent), (
                "a call in `valid_calls` was rejected; the corpus is meant to be "
                f"the mappable happy path, but derive returned {result!r}"
            )
            yield call, result

    # -- contract compliance ------------------------------------------------

    def test_declares_the_rail_class_it_serves(self):
        rail = getattr(self._adapter(), "rail_class", None)
        assert isinstance(rail, RailClass), (
            f"adapter declares rail_class {rail!r}, which is not a RailClass"
        )

    def test_derive_returns_an_intent_or_a_reject(self):
        adapter = self._adapter()
        for call in self._calls():
            result = adapter.derive(call)
            assert isinstance(result, (TransactionIntent, RejectReason)), (
                f"derive returned {type(result).__name__}, not an intent or a RejectReason"
            )

    def test_every_valid_call_maps_to_an_intent(self):
        for _call, intent in self._intents():
            assert isinstance(intent, TransactionIntent)

    def test_intents_carry_the_declared_rail_class(self):
        rail = self._adapter().rail_class
        for _call, intent in self._intents():
            assert intent.dimensions.rail_class is rail, (
                "adapter produced an intent on a rail it does not declare"
            )

    # -- idempotency (B2) ---------------------------------------------------

    def test_the_idempotency_key_cannot_be_supplied_by_the_caller(self):
        """Structural: no call in the corpus even has a key field to set."""
        for call in self._calls():
            assert "idempotency_key" not in type(call).model_fields, (
                "a call type exposes an idempotency_key field — a caller could "
                "then choose it, which is how a replay is disguised (B2)"
            )

    def test_the_idempotency_key_is_derived_and_non_empty(self):
        for _call, intent in self._intents():
            assert intent.idempotency_key, "derived idempotency key is empty"

    # -- determinism and purity ---------------------------------------------

    def test_derivation_is_deterministic(self):
        adapter = self._adapter()
        for call in self._calls():
            assert adapter.derive(call) == adapter.derive(call), (
                "adapter is not deterministic for an identical call"
            )

    def test_does_not_mutate_the_call(self):
        adapter = self._adapter()
        for call in self._calls():
            before = call.model_dump()
            adapter.derive(call)
            assert call.model_dump() == before, "adapter mutated the call it was given"

    # -- provenance (B9) ----------------------------------------------------

    def test_source_trust_is_never_upgraded(self):
        """The adapter may lower declared provenance, never raise it."""
        for call, intent in self._intents():
            assert trust_rank(intent.dimensions.source_trust) <= trust_rank(
                call.declared_source_trust
            ), (
                "adapter raised source trust above what the call declared — "
                f"{call.declared_source_trust} became {intent.dimensions.source_trust}"
            )
