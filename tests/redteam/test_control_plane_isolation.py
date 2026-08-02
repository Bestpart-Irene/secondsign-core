# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: the control-plane isolation group (A2, A3).

The managed agent, and the extensions it can influence, must have no path to
control-plane material: the idempotency store, the approver roster, the audit
keys, the fingerprint keys, or the configured limits. These attacks confirm that
the surfaces an agent or a plugin can see carry none of it — the isolation is
structural, present in the *shape* of the types, not a runtime access check.

Full deployment-topology isolation (an agent process that structurally cannot
reach the control plane at all) is INV-12 / CORE-S017, unbuilt. What is
enforceable in the library today — that no control-plane field exists on any
agent- or plugin-facing model — is what these assert.
"""

from secondsign.adapters import StripeCall, ToolCall
from secondsign.approval import PendingApproval
from secondsign.contracts import Finding, PluginJudgement, PolicyView
from secondsign.controlplane.pending import PendingReview
from secondsign.intent import TransactionIntent
from secondsign.isolation import is_control_plane
from secondsign.policy import PolicyContext, WindowAggregate

#: Field-name fragments that would mean control-plane material had leaked onto a
#: surface the agent or a plugin can see.
# Deliberately specific: a bounded finding quantity is legitimately named
# `limit` (e.g. "velocity 9 against a limit of 5"), so a bare "limit" fragment
# would be a false positive. These name control-plane *stores and secrets*, not
# quantities.
_CONTROL_PLANE_FRAGMENTS = (
    "idempotency",
    "roster",
    "approver",
    "secret",
    "api_key",
    "apikey",
    "fingerprint_key",
    "hmac",
    "ledger",
    "aggregate_store",
)


def _field_names(model) -> set[str]:
    return {name.lower() for name in model.model_fields}


def _assert_no_control_plane_fields(model):
    for field in _field_names(model):
        for fragment in _CONTROL_PLANE_FRAGMENTS:
            assert fragment not in field, (
                f"{model.__name__}.{field} exposes control-plane material ({fragment!r})"
            )


def test_the_plugin_view_carries_no_control_plane_material():
    """A2/A3. A policy plugin sees a redacted view — no key, roster, or limit."""
    _assert_no_control_plane_fields(PolicyView)


def test_the_adapter_call_surface_carries_no_control_plane_material():
    _assert_no_control_plane_fields(ToolCall)
    _assert_no_control_plane_fields(StripeCall)


def test_plugin_output_cannot_carry_control_plane_material():
    _assert_no_control_plane_fields(Finding)
    _assert_no_control_plane_fields(PluginJudgement)


def test_the_policy_context_exposes_an_aggregate_not_the_store():
    """The amount policy reads a derived number, never the idempotency/aggregate
    store itself or the underlying transactions."""
    _assert_no_control_plane_fields(PolicyContext)
    _assert_no_control_plane_fields(WindowAggregate)
    # The aggregate is a count and a sum — not a list of transactions to mine.
    assert set(WindowAggregate.model_fields) == {
        "key",
        "window_seconds",
        "aggregate_minor",
        "count",
    }


def test_the_pending_approval_names_no_roster():
    """B6-adjacent: an approval carries the maker and a digest, not the set of
    who could approve — an agent cannot enumerate approvers from it."""
    _assert_no_control_plane_fields(PendingApproval)


def test_a_held_review_is_on_the_control_plane_side_by_where_it_lives():
    """INV-12 by prefix, not by an entry in a list.

    `secondsign.controlplane.pending` holds the queue of reviews waiting for a
    human. Nothing was added to `isolation.py` to classify it — the module is on
    the protected side because of where the file is, which is the property that
    survives somebody adding the next control-plane module without reading this
    test.
    """
    assert is_control_plane(PendingReview.__module__)
    _assert_no_control_plane_fields(PendingReview)


def test_the_idempotency_key_is_not_a_view_the_agent_can_read():
    """The idempotency key is control-plane material (it gates replay). It lives
    on the intent, but never on the plugin view the agent can influence."""
    assert "idempotency_key" in TransactionIntent.model_fields
    assert "idempotency_key" not in PolicyView.model_fields
