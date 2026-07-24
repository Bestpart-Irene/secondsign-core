# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Properties of the gateway — the ones a double-spend or replay would exploit.

For any number of concurrent-looking retries of the same intent, the rail is
dispatched at most once; and whatever the executor reports, a duplicate returns
the same recorded outcome rather than re-executing.
"""

from hypothesis import given
from hypothesis import strategies as st

from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionGateway, ExecutionStatus
from tests.gateway.conftest import (
    NOW,
    FixedExecutor,
    fresh_store,
    make_decision,
    make_intent,
)


@given(
    retries=st.integers(min_value=1, max_value=12),
    status=st.sampled_from(list(ExecutionStatus)),
)
def test_the_rail_is_dispatched_at_most_once_per_key(retries, status):
    executor = FixedExecutor(status)
    gateway = ExecutionGateway(executor, fresh_store())
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.ALLOW)
    outcomes = [gateway.execute(intent, decision, now=NOW) for _ in range(retries)]
    assert len(executor.dispatched) == 1
    assert all(o == outcomes[0] for o in outcomes)


@given(status=st.sampled_from(list(ExecutionStatus)))
def test_distinct_keys_each_dispatch_once(status):
    executor = FixedExecutor(status)
    gateway = ExecutionGateway(executor, fresh_store())
    a = make_intent(idempotency_key="k-a")
    b = make_intent(idempotency_key="k-b")
    gateway.execute(a, make_decision(a, DecisionVerdict.ALLOW), now=NOW)
    gateway.execute(b, make_decision(b, DecisionVerdict.ALLOW), now=NOW)
    assert sorted(executor.dispatched) == ["k-a", "k-b"]
