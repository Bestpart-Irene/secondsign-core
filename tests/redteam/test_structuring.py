# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: the structuring group (B4).

The classic evasion: keep every single payment under a limit, but let them add
up past it. The sliding-window aggregate is what defeats it — and the positive
control proves that a naive per-transaction check would not.
"""

from secondsign.decision import DecisionVerdict
from secondsign.intent import compute_digest  # noqa: F401 — imported for parity with siblings
from tests.redteam.conftest import amount_context, amount_engine, make_intent

_CAP = 1_000_000
_DRIP = 200_000  # each payment is a fifth of the cap — individually harmless


def test_structuring_a_large_payment_into_small_ones_is_caught():
    engine = amount_engine(_CAP)
    running = 0
    verdicts = []
    for index in range(6):
        intent = make_intent(amount=_DRIP, idempotency_key=f"drip-{index}")
        decision = engine.decide(intent, amount_context(intent, recent_minor=running))
        verdicts.append(decision.verdict)
        if decision.verdict is DecisionVerdict.ALLOW:
            running += _DRIP  # a permitted payment settles into the window

    # Five fit under the cap; the sixth — which would total 1.2M — is denied.
    assert verdicts[:5] == [DecisionVerdict.ALLOW] * 5
    assert verdicts[5] is DecisionVerdict.DENY


def test_positive_control_a_per_transaction_check_would_miss_it():
    """Judged individually — window always empty — every drip passes. That gap
    is exactly what the aggregate closes, so this proves the test above bites."""
    engine = amount_engine(_CAP)
    for index in range(6):
        intent = make_intent(amount=_DRIP, idempotency_key=f"drip-{index}")
        decision = engine.decide(intent, amount_context(intent, recent_minor=0))
        assert decision.verdict is DecisionVerdict.ALLOW


def test_a_single_payment_over_the_cap_is_also_caught():
    """The single transaction is the aggregate's special case, not a blind spot."""
    engine = amount_engine(_CAP)
    intent = make_intent(amount=_CAP + 1)
    assert engine.decide(intent, amount_context(intent)).verdict is DecisionVerdict.DENY
