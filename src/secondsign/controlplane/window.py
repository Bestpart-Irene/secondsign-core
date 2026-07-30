# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The trailing-window spend ledger — the state a velocity limit is judged on.

:class:`~secondsign.policy.AmountWindowPolicy` reads a
:class:`~secondsign.policy.WindowAggregate` and never computes one, which is the
right split: a policy that computed its own aggregate would be a policy holding
control-plane state. This module is where that state lives.

Two properties the limit depends on:

**A rolling duration, never a calendar boundary.** The aggregate covers
``now - window_seconds`` to ``now``. A natural-day boundary is itself a thing to
game — spend up to the limit at 23:59 and again at 00:01 — so the window moves
with the clock rather than with the date.

**Missing is not empty, and this ledger cannot express "missing".** A caller that
cannot reach this store must pass ``None`` to the policy, which denies (A4).
What this class returns is always a real aggregate for a real key, so a zero here
means "nothing was spent", not "nothing was found". Conflating those two is how a
velocity limit stops applying to the traffic that most needs it.

The ledger is control plane by prefix: an agent that could write here could
raise its own limit by declaring its prior spend to be zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from secondsign.policy import AggregateKey, WindowAggregate


@dataclass(frozen=True)
class _Entry:
    key: AggregateKey
    amount_minor: int
    at: datetime


@dataclass
class WindowLedger:
    """Spend recorded against aggregate keys, read back over a rolling window."""

    window_seconds: int
    _entries: list[_Entry] = field(default_factory=list, init=False)

    def record(self, key: AggregateKey, *, amount_minor: int, at: datetime) -> None:
        """Note that ``amount_minor`` was committed against ``key`` at ``at``.

        Called for anything that may have moved money — which includes an
        indeterminate dispatch. Counting only confirmed successes would let a
        window be spent twice by an agent that arranged for the first answer to
        be ambiguous.
        """
        self._entries.append(_Entry(key=key, amount_minor=amount_minor, at=at))

    def aggregate(self, key: AggregateKey, *, now: datetime) -> WindowAggregate:
        """The spend against ``key`` in the window ending at ``now``.

        Entries at exactly the window's opening edge are included, and the
        aggregate carries the window it was computed over — the policy re-checks
        that, so an aggregate for the wrong window denies rather than being
        silently accepted as the right one.
        """
        opened = now - timedelta(seconds=self.window_seconds)
        inside = [e for e in self._entries if e.key == key and opened <= e.at <= now]
        return WindowAggregate(
            key=key,
            window_seconds=self.window_seconds,
            aggregate_minor=sum(e.amount_minor for e in inside),
            count=len(inside),
        )
