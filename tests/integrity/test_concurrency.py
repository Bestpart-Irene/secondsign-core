# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Integrity under concurrency — the gateway serves requests on threads.

`secondsign.gateway.server` is a `ThreadingHTTPServer`, so one
`AuthorizationService` answers many requests at once. Every other suite drives
it one call at a time, which is the right way to test a decision and a blind
spot for a limit: a spending cap is only a cap if two requests that arrive
together cannot both read "nothing spent yet" and both dispatch.

These cases hammer a single service from many threads and assert the invariant
that a cap makes — **total dispatched value never exceeds the cap** — plus the
idempotency invariant that N identical retries cause at most one dispatch.

They use a barrier so the workers genuinely overlap rather than serialising by
luck, and a rail that sleeps briefly inside `dispatch` to widen the window
between the decision and the ledger write. No real money and no real API: the
rail is a counter.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from secondsign.agent.surface import AuthorizationRequest
from secondsign.audit import AuditLog, InMemoryAuditSink
from secondsign.contracts import Currency
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway.authorization import AuthorizationService
from secondsign.gateway.execution import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.policy import AmountLimit, AmountWindowPolicy

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
PRINCIPAL = "spiffe://secondsign.example/agent/load"
CAP = 1_000_00
PER_PROPOSAL = 300_00  # three fit under the cap, a fourth does not


class CountingRail:
    """A rail that only counts, and sleeps to widen the decision→dispatch gap.

    `dispatched_minor` is the sum of everything that reached `dispatch`. In a
    correct system it never exceeds the cap, because a request that would push
    the window over is denied before it ever gets here.
    """

    def __init__(self, delay_seconds: float = 0.002) -> None:
        self._delay = delay_seconds
        self._lock = threading.Lock()
        self.dispatched_minor = 0
        self.dispatch_count = 0

    def dispatch(self, intent) -> RailResult:  # noqa: ANN001 — protocol shape
        time.sleep(self._delay)
        with self._lock:
            self.dispatched_minor += intent.dimensions.value_upper_minor
            self.dispatch_count += 1
        return RailResult(status=ExecutionStatus.success, reference="ref")


def _service(rail: CountingRail) -> AuthorizationService:
    limit = AmountLimit(quote_currency=Currency.USD, window_seconds=3600, max_aggregate_minor=CAP)
    return AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(rail, InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
    )


def _request(ref_hex: str, amount: int = PER_PROPOSAL) -> AuthorizationRequest:
    return AuthorizationRequest.model_validate(
        {
            "action": "payment",
            "rail": "card",
            "currency": "USD",
            "amount_minor": amount,
            "reversibility": "irreversible",
            "counterparty_ref": "fp:" + "cd" * 32,
            "source_account_ref": "fp:" + "ef" * 32,
            "request_ref": "fp:" + ref_hex,
        }
    )


def _run_concurrently(service, requests, *, refs):
    """Fire every (ref, request) at the service at once, from its own thread."""
    barrier = threading.Barrier(len(requests))
    results: list[str] = []
    results_lock = threading.Lock()

    def worker(ref: str, request: AuthorizationRequest) -> None:
        barrier.wait()
        outcome = service.authorize(PRINCIPAL, request, now=NOW)
        with results_lock:
            results.append(outcome.status.value)

    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = [
            pool.submit(worker, ref, request) for ref, request in zip(refs, requests, strict=True)
        ]
        for future in futures:
            future.result()
    return results


class TestTheCapHoldsUnderConcurrency:
    def test_total_dispatched_value_never_exceeds_the_cap(self) -> None:
        """The invariant a limit exists to make. Ten distinct proposals of
        $300 against a $1,000 cap arrive together; at most three may dispatch,
        whatever the interleaving, because the fourth crosses the cap."""
        rail = CountingRail()
        service = _service(rail)
        refs = [f"{i:02x}" * 32 for i in range(10)]
        requests = [_request(ref) for ref in refs]

        statuses = _run_concurrently(service, requests, refs=refs)

        assert rail.dispatched_minor <= CAP, (
            f"dispatched {rail.dispatched_minor} against a cap of {CAP} — the "
            "spending limit did not hold under concurrent proposals"
        )
        completed = statuses.count("completed")
        assert completed == rail.dispatch_count
        assert completed <= CAP // PER_PROPOSAL

    def test_the_cap_holds_when_stamp_order_inverts_lock_order(self) -> None:
        """The subtler leak, deterministic and thread-free.

        `now` is stamped in the handler thread *before* the lock is taken, and
        the lock is not FIFO-fair — it is held across a rail call — so under a
        burst a request with an earlier stamp can acquire the lock *after* a
        later-stamped one has already recorded its spend. The window aggregate
        is bounded at `now`, so that earlier-stamped decision cannot see the
        later spend, and both dispatch. The lock serialises the sections; it
        does not order them by clock. The single-shared-`NOW` test above cannot
        see this, because `e.at == now` holds by equality regardless of order.

        Two sequential calls reproduce it exactly: a $900 at T+2s records at
        T+2s, then a $900 stamped at T reads the window as of T — blind to the
        T+2s entry — and both would complete for $1,800 against a $1,000 cap
        unless the service refuses to let its clock run backwards.
        """
        rail = CountingRail()
        service = _service(rail)

        first = service.authorize(
            PRINCIPAL, _request("aa" * 32, 900_00), now=NOW + timedelta(seconds=2)
        )
        second = service.authorize(PRINCIPAL, _request("bb" * 32, 900_00), now=NOW)

        assert (first.status.value, second.status.value) == ("completed", "refused"), (
            f"got {first.status.value}/{second.status.value} — an earlier stamp "
            "arriving after a later one saw a stale window and overspent"
        )
        assert rail.dispatched_minor <= CAP, (
            f"dispatched {rail.dispatched_minor} against a cap of {CAP} — the "
            "clock ran backwards and the window under-counted a prior spend"
        )


class TestIdempotencyHoldsUnderConcurrency:
    def test_identical_retries_dispatch_at_most_once(self) -> None:
        """The same handle sent from many threads at once must reach the rail
        no more than once — the reservation is the whole point (B2).

        Every caller still gets a truthful answer: the one that dispatches, and
        the rest reading that settled outcome back rather than a refusal. A
        concurrent retry is a retry, not a second payment and not a lie about
        the first.
        """
        rail = CountingRail()
        service = _service(rail)
        ref = "ab" * 32
        requests = [_request(ref) for _ in range(16)]

        statuses = _run_concurrently(service, requests, refs=[ref] * 16)

        assert rail.dispatch_count == 1, (
            f"{rail.dispatch_count} dispatches for one idempotency key — a "
            "concurrent retry double-spent (or never spent)"
        )
        # Once the answer is settled, every retry reads it back. None may report
        # a spurious refusal: the money moved, and telling an agent otherwise is
        # how it retries against a completed payment.
        assert set(statuses) == {"completed"}, (
            f"a retry got something other than the answer: {statuses}"
        )
