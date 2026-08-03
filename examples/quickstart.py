# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""SecondSign in five minutes — no Docker, no credential, no real money.

    pip install secondsign-core
    python quickstart.py

Three proposals from an AI agent, three different fates, driven through the
*real* gateway decision path — the same ``authorize()`` / ``resolve()`` an agent
hits in production. The only thing swapped out is the rail at the very end: a
mock that counts calls instead of a driver holding a Stripe key. Nothing in this
file can move a cent.

    $42   ->  completed        (under the review threshold — the machine's to allow)
    $300  ->  awaiting_review  (held for a human; approved below -> completed)
    $900  ->  refused          (over the $500/hour cap — no human can wave it through)

The point is the boundary. What the agent never touches: the rail credential,
the spending window, the approver's answer. It sends a *proposal* and reads back
one of three words — completed, awaiting_review, refused. Everything that
decides, holds, executes and records lives on the other side, where the agent
has no route.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from secondsign.agent import AuthorizationRequest
from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.audit import AuditLog, InMemoryAuditSink
from secondsign.contracts import ActionClass, Currency, RailClass, Reversibility
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.pending import InMemoryPendingStore
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.gateway.approver import render_review

# `AuthorizationService` is the real in-process decision path. It is not on the
# frozen public-contract surface (that is `secondsign.contracts`), so it is
# imported from its module rather than the package root.
from secondsign.gateway.authorization import AuthorizationService
from secondsign.intent import TransactionIntent
from secondsign.policy import AmountLimit, AmountWindowPolicy, CurrencyCoveragePolicy

# The one rule this deployment runs: at most $500 an hour to a counterparty, and
# anything over $200 is held for a human. Money is always integer minor units.
CAP_MINOR = 500_00
REVIEW_ABOVE_MINOR = 200_00
WINDOW_SECONDS = 3600

# Stable opaque handles. In a real deployment the control plane fingerprints the
# real account identifiers with a key the agent cannot reach; here they are just
# well-formed constants. Same counterparty across all three, so the spend
# accumulates against one window.
COUNTERPARTY = "fp:" + "a1" * 32
SOURCE = "fp:" + "b2" * 32


class MockRail:
    """A stand-in rail that counts calls instead of moving money.

    A real executor holds a credential and makes an outbound call (this is the
    one component that does). This one holds nothing and calls nothing — it just
    reports success so the decision path can be watched end to end without a key
    or a network. Its ``rail_class`` matches the card proposals below.
    """

    rail_class: RailClass = RailClass.card

    def __init__(self) -> None:
        self.calls = 0

    def dispatch(self, intent: TransactionIntent) -> RailResult:
        self.calls += 1
        return RailResult(status=ExecutionStatus.success, reference=f"mock-{self.calls}")


def build_service() -> tuple[AuthorizationService, InMemoryPendingStore, MockRail]:
    """The gateway's in-process decision path, wired to a mock rail.

    This is exactly what the shipped ``build_authorization`` assembles, with one
    substitution: the rail executor is the mock above instead of a
    credential-holding HTTP or Stripe driver. The pending store is held here too,
    so the approver side of the demo can read the open review.
    """
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=WINDOW_SECONDS,
        max_aggregate_minor=CAP_MINOR,
        review_above_minor=REVIEW_ABOVE_MINOR,
    )
    pending = InMemoryPendingStore()
    rail = MockRail()
    service = AuthorizationService(
        engine=DecisionEngine(
            [AmountWindowPolicy(limit), CurrencyCoveragePolicy(covered={limit.quote_currency})]
        ),
        gateway=ExecutionGateway(rail, InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
        pending=pending,
    )
    return service, pending, rail


def proposal(dollars: int, *, request_ref: str) -> AuthorizationRequest:
    """One proposal from the agent: pay ``dollars`` to the counterparty.

    The agent supplies the shape of the action and opaque handles — never a
    credential, never an approval, because it holds neither.
    """
    return AuthorizationRequest(
        action=ActionClass.payment,
        rail=RailClass.card,
        currency=Currency.USD,
        amount_minor=dollars * 100,
        reversibility=Reversibility.irreversible,
        counterparty_ref=COUNTERPARTY,
        source_account_ref=SOURCE,
        request_ref=request_ref,
    )


def _short(ref: str) -> str:
    return ref[:8] + "…" + ref[-2:]


def main() -> None:
    service, pending, rail = build_service()
    now = datetime.now(timezone.utc)
    principal = "agent-workload-7"  # the authenticated agent identity

    print("SecondSign · quickstart      (mock rail — nothing here moves real money)")
    print(
        f"Rule: ≤ ${CAP_MINOR // 100} per hour to one counterparty; "
        f"anything over ${REVIEW_ABOVE_MINOR // 100} needs a human.\n"
    )
    print(f"The agent proposes; the gateway decides.   (paying {_short(COUNTERPARTY)})\n")

    # --- Act 1: under the review threshold — allowed and executed --------------
    small = service.authorize(principal, proposal(42, request_ref="fp:" + f"{1:064x}"), now=now)
    print(f"  agent proposes  $42    →   {small.status.value:<15}  ✓  money moved (mock)")

    # --- Act 2: over the threshold, under the cap — held for a human -----------
    mid = service.authorize(principal, proposal(300, request_ref="fp:" + f"{2:064x}"), now=now)
    print(f"  agent proposes  $300   →   {mid.status.value:<15}  ⏸  parked for a human")

    review = pending.open_reviews()[0]
    panel = render_review(review)  # exactly the projection the approver panel renders
    held = f"${cast(int, panel['amount_minor']) / 100:,.2f}"
    inner = 40

    def _box_line(text: str) -> str:
        return "    │ " + text.ljust(inner) + " │"

    print("\n  a human opens the approver panel (a listener the agent has no route to):")
    print("    ┌" + "─" * (inner + 2) + "┐")
    print(_box_line(f"{held} · held for review"))
    print(_box_line(f"to {_short(str(panel['counterparty_ref']))}"))
    print(_box_line("        [ Approve ]   [ Decline ]"))
    print("    └" + "─" * (inner + 2) + "┘")

    # The checker is a different principal than the maker (the proposing agent),
    # so this is not a self-approval. The answer binds the exact proposal digest.
    approved = CheckerVerdict(
        checker=CheckerIdentity(subject="approver@quickstart"),
        approval_id=review.approval_id,
        proposal=review.approval.proposal,
        approved=True,
    )
    resolution = service.resolve(review.approval_id, approved, now=now)
    print(f"    approver clicks Approve →   {resolution.status.value:<15}  ✓  money moved (mock)")

    # --- Act 3: over the cap — refused, and no approval can override it --------
    big = service.authorize(principal, proposal(900, request_ref="fp:" + f"{3:064x}"), now=now)
    reasons = ", ".join(reason.value for reason in big.reasons)
    print(f"\n  agent proposes  $900   →   {big.status.value:<15}  ✗  {reasons}")

    print(
        "\nThe agent held no credential, no spending window, no approval — the whole time.\n"
        "It sent three proposals and read back three words: completed, awaiting_review, refused.\n"
        f"The rail was reached {rail.calls}× — only the two approved payments, never the $900."
    )


if __name__ == "__main__":
    main()
