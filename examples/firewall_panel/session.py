# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""One panel session: a simulated account, a real co-signer, and the knobs.

The session owns the only mutable state the panel has. It is in-process and
resets on restart, deliberately — the panel demonstrates a decision, it is not a
system of record.

One design note worth stating, because it is what makes the sharpest
demonstration possible. The reader handed to the co-signer is a *live view* of
the world rather than a snapshot, so a tamper applied **after** a review is held
is still seen when the checker answers. That is not a trick: ``resolve()``
genuinely re-verifies the chain before it consumes the human's answer, so the
panel can show a review being approved by a real human and *still* refused,
because the account moved underneath it while the human was deciding.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from examples.firewall_panel import trace as trace_module
from examples.firewall_panel.world import AGENT, SAFE, TOKEN, USDC, Tamper, World
from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.audit.log import InMemoryAuditSink
from secondsign.gateway.onchain_cosigner import (
    CosignOutcome,
    CosignStatus,
    OnchainCosigner,
    SafeContext,
)
from secondsign.gateway.signer import LocalSigner
from secondsign.intent import ProposalDigest
from secondsign.onchain.chain_state import SafeChainState, TokenIdentity
from secondsign.onchain.effect import SafeCall

#: The panel's signing key. A throwaway constant, not a secret: it signs only
#: hashes of transactions on a chain that does not exist. A deployment holds its
#: key in a KMS behind the same ``SignerProvider`` contract (ADR 0007).
_DEMO_KEY = bytes.fromhex("11" * 32)

#: Who can answer a review in the panel. The agent is listed on purpose — trying
#: to approve as the proposer is the maker-checker demonstration.
CHECKERS: tuple[tuple[str, str], ...] = (
    ("ops-human", "Ops (a different person)"),
    ("finance-lead", "Finance lead (a different person)"),
    (AGENT, "The agent itself (the maker)"),
)


@dataclass
class Knobs:
    """The policy configuration the panel exposes."""

    approval_cap: int = 50 * USDC
    review_above: int | None = 5 * USDC
    approve_spender_allowlist: frozenset[str] = frozenset()


class Session:
    """Holds the world, the knobs and a real co-signer over both."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.world = World.pristine()
        self.knobs = Knobs()
        self._audit_sink = InMemoryAuditSink()
        self._cosigner = self._build()

    # -- construction ----------------------------------------------------

    def _build(self) -> OnchainCosigner:
        """A co-signer over the current knobs and a live view of the world."""
        return OnchainCosigner(
            LocalSigner(_DEMO_KEY),
            SafeContext(safe_address=SAFE, chain_id=self.world.expected.chain_id),
            approval_cap=self.knobs.approval_cap,
            reader=_LiveReader(self.world) if self.world.reader_wired else None,
            expected=self.world.expected,
            review_above=self.knobs.review_above,
            approve_spender_allowlist=self.knobs.approve_spender_allowlist,
            audit_sink=self._audit_sink,
        )

    def _rebuild(self) -> None:
        """Rebuild the co-signer, dropping held reviews.

        Needed only when a constructor argument changes — the knobs, or the
        reader being unwired. An ordinary tamper does *not* rebuild, because the
        live reader already exposes it and the held queue is worth keeping.
        """
        self._cosigner = self._build()

    # -- actions ---------------------------------------------------------

    def propose(
        self, call: SafeCall, *, proposer: str = AGENT
    ) -> tuple[CosignOutcome, trace_module.Trace]:
        """Judge one proposal. The outcome is the co-signer's; the trace observes."""
        with self._lock:
            outcome = self._cosigner.cosign(call, proposer=proposer, now=_now())
            reader = self.world.reader()
            observed = trace_module.observe(
                call,
                outcome,
                safe_address=SAFE,
                reader=reader,
                expected=self.world.expected if reader is not None else None,
                approval_cap=self.knobs.approval_cap,
                review_above=self.knobs.review_above,
                approve_spender_allowlist=self.knobs.approve_spender_allowlist,
                token_allowlist=frozenset({TOKEN}),
            )
            return outcome, observed

    def resolve(
        self, approval_id: str, *, checker: str, approved: bool
    ) -> tuple[CosignOutcome, trace_module.Trace]:
        """Answer a held review as ``checker``.

        Approving as the proposer is refused by the shared maker-checker — that
        refusal is the point of letting the panel choose an identity at all.
        """
        with self._lock:
            verdict = CheckerVerdict(
                checker=CheckerIdentity(subject=checker),
                approval_id=approval_id,
                proposal=ProposalDigest(value=approval_id),
                approved=approved,
            )
            outcome = self._cosigner.resolve(approval_id, verdict, now=_now())
            reader = self.world.reader()
            observed = trace_module.observe_resolution(
                outcome,
                safe_address=SAFE,
                reader=reader,
                expected=self.world.expected if reader is not None else None,
                checker=checker,
                approved=approved,
            )
            return outcome, observed

    def tamper(self, what: Tamper) -> None:
        with self._lock:
            self.world.tamper(what)
            if what is Tamper.unwire_reader:
                # The reader is a constructor argument; unwiring it is the one
                # tamper the live view cannot express.
                self._rebuild()

    def repair(self) -> None:
        with self._lock:
            was_unwired = not self.world.reader_wired
            self.world.repair()
            if was_unwired:
                self._rebuild()

    def reconfigure(
        self,
        *,
        approval_cap: int | None = None,
        review_above: int | None = None,
        vouch_spender: str | None = None,
        unvouch_spender: str | None = None,
    ) -> None:
        with self._lock:
            if approval_cap is not None:
                self.knobs.approval_cap = approval_cap
            if review_above is not None:
                self.knobs.review_above = review_above or None
            if vouch_spender:
                self.knobs.approve_spender_allowlist |= {vouch_spender.lower()}
            if unvouch_spender:
                self.knobs.approve_spender_allowlist -= {unvouch_spender.lower()}
            self._rebuild()

    def reset(self) -> None:
        with self._lock:
            self.world = World.pristine()
            self.knobs = Knobs()
            self._audit_sink = InMemoryAuditSink()
            self._cosigner = self._build()

    # -- reads -----------------------------------------------------------

    def open_reviews(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "approval_id": approval.approval_id,
                # Shortened for the card: the maker is an address, and the full
                # 42 characters push the approve/decline buttons off the panel.
                "maker": _short(approval.maker.subject),
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else "—",
            }
            for approval in self._cosigner.open_reviews()
        )

    def audit_tail(self, limit: int = 12) -> tuple[dict[str, str], ...]:
        entries = self._audit_sink.entries()[-limit:]
        return tuple(
            {
                "sequence": str(receipt.sequence),
                "digest": receipt.digest.value[:16] + "…",
                # ``DecisionVerdict`` is an IntEnum ordered by strictness, so
                # ``.value`` is 0/1/2 — the name is what a reader of the trail
                # needs, and what the page styles on.
                "verdict": receipt.verdict.name,
                "approval_id": (receipt.approval_id or "—")[:16],
                "receipt_hash": receipt.receipt_hash[:12] + "…",
            }
            for receipt in reversed(entries)
        )

    @property
    def cosigner_address(self) -> str:
        return self._cosigner.address


class _LiveReader:
    """A ``ChainStateReader`` that reads the world at call time, not at wiring time.

    Snapshotting here would make the panel *less* faithful, not more: the real
    co-signer reads the chain afresh on every ``cosign`` and every ``resolve``,
    and a chain that cannot move between those two reads cannot demonstrate why
    the second read exists.
    """

    def __init__(self, world: World) -> None:
        self._world = world

    def read_safe(self, safe_address: str) -> SafeChainState:
        return self._world.live

    def token_identity(self, token_address: str) -> TokenIdentity:
        if token_address.lower() != TOKEN.lower():
            raise KeyError(token_address)
        return self._world.live_token


def _short(subject: str) -> str:
    """An address abbreviated for display; any other subject left alone."""
    if subject.startswith("0x") and len(subject) > 16:
        return f"{subject[:10]}…{subject[-6:]}"
    return subject


def _now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["CHECKERS", "CosignStatus", "Knobs", "Session"]
