# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Fixtures that assemble the whole decision path for the end-to-end tests.

This is the first place every component meets: a Stripe tool call becomes an
intent (S008), a policy sends it to review (S009/S010), a maker-checker approves
it (S011), the gateway executes it exactly once (S012), and the audit chain
records the result (S013). The Stripe rail itself is faked here so the path can
be exercised in CI without a network or a credential; the live rail is
`test_stripe_live.py`.
"""

import ssl
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from secondsign.adapters import StripeAdapter, StripeCall
from secondsign.approval import CheckerIdentity, CheckerVerdict, MakerChecker, MakerIdentity
from secondsign.contracts import (
    Currency,
    Finding,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
    SourceTrust,
)
from secondsign.intent import PaymentTargetKind, SettlementPriority

#: The three spellings of one fact: the handshake yielded no service.
#:
#: Under TLS 1.3 the server learns about the missing or untrusted certificate
#: only after its own Finished flight, so it sends an alert and closes while the
#: caller is still mid-exchange. Which error the caller sees is a race it does
#: not get to pick: it reads the alert (`SSLError`), reads the close
#: (`ConnectionResetError`), or loses even that and finds its own write hitting a
#: closed socket (`BrokenPipeError`). CI's Linux runners reliably produce the
#: second; macOS produces the first usually and the third about once in
#: twenty-five runs.
#:
#: Named types, never `OSError`. The broad catch would also swallow
#: `ConnectionRefusedError` — nothing listening at all — and a suite using it
#: would then report "the gateway refused an anonymous caller" on a machine
#: where the gateway never started.
#:
#: Here rather than in one test module because three files now dial a gateway
#: that will refuse them, and the reasoning above is the part that must not be
#: re-derived — a second copy is where someone widens one of them to `OSError`.
NO_SERVICE = (ssl.SSLError, ConnectionResetError, BrokenPipeError)

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
NOT_AFTER = _EPOCH + timedelta(minutes=5)
NOW = _EPOCH + timedelta(minutes=1)  # inside the validity window
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32

MAKER = MakerIdentity(subject="agent-operator")
CHECKER = CheckerIdentity(subject="human-approver")


def make_stripe_call(amount_minor: int = 5_000, currency: Currency = Currency.USD) -> StripeCall:
    """A well-formed Stripe payment tool call (references already fingerprinted)."""
    return StripeCall(
        counterparty_ref=FINGERPRINT_A,
        source_account_ref=FINGERPRINT_B,
        not_before=_EPOCH,
        not_after=NOT_AFTER,
        declared_source_trust=SourceTrust.trusted_instruction,
        scope_count=1,
        amount_minor=amount_minor,
        quote_currency=currency,
        target_kind=PaymentTargetKind.bank_account,
        new_beneficiary=True,
        cross_border=False,
        settlement_priority=SettlementPriority.standard,
    )


def derive_intent(call: StripeCall | None = None):
    """The adapter step: a tool call becomes an immutable TransactionIntent."""
    result = StripeAdapter().derive(call if call is not None else make_stripe_call())
    # In these tests the call is always mappable; a RejectReason would be a bug.
    assert not hasattr(result, "code"), f"adapter rejected a valid call: {result!r}"
    return result


class LargePaymentReviewPolicy:
    """Sends any payment at or above a threshold to human review — the 'held' path."""

    def __init__(self, threshold_minor: int) -> None:
        self._threshold = threshold_minor

    def evaluate(self, intent, context) -> PluginJudgement:
        if intent.dimensions.value_upper_minor >= self._threshold:
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW,
                findings=(Finding(code=ReasonCode.new_counterparty),),
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


def approve(pending) -> CheckerVerdict:
    return CheckerVerdict(checker=CHECKER, digest=pending.digest, approved=True)


class FakeStripe:
    """A stand-in for the ``stripe`` module.

    Records the idempotency key it is called with and either returns a
    PaymentIntent-shaped object with a configured status, or raises a configured
    (real) stripe error so the executor's success/failure/unknown mapping is
    exercised end to end.
    """

    def __init__(
        self,
        *,
        status: str = "succeeded",
        pi_id: str = "pi_fake_123",
        raises: Exception | None = None,
    ) -> None:
        self._status = status
        self._pi_id = pi_id
        self._raises = raises
        self.calls: list[dict] = []
        self.PaymentIntent = _FakePaymentIntent(self)


class _FakePaymentIntent:
    def __init__(self, outer: FakeStripe) -> None:
        self._outer = outer

    def create(self, **kwargs):
        self._outer.calls.append(kwargs)
        if self._outer._raises is not None:
            raise self._outer._raises
        return SimpleNamespace(id=self._outer._pi_id, status=self._outer._status)


def new_maker_checker() -> MakerChecker:
    return MakerChecker()
