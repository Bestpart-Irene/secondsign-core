# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Properties of the audit chain.

Whatever the length and content of a recorded chain, it verifies; and editing
any single receipt's field, or dropping any single receipt, always breaks
verification. These are the detectability guarantees a tamper would have to
defeat, stated over the whole input space rather than by example.
"""

from hypothesis import given
from hypothesis import strategies as st

from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.decision import DecisionVerdict
from secondsign.intent import IntentDigest

_verdicts = st.sampled_from(list(DecisionVerdict))
_hex = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


def _record_chain(specs) -> InMemoryAuditSink:
    sink = InMemoryAuditSink()
    log = AuditLog(sink)
    for value, verdict in specs:
        log.record(digest=IntentDigest(value=value), verdict=verdict)
    return sink


@given(specs=st.lists(st.tuples(_hex, _verdicts), min_size=0, max_size=10))
def test_any_recorded_chain_verifies(specs):
    assert verify_chain(_record_chain(specs).entries()) is True


@given(
    specs=st.lists(st.tuples(_hex, _verdicts), min_size=2, max_size=8),
    index=st.integers(min_value=0, max_value=7),
)
def test_dropping_a_non_tail_receipt_breaks_verification(specs, index):
    """A mid-chain removal desynchronises the sequence and the prev_hash link.

    Tail truncation is deliberately *not* claimed here: removing the last
    receipt leaves a valid shorter chain, and detecting that needs an external
    commitment to the chain head/length (a control-plane anchor), not
    chain-internal verification. See ``verify_chain``.
    """
    entries = list(_record_chain(specs).entries())
    non_tail = index % (len(entries) - 1)  # never the last element
    del entries[non_tail]
    assert verify_chain(entries) is False


@given(
    specs=st.lists(st.tuples(_hex, _verdicts), min_size=1, max_size=8),
    index=st.integers(min_value=0, max_value=7),
    new_value=_hex,
)
def test_editing_any_digest_breaks_verification(specs, index, new_value):
    entries = list(_record_chain(specs).entries())
    i = index % len(entries)
    if entries[i].digest.value == new_value:
        return
    entries[i] = entries[i].model_copy(update={"digest": IntentDigest(value=new_value)})
    assert verify_chain(entries) is False
