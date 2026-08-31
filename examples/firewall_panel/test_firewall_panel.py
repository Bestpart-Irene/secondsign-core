# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The panel is a claim about the co-signer. These keep it true.

The load-bearing one is :func:`test_trace_never_disagrees_with_the_cosigner`.
The panel reconstructs its seven stations through the public API rather than
instrumenting the signing boundary, which buys the decision path immunity from
display concerns at the cost of a drift risk: a reconstruction can diverge from
what the co-signer actually did. A panel that shows confident, wrong reasoning
would be worse than one that shows none, so the reconstruction is pinned to the
real ``CosignOutcome`` over the whole scenario-by-knob matrix.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from examples.firewall_panel.scenarios import CATALOGUE, erc20_approve, erc20_transfer
from examples.firewall_panel.session import Session
from examples.firewall_panel.trace import INERT, REFUSE, SKIPPED
from examples.firewall_panel.world import AGENT, ATTACKER, CLOUDFLARE, TOKEN, USDC, Tamper, World

#: Knob settings the matrix is swept over. Each moves a band boundary or opens a
#: fail-closed allowlist, so scenarios change fate between them.
_KNOBS = (
    {},
    {"approval_cap": 1 * USDC},
    {"approval_cap": 10_000 * USDC},
    {"review_above": 0},
    {"review_above": 1_000 * USDC},
    {"vouch_spender": ATTACKER},
    {"approval_cap": 2 * USDC, "review_above": 1 * USDC},
)


def _session(**knobs) -> Session:
    session = Session()
    if knobs:
        session.reconfigure(**knobs)
    return session


# -- 1. the consistency control ------------------------------------------------


@pytest.mark.parametrize("knobs", _KNOBS, ids=lambda k: ",".join(k) or "defaults")
@pytest.mark.parametrize("scenario", CATALOGUE, ids=lambda s: s.key)
def test_trace_never_disagrees_with_the_cosigner(scenario, knobs) -> None:
    """What the panel's reconstruction implies is what the co-signer decided."""
    outcome, observed = _session(**knobs).propose(scenario.call)
    assert observed.implied == outcome.status.value


@pytest.mark.parametrize("tamper", list(Tamper), ids=lambda t: t.value)
def test_trace_agrees_with_the_cosigner_on_a_broken_account(tamper) -> None:
    """The same equality has to hold on the refusal-before-judging path."""
    session = Session()
    session.tamper(tamper)
    outcome, observed = session.propose(CATALOGUE[0].call)
    assert observed.implied == outcome.status.value == "refused"


# -- 2. tampering ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        (Tamper.remove_guard, "structural_change"),
        (Tamper.swap_owner, "structural_change"),
        (Tamper.lower_threshold, "structural_change"),
        (Tamper.counterfeit_token, "implementation_moved"),
        (Tamper.wrong_chain, "replayed_signature"),
    ],
)
def test_each_tamper_produces_its_own_drift(tamper, reason) -> None:
    world = World.pristine()
    world.tamper(tamper)
    drift = world.expected.mismatches(world.live, world.live_token)
    assert [code.value for code in drift] == [reason]


def test_a_pristine_account_has_no_drift() -> None:
    world = World.pristine()
    assert world.expected.mismatches(world.live, world.live_token) == ()


def test_an_unwired_reader_refuses_rather_than_trusting_the_caller() -> None:
    session = Session()
    session.tamper(Tamper.unwire_reader)
    outcome, observed = session.propose(CATALOGUE[0].call)
    assert outcome.status.value == "refused"
    # Everything after the failed re-verification must be marked unreached, not
    # quietly rendered as though it had passed.
    assert observed.stations[0].state == REFUSE
    assert [s.state for s in observed.stations[1:4]] == [SKIPPED] * 3


def test_a_broken_account_refuses_a_transfer_that_would_otherwise_be_signed() -> None:
    """The demonstration itself: the same proposal, before and after the break."""
    session = Session()
    assert session.propose(CATALOGUE[0].call)[0].status.value == "signed"
    session.tamper(Tamper.remove_guard)
    assert session.propose(CATALOGUE[0].call)[0].status.value == "refused"
    session.repair()
    assert session.propose(CATALOGUE[0].call)[0].status.value == "signed"


# -- 3. the catalogue tells the truth -------------------------------------------


@pytest.mark.parametrize("scenario", CATALOGUE, ids=lambda s: s.key)
def test_each_preset_produces_the_verdict_its_label_advertises(scenario) -> None:
    outcome, _ = Session().propose(scenario.call)
    assert outcome.status.value == scenario.claims


@pytest.mark.parametrize("scenario", [s for s in CATALOGUE if s.claims_reason], ids=lambda s: s.key)
def test_each_preset_produces_the_reason_its_label_implies(scenario) -> None:
    outcome, _ = Session().propose(scenario.call)
    reasons = [f.code.value for f in (outcome.judgement.findings if outcome.judgement else ())]
    assert scenario.claims_reason in reasons


def test_the_guard_station_is_never_claimed_as_executed() -> None:
    """The Solidity guards are rendered, not run. Saying otherwise would be the
    one dishonesty this panel could commit."""
    _, observed = Session().propose(CATALOGUE[0].call)
    guard = observed.stations[-1]
    assert guard.key == "guard"
    assert guard.state == INERT


# -- 4. maker-checker ------------------------------------------------------------


def _held(session: Session) -> str:
    outcome, _ = session.propose(next(s for s in CATALOGUE if s.claims == "held").call)
    assert outcome.approval_id is not None
    return outcome.approval_id


def test_the_proposer_cannot_approve_its_own_proposal() -> None:
    session = Session()
    approval_id = _held(session)
    outcome, _ = session.resolve(approval_id, checker=AGENT, approved=True)
    assert outcome.status.value == "refused"
    assert outcome.signature is None


def test_a_different_principal_can_approve_and_the_signature_appears() -> None:
    session = Session()
    approval_id = _held(session)
    outcome, _ = session.resolve(approval_id, checker="ops-human", approved=True)
    assert outcome.status.value == "signed"
    assert outcome.signature and outcome.signature.startswith("0x")


def test_a_decline_leaves_no_signature() -> None:
    session = Session()
    approval_id = _held(session)
    outcome, _ = session.resolve(approval_id, checker="ops-human", approved=False)
    assert outcome.status.value == "refused"
    assert outcome.signature is None


def test_an_account_broken_while_a_human_decides_refuses_the_approval() -> None:
    """``resolve`` re-verifies, so a real approval of a real review still fails
    when the account moved underneath it — and the human's answer is not burnt."""
    session = Session()
    approval_id = _held(session)
    session.tamper(Tamper.remove_guard)
    refused, observed = session.resolve(approval_id, checker="ops-human", approved=True)
    assert refused.status.value == "refused"
    assert observed.stations[0].state == REFUSE
    session.repair()
    recovered, _ = session.resolve(approval_id, checker="ops-human", approved=True)
    assert recovered.status.value == "signed"


def test_the_resolution_trace_does_not_replay_the_proposal_stations() -> None:
    """Only ①, ⑤ and ⑥ are live on an answer; rendering all seven would leave a
    stale PASS under a fresh refusal."""
    session = Session()
    approval_id = _held(session)
    _, observed = session.resolve(approval_id, checker="ops-human", approved=True)
    assert [station.ordinal for station in observed.stations] == ["①", "⑤", "⑥"]


# -- 5. knobs actually move the boundary ------------------------------------------


def test_lowering_the_cap_turns_a_signed_transfer_into_a_refusal() -> None:
    call = CATALOGUE[0].call
    assert Session().propose(call)[0].status.value == "signed"
    assert _session(approval_cap=1 * USDC).propose(call)[0].status.value == "refused"


def test_vouching_for_a_spender_admits_an_approval_the_allowlist_had_refused() -> None:
    """The allowlist is the *only* thing that admits an approval, and it is
    empty until somebody deliberately vouches. The amount here is under the
    review band, so once the spender is vouched for the approval signs
    outright — the refusal was never about the magnitude."""
    call = next(s for s in CATALOGUE if s.key == "bounded_approval").call
    assert Session().propose(call)[0].status.value == "refused"
    session = _session(vouch_spender=ATTACKER)
    assert session.propose(call)[0].status.value == "signed"


def test_the_panel_reimplements_no_policy() -> None:
    """A guard against the slice's own forbidden list: the panel must not carry a
    threshold, band or refusal of its own."""
    from examples.firewall_panel import scenarios, session, trace, world

    for module in (scenarios, session, trace, world):
        source = module.__file__
        assert source is not None
        text = open(source, encoding="utf-8").read()  # noqa: SIM115, PTH123
        assert "OnchainVerdict.DENY" not in text, f"{module.__name__} decides a verdict"
        assert "def evaluate" not in text, f"{module.__name__} reimplements a policy"


# -- 6. the HTTP surface -----------------------------------------------------------


@pytest.fixture
def panel_url():
    from examples.firewall_panel import server as server_module

    server_module.SESSION = Session()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 — loopback
        return json.load(response)


def _post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(  # noqa: S310 — loopback
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return json.load(response)


def test_the_page_and_its_assets_are_served(panel_url) -> None:
    for path in ("/", "/static/panel.css", "/static/panel.js"):
        with urllib.request.urlopen(panel_url + path, timeout=5) as response:  # noqa: S310
            assert response.status == 200
            assert response.read()


def test_state_carries_what_the_page_needs(panel_url) -> None:
    state = _get(panel_url + "/api/state")
    assert {"safe", "tampers", "knobs", "reviews", "audit", "scenarios"} <= set(state)
    assert len(state["scenarios"]) == len(CATALOGUE)
    assert len(state["tampers"]) == len(Tamper)


def test_proposing_over_http_returns_the_cosigner_verdict(panel_url) -> None:
    payload = _post(panel_url + "/api/propose", {"scenario": "unlimited_approval"})
    assert payload["outcome"]["status"] == "refused"
    assert "unbounded_approval" in payload["outcome"]["reasons"]
    assert len(payload["stations"]) == 7


def test_the_audit_trail_names_its_verdicts_in_words(panel_url) -> None:
    """``DecisionVerdict`` is an IntEnum, so a trail that serialised ``.value``
    would show 0/1/2 to a human reading the evidence."""
    _post(panel_url + "/api/propose", {"scenario": "unlimited_approval"})
    audit = _get(panel_url + "/api/state")["audit"]
    assert audit and audit[0]["verdict"] in {"ALLOW", "REVIEW", "DENY"}


def test_a_bad_request_is_an_error_not_a_plausible_verdict(panel_url) -> None:
    with pytest.raises(urllib.error.HTTPError) as raised:
        _post(panel_url + "/api/propose", {"scenario": "no-such-scenario"})
    assert raised.value.code == 400


def test_tampering_over_http_shows_up_in_the_account(panel_url) -> None:
    state = _post(panel_url + "/api/tamper", {"tamper": "remove_guard"})["state"]
    assert state["safe"]["transaction_guard"] == "0x" + "0" * 40
    restored = _post(panel_url + "/api/tamper", {"repair": True})["state"]
    assert restored["safe"]["transaction_guard"] != "0x" + "0" * 40


def test_custom_calldata_helpers_decode_to_what_they_claim(panel_url) -> None:
    """The two helpers build the calldata the whole catalogue rests on."""
    from examples.firewall_panel.world import SAFE
    from secondsign.onchain.effect import SafeAdapter, SafeCall, SafeOperation

    adapter = SafeAdapter(SAFE)
    transfer = adapter.decode(
        SafeCall(
            to=TOKEN,
            value=0,
            data=erc20_transfer(CLOUDFLARE, 7 * USDC),
            operation=SafeOperation.call,
        )
    )
    assert transfer.kind.value == "erc20_transfer"
    assert transfer.amount == 7 * USDC
    assert transfer.counterparty.lower() == CLOUDFLARE.lower()

    approval = adapter.decode(
        SafeCall(to=TOKEN, value=0, data=erc20_approve(ATTACKER, 3), operation=SafeOperation.call)
    )
    assert approval.kind.value == "erc20_approval"
    assert approval.amount == 3
