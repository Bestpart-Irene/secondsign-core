<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/secondsign-wordmark-dark.png">
    <img src="docs/assets/secondsign-wordmark.png" alt="SecondSign" width="320">
  </picture>
</p>

<p align="center"><b>An independent transaction co-signer for AI agents that manage other people's money.</b><br>
An out-of-mandate transaction is never signed, so it never happens — and every
decision leaves evidence the operator could not have written for itself.</p>

<p align="center">
  <a href="https://pypi.org/project/secondsign-core/"><img alt="PyPI" src="https://img.shields.io/pypi/v/secondsign-core.svg"></a>
  <a href="https://github.com/Bestpart-Irene/secondsign-core/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Bestpart-Irene/secondsign-core/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="Licence: Apache-2.0" src="https://img.shields.io/badge/licence-Apache--2.0-green.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
  <a href="docs/INVARIANTS.md"><img alt="Guarantees" src="https://img.shields.io/badge/guarantees-test--enforced-green.svg"></a>
  <a href="https://discord.gg/yQHfJGSmXn"><img alt="Discord" src="https://img.shields.io/badge/chat-Discord-5865F2.svg"></a>
</p>

---

## See it run

One screen, three vantage points: the agent that proposes, the human who
decides, and the money that only moves when both sides of the boundary agree.

```text
┌──────────────────────────────┬──────────────────────────────┐
│ ① the agent's terminal       │ ② the approver's browser      │
│                              │                               │
│ $42 payment                  │   SecondSign · open reviews   │
│ → completed ✓                │  ┌─────────────────────────┐  │
│                              │  │ $300.00 · held for review│  │
│ $300 payment                 │  │ to fp:abab…              │  │
│ → awaiting_review ⏸          │  │   [Approve]  [Decline]   │  │
│   (parked for a human)       │  └─────────────────────────┘  │
│ → completed ✓ on approval    │                               │
│                              │                               │
│ $900 payment                 │                               │
│ → refused ✗ (over the cap)   │                               │
├──────────────────────────────┴──────────────────────────────┤
│ ③ the rail's own ledger, live                                │
│   14:02:11  request #1 arrived   via=gateway                 │
│   14:02:39  request #2 arrived   via=gateway    (and no #3)  │
└─────────────────────────────────────────────────────────────┘
```

The agent container in ① holds **no payment credential and no network route
to the rail** — its only way to money is a proposal to the gateway. The panel
in ② talks to the gateway over a **second mTLS channel with its own CA and
its own network**, which the agent cannot reach. The ledger in ③ is read at
the destination, because "my attempt failed" and "nothing arrived" are
different statements.

### Install

```bash
pip install secondsign-core            # the engine (Python 3.11+)
pip install "secondsign-core[stripe]"  # plus the Stripe rail driver
```

### Run the quickstart (no Docker)

The whole decision path in one script — three proposals through the *real*
gateway `authorize()` / `resolve()`, on a mock rail that moves no money:

```bash
pip install secondsign-core
python examples/quickstart.py     # one script, imports only the public API
```

```text
  agent proposes  $42    →   completed        ✓  money moved (mock)
  agent proposes  $300   →   awaiting_review  ⏸  parked for a human
    approver clicks Approve →   executed         ✓  money moved (mock)
  agent proposes  $900   →   refused          ✗  value_band_exceeded
```

[`examples/quickstart.py`](examples/quickstart.py) is self-contained on the
public API — clone the repo to run it, or copy it anywhere. For the
production-faithful topology — two networks, mTLS, the agent in its own
container with no rail code — run the demo below.

### Run the demo (Docker required)

```bash
git clone https://github.com/Bestpart-Irene/secondsign-core
cd secondsign-core/deploy/reference

python tls/generate.py                 # ephemeral two-CA PKI, never committed
docker compose -f compose.yaml -f compose.demo.yaml up --build -d

# ② open http://127.0.0.1:8090        — the approver panel
python demo/run_demo.py                # ① three proposals: $42 / $300 / $900
python demo/watch.py                   # ③ the rail's ledger, live

docker compose -f compose.yaml -f compose.demo.yaml down -v
```

The $300 proposal will sit at `awaiting_review` until you press **Approve**
in the panel — then the agent's own re-send of the same handle reads
`completed`, and one request appears on the ledger. Decline it instead and
nothing moves. Details and the security properties of the topology:
[`deploy/reference/`](deploy/reference/).

## Why this exists

Give an AI agent a payment tool and you have given it the ability to lose real
money. A bad sentence can be retracted with an apology; a wrong wire cannot.

The usual answers are a better prompt, an eval suite, and a safety function the
agent is told to call first. All three share one flaw: **the agent decides
whether to obey them.** Anything an agent can skip is not a control.

SecondSign takes that decision away from the agent.

And when the money an agent moves is not its operator's own — a client's
treasury, user balances, a fund's capital — solving that first problem exposes
a second one: **the owner of the money will eventually ask the operator to
prove the agent stayed inside what was authorized.** Logs written by the same
system that made the mistake do not answer that question; they are the
operator grading its own homework. An independent co-signer answers it
structurally: a transaction outside the mandate is never signed, so it never
happens, and the trail of signed verdicts is evidence the operator could not
have manufactured.

## What it is

A gate that sits on the execution path. The agent can *ask* for money to move.
Only SecondSign can *make* it move.

The agent holds no bank, broker or processor credential, and has no network
route to them. Its only route to the money is a request to SecondSign, and
SecondSign answers it the same way every time.

> **The test that falsifies a deployment:** turn SecondSign off. If the agent
> can still move money, you have not installed a boundary — you have installed a
> library it is free to skip.

**There is now a deployment that passes that test, and running core in-process
still does not.** [`CORE-S019`](docs/slices/roadmap.yaml) builds the shape — a
standalone gateway process holding the credentials, the agent on the other side
of a process boundary with a client distribution that contains no rail code at
all — and [`deploy/reference/`](deploy/reference/) is a two-network topology you
can copy. CI stands it up, runs an adversarial suite *inside* the agent
container written against the standard library rather than against the client,
and then re-runs that suite against a deliberately joined topology and requires
it to fail there, because a gate that cannot be made to fail is not evidence.

Installed the other way — the library imported into your agent's process — it is
still a control your own code chooses to route through, and the falsification
test still fails. That is right for development and evaluation, and it is not
production custody of money. [Status](#status) says what is left.

## What happens to a request

```text
financial agent
      │  "pay invoice 4471, $2,500, to a new supplier"
      ▼
  IntentAdapter        trust boundary — raw account and customer data stop here
      │
      ▼
  TransactionIntent    immutable; fingerprints and whole cents, never a card number
      │
      ▼
  Policy → Decision    ALLOW / REVIEW / DENY — combining can only tighten
      │           └── REVIEW → MakerChecker: a human, one shot, expiring
      ▼
  ExecutionGateway     re-checks the request is still the approved one, then sends it once
      │
      ▼
  AuditReceipt         redacted, hash-chained — a later edit is detectable
```

In plain terms:

1. **Adapter.** The agent's tool call becomes a structured, immutable request.
   Account numbers and customer records cannot cross this line; amounts are
   whole cents, never floats.
2. **Decision.** Your rules return allow, hold for review, or deny. Run ten
   rules and they can only make the answer stricter — no rule can overrule
   another one's "no", and no rule can grant permission.
3. **Human approval, when it is warranted.** The approval is one-shot, expires,
   and is bound to that exact request. Approve a $2,500 invoice and nothing else
   can ride on that approval.
4. **Execution.** Right before sending, the gateway re-checks that the request
   is byte-for-byte the one that was approved, then sends it exactly once — with
   an idempotency key SecondSign derives, never one the agent supplies.
5. **Receipt.** What was decided, who approved it, what happened. Redacted, and
   chained by hash so tampering shows.

## Try it

```bash
pip install secondsign-core          # the engine
pip install "secondsign-core[stripe]" # plus the Stripe rail
```

```python
from datetime import datetime, timedelta, timezone

from secondsign.adapters import StripeAdapter, StripeCall
from secondsign.contracts import Currency, SourceTrust
from secondsign.decision import DecisionEngine
from secondsign.intent import PaymentTargetKind, SettlementPriority
from secondsign.policy import (
    AggregateKey,
    AmountLimit,
    AmountWindowPolicy,
    PolicyContext,
    WindowAggregate,
)

now = datetime.now(timezone.utc)

# 1. The agent asks to pay. The adapter turns the tool call into an immutable
#    request — account identifiers never enter, only fingerprints of them.
call = StripeCall(
    counterparty_ref="fp:" + "a1" * 32,
    source_account_ref="fp:" + "b2" * 32,
    not_before=now,
    not_after=now + timedelta(minutes=5),
    declared_source_trust=SourceTrust.trusted_instruction,
    scope_count=1,
    amount_minor=250_000,  # $2,500.00 — always integer minor units
    quote_currency=Currency.USD,
    target_kind=PaymentTargetKind.bank_account,
    new_beneficiary=True,
    cross_border=False,
    settlement_priority=SettlementPriority.standard,
)
intent = StripeAdapter().derive(call)

# 2. Your rule: at most $1,000 an hour to this counterparty.
policy = AmountWindowPolicy(
    AmountLimit(quote_currency=Currency.USD, window_seconds=3600, max_aggregate_minor=100_000)
)
context = PolicyContext(
    window_aggregate=WindowAggregate(
        key=AggregateKey.from_intent(intent),
        window_seconds=3600,
        aggregate_minor=0,  # nothing spent in this window yet
        count=0,
    )
)

# 3. The decision.
decision = DecisionEngine([policy]).decide(intent, context)
print(decision.verdict.name, [reason.value for reason in decision.reasons])
# DENY ['value_band_exceeded']
```

That is the decision primitive in isolation. The full path — proposed, held,
approved by a second human, executed, and receipted — runs in
[`examples/quickstart.py`](examples/quickstart.py) (no Docker), and is proven
against real test-mode Stripe in
[`tests/e2e/test_vertical_path.py`](tests/e2e/test_vertical_path.py).

## When the agent holds a wallet

The same engine governs a second execution domain: an agent whose rail is a
blockchain account. The account is a [Safe](https://safe.global) smart account
owned 2-of-2 — the agent's key and SecondSign's co-signer — so the co-signer's
signature **is** the ALLOW verdict. A refused proposal is simply never signed,
and a transaction with one signature of two cannot execute. There is no
separate enforcement step for the agent to skip.

Before it signs anything, the co-signer re-reads the Safe's live state —
owners, threshold, guard, nonce — and the token's on-chain identity, and
refuses on any drift from what was configured. The signing key sits behind a
provider contract, never in the co-signer itself. And on the chain, a pair of
Solidity guards (a transaction guard and a module guard, Safe 1.5.0, under
[`onchain/`](onchain/)) refuse by revert any transaction that would change the
account's control — replace the guard, change owners or threshold, enable a
module, delegatecall — on **both** Safe execution paths. The guards judge
integrity only, never value: amounts and counterparties are the co-signer's
decision, made off-chain by the same deterministic engine as everything above.

SecondSign is not a wallet and takes no custody — it holds one key of two, and
the account is yours: no funds move onto anyone's platform in order to be
protected. It issues no token, and no authorization may ever depend on holding
one.

Watch the co-signer at work against a real Safe on a local chain (needs
[Foundry](https://getfoundry.sh)):

```bash
python examples/onchain_firewall_demo.py --out /tmp/ss-demo
```

Four proposals: a small transfer is co-signed and the USDC moves; a large one
is held for a human and executes on approval; an unlimited `approve` to an
unvouched spender gets no signature; and the agent's own attempt to remove
SecondSign (`setGuard(0)`) gets no signature either. Every verdict and
signature comes from the actual co-signer — only the ERC-20 is a local
stand-in.

This domain is younger than the fiat path and says so plainly: the contracts
are unaudited, nothing has run beyond a local chain, and [Status](#status)
names the rest. What it defends against, and why each rule exists:
[On-chain threat model](docs/ONCHAIN_THREAT_MODEL.md).

## What it guarantees

Each of these is a promise bound to the test that enforces it. See
[Invariants](docs/INVARIANTS.md).

- **Fail closed.** Anything unclear, missing or unavailable takes the strictest
  path. Silence is never consent.
- **Only ever stricter.** More rules, plugins or enterprise extensions can
  tighten a decision. Nothing can loosen one.
- **What was decided is what gets executed.** Bound by a digest, re-verified in
  the instant before dispatch.
- **Approvals are single-use.** Tied to one request, with an expiry.
- **Credentials never leave the gateway.** They cannot appear in a request, a
  receipt, a plugin's input, or an error message.
- **No raw financial or customer data** in decisions, receipts or logs.
- **Deterministic.** No model sits on the live decision path. The same request
  gets the same answer, and you can explain that answer to an auditor.

## Who it is for

The sharpest fit is a team whose agents control money that belongs to someone
else — where the capital's owner can ask, at any moment: *prove the agent
stayed inside what I authorized*.

- An operator running treasury, trading or DeFi agents over a client's or a
  fund's capital.
- An agentic-commerce or payments team whose agents touch user or merchant
  balances.
- A company selling agents into enterprises, where the deal stalls on *how
  would we ever let this near production money?* — "every financial action
  passes an independent co-signer the agent cannot bypass" is the answer that
  unblocks it.
- A fintech or vertical SaaS shipping agent features that need a control an
  auditor will accept.

The same boundary also protects a team spending its own budget from a
prompt-injected or simply wrong agent — that is where many deployments start.
It is **not** a wallet, a model-safety layer, a prompt filter, or an agent
framework. It has one job, at one moment: the instant before money moves.

## Open core

| | |
|---|---|
| **SecondSign Core** — this repository, Apache-2.0 | The decision path: contracts, intent, policy, decision, human approval, gateway, local audit, rail adapters, and the conformance kits third parties test against. Useful on its own, and it always will be — this is not a crippled edition. |
| **SecondSign Enterprise** — separate, commercial | Organisational scale: hosted runtime and control plane, multi-tenancy, org-wide policy, centralised audit, remote approvals, SSO/RBAC, compliance workflows, and attestation that a deployment really is what it claims. |

Two rules hold that line: core never depends on anything private, and an
enterprise extension may only make a decision stricter — never grant a
permission core would have refused.

The split follows the trust model, not a feature ledger. The open core is the
whole mechanism, and operated by your own team it is a strong internal
control — but a co-signer you run yourself is still your own word, which your
clients, auditors and insurers must take on faith. *Independence* — the
co-signer operated by a party the agent's operator does not control, under a
policy the capital owner is party to and that can only ever be tightened — is
a property of who runs a deployment, never of code. That independently
operated form is what the commercial layer exists to be: independence cannot
be self-hosted.

Extensions — a new rail, a policy plugin, an approval provider — prove they are
safe by inheriting a conformance test suite, not by persuading a maintainer.
See [Extension contracts](docs/EXTENSION_CONTRACTS.md).

## Status

Pre-1.0. Interfaces may still change.

**Built and tested:** the whole decision path end to end — contracts and the
plugin boundary, intent, policy, the decision engine, maker-checker approval,
the execution gateway, the hash-chained audit receipt, Stripe and Alpaca
adapters, the conformance kits, and an adversarial matrix run against the threat
model. Around it, the deployment shape: the standalone gateway process, the
credential-free client distribution, the reference two-network topology, and a
held `REVIEW` that reaches a human on a second mTLS channel the agent has no
route to — and comes back as an executed payment when, and only when, that
human approves. On the wallet side: the Safe co-signer path with live-chain
re-verification before every signature, the signing key behind a provider
contract, the constitutional double guard in Solidity, and a timelocked,
account-vetoable recovery path for a lost co-signer key. Branch coverage is
100%, enforced by CI rather than asserted here — but read that as an
engineering signal, not as evidence of security. It says every branch was
executed by some test. It does not say the tests assert the right things, and
it is not a substitute for the independent review this project has not yet had.

**Not there yet:** named rather than rounded off. The control-plane state the
gateway keeps (the principal fingerprint key, the spend window, pending
reviews) lives in the process, so a restart forgets it. Spending limits are a
constant in the gateway rather than state under an auditable authority. And
the on-chain path is younger than the fiat one: the contracts have had no
independent audit, nothing has run beyond a local chain, and the decided
effect is still read from calldata rather than from simulation. Running the library
inside your agent's process remains right for development and testing, not for
production custody of money.

Where each queued slice actually stands, derived from Git rather than
hand-maintained: [`docs/slices/STATUS.md`](docs/slices/STATUS.md).

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | What core is, and what it deliberately is not |
| [Threat model](docs/THREAT_MODEL.md) | What this defends against, and why each rule exists |
| [On-chain threat model](docs/ONCHAIN_THREAT_MODEL.md) | What changes when the agent holds a wallet, and what the guards must hold |
| [Invariants](docs/INVARIANTS.md) | The guarantees, each bound to the test that enforces it |
| [Extension contracts](docs/EXTENSION_CONTRACTS.md) | How to add a rail, rule or provider and certify it |
| [Contributing](CONTRIBUTING.md) | The slice protocol and quality gates |
| [Governance](GOVERNANCE.md) | Who decides what, and how little needs deciding |
| [Security](SECURITY.md) | How to report a vulnerability, privately |
| [Support](SUPPORT.md) | Where to start reading, building, and asking |
| [Releasing](docs/RELEASING.md) | How a version reaches PyPI |
| [Changelog](CHANGELOG.md) | What changed in each release |
| [Roadmap](docs/slices/roadmap.yaml) | The build queue, machine-validated |
| [Status](docs/slices/STATUS.md) | Where each slice stands, derived from Git |

Everything needed to build on or contribute to this project is in this
repository. Nothing here depends on a private one.

## Community

[Discord](https://discord.gg/yQHfJGSmXn) — questions while you are building,
and what people are building with it. Issues and Discussions remain the durable
record; chat is for the parts that never make it into either.

## Provenance

SecondSign Core is an independent implementation. Its history begins at its own
initial commit and shares no Git history with any other project.

Where another project's work informed this one, it is named in
[`NOTICE`](NOTICE) with its licence rather than left implicit — including the
architectural patterns adopted from Doberman-Core (Apache-2.0), and the handful
of explanatory comments adapted from it.

Specifications are committed before the implementations they describe, so the
commit order is itself part of the record. Every commit carries a DCO sign-off,
and any third-party source that informed a change is named in its pull request
along with the licence it carries.

## Licence

Apache-2.0. Copyright 2026 SecondSign contributors. See [`LICENSE`](LICENSE).

The licence text was fetched from
<https://www.apache.org/licenses/LICENSE-2.0.txt>.

## Contributing

Every commit requires a DCO sign-off. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
