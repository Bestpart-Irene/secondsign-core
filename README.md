<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/secondsign-wordmark-dark.png">
    <img src="docs/assets/secondsign-wordmark.png" alt="SecondSign" width="360">
  </picture>
</p>

<p align="center"><b>Runtime authorization for financial AI agents.</b><br>
The gate between an AI agent and real money.</p>

<p align="center">
  <a href="https://pypi.org/project/secondsign-core/"><img alt="PyPI" src="https://img.shields.io/pypi/v/secondsign-core.svg"></a>
  <a href="https://github.com/Bestpart-Irene/secondsign-core/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Bestpart-Irene/secondsign-core/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="Licence: Apache-2.0" src="https://img.shields.io/badge/licence-Apache--2.0-green.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
  <a href="docs/INVARIANTS.md"><img alt="Guarantees" src="https://img.shields.io/badge/guarantees-test--enforced-green.svg"></a>
  <a href="https://discord.gg/yQHfJGSmXn"><img alt="Discord" src="https://img.shields.io/badge/chat-Discord-5865F2.svg"></a>
</p>

---

## Why this exists

Give an AI agent a payment tool and you have given it the ability to lose real
money. A bad sentence can be retracted with an apology; a wrong wire cannot.

The usual answers are a better prompt, an eval suite, and a safety function the
agent is told to call first. All three share one flaw: **the agent decides
whether to obey them.** Anything an agent can skip is not a control.

SecondSign takes that decision away from the agent.

## What it is

A gate that sits on the execution path. The agent can *ask* for money to move.
Only SecondSign can *make* it move.

The agent holds no bank, broker or processor credential, and has no network
route to them. Its only route to the money is a request to SecondSign, and
SecondSign answers it the same way every time.

> **The test that falsifies a deployment:** turn SecondSign off. If the agent
> can still move money, you have not installed a boundary — you have installed a
> library it is free to skip.

**Today, core does not yet pass its own test.** The deployment shape that makes
it pass — a standalone gateway process holding the credentials, with the agent
on the other side of a process boundary — is specified and queued as
[`CORE-S019`](docs/slices/roadmap.yaml), not built. Run in-process, as it ships
now, SecondSign is a control your own code chooses to route through: right for
development and evaluation, not yet for production custody of money. The rest of
this README describes what the engine does; [Status](#status) says how far the
deployment story has actually got.

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

The full path — held, approved by a second human, released through Stripe, and
receipted — is in [`tests/e2e/test_vertical_path.py`](tests/e2e/test_vertical_path.py).

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

- A team about to hand an agent a payment, treasury or trading tool.
- A fintech or vertical SaaS shipping agent features that need a control an
  auditor will accept.
- Anyone who will one day have to answer: *what stopped it, and can you prove
  it?*

It is **not** a model-safety layer, a prompt filter, or an agent framework. It
has one job, at one moment: the instant before money moves.

## Open core

| | |
|---|---|
| **SecondSign Core** — this repository, Apache-2.0 | The decision path: contracts, intent, policy, decision, human approval, gateway, local audit, rail adapters, and the conformance kits third parties test against. Useful on its own, and it always will be — this is not a crippled edition. |
| **SecondSign Enterprise** — separate, commercial | Organisational scale: hosted runtime and control plane, multi-tenancy, org-wide policy, centralised audit, remote approvals, SSO/RBAC, compliance workflows, and attestation that a deployment really is what it claims. |

Two rules hold that line: core never depends on anything private, and an
enterprise extension may only make a decision stricter — never grant a
permission core would have refused.

Extensions — a new rail, a policy plugin, an approval provider — prove they are
safe by inheriting a conformance test suite, not by persuading a maintainer.
See [Extension contracts](docs/EXTENSION_CONTRACTS.md).

## Status

Pre-1.0. Interfaces may still change.

**Built and tested:** the whole decision path end to end — contracts and the
plugin boundary, intent, policy, the decision engine, maker-checker approval,
the execution gateway, the hash-chained audit receipt, Stripe and Alpaca
adapters, the conformance kits, and an adversarial matrix run against the threat
model. Branch coverage is 100%, enforced by CI rather than asserted here — but
read that as an engineering signal, not as evidence of security. It says every
branch was executed by some test. It does not say the tests assert the right
things, and it is not a substitute for the independent review this project has
not yet had.

**Not there yet:** the deployment shape that makes no-bypass real for you — a
standalone gateway process with a control-plane store the agent cannot reach —
plus a first-class agent-facing integration surface ([`CORE-S019`](docs/slices/roadmap.yaml)).
Today, running the library inside your agent's process is right for development
and testing, not for production custody of money.

Where each queued slice actually stands, derived from Git rather than
hand-maintained: [`docs/slices/STATUS.md`](docs/slices/STATUS.md).

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | What core is, and what it deliberately is not |
| [Threat model](docs/THREAT_MODEL.md) | What this defends against, and why each rule exists |
| [On-chain threat model](docs/ONCHAIN_THREAT_MODEL.md) | What changes when the agent holds a wallet — designed, not implemented |
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
