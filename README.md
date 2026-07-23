# SecondSign Core

Runtime authorization for financial AI agents. It sits on the execution path
before an agent can move money, place an order, change account controls, or
export financial data.

```text
financial agent
      │
      ▼
  IntentAdapter        trust boundary — raw account data cannot enter
      │
      ▼
  TransactionIntent    immutable; digest-bound
      │
      ▼
  Policy → Decision    ALLOW / REVIEW / DENY, monotonic
      │           └── REVIEW → MakerChecker (one-shot, TTL, digest-bound)
      ▼
  ExecutionGateway     re-verify digest and validity, then execute
      │
      ▼
  AuditReceipt         redacted, hash-chained
```

**Status: early.** The plugin contract, its conformance kit and the
architectural enforcement are implemented. Intent, policy, decision, approval,
gateway and audit are specified but not yet built.

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | What core is, and what it deliberately is not |
| [Threat model](docs/THREAT_MODEL.md) | What this defends against, and why each rule exists |
| [Invariants](docs/INVARIANTS.md) | The guarantees, each bound to the test that enforces it |
| [Extension contracts](docs/EXTENSION_CONTRACTS.md) | How to add a rail, rule or provider and certify it |
| [Contributing](CONTRIBUTING.md) | The slice protocol and quality gates |
| [Governance](GOVERNANCE.md) | Who decides what, and how little needs deciding |
| [Roadmap](docs/slices/roadmap.yaml) | The build queue, machine-validated |

Everything needed to build on or contribute to this project is in this
repository. Nothing here depends on a private one.

## Design principles

- **Fail closed.** Uncertainty takes the strictest path.
- **Monotonic.** Combining judgements may only ever tighten.
- **Decided value == executed value.** Bound by an intent digest that is
  re-verified immediately before execution.
- **Rail-agnostic.** Adding a payment or brokerage rail must not change the
  decision layer. Stripe and Alpaca drive the design as a falsification pair.
- **Deterministic.** No learned component on the live decision path.
- **No raw financial data** anywhere in decisions, receipts, or logs. Money is
  integer minor units.

## Provenance

SecondSign Core is authored from scratch. Its history begins at its own initial
commit, and it contains no source copied or adapted from a third party.

Specifications are committed before the implementations they describe, so the
commit order is itself part of the record. Every commit carries a DCO sign-off,
and any third-party source that informed a change is named in its pull request
along with the licence it carries.

## Licence

Apache-2.0. Copyright 2026 SecondSign contributors. See `LICENSE`.

The licence text was fetched from
<https://www.apache.org/licenses/LICENSE-2.0.txt>.

## Contributing

Every commit requires a DCO sign-off. See `CONTRIBUTING.md`.
