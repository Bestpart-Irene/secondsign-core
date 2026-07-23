# Architecture

SecondSign Core is a **deterministic execution authorization kernel for
financial AI agents.** It sits between an agent's intent and a bank, broker or
custodian, and decides — reproducibly, and with a record — whether the action
proceeds.

## The path

```text
      rail adapter                    Stripe, Alpaca, bank APIs
            │                         maps a tool call to an intent
            ▼
     TransactionIntent                immutable, closed, digest-bound
            │
            ▼
    Policy → DecisionEngine           ALLOW / REVIEW / DENY, monotone
            │           │
            │           └── REVIEW ──▶ MakerChecker
            │                          one-shot, expiring, digest-bound
            ▼                                    │
    ExecutionGateway  ◀────────────────────────┘
            │   re-verify digest, re-check validity and screening,
            │   reserve idempotency, then dispatch
            ├──────────────▶ rail API
            ▼
      AuditReceipt                    redacted, hash-chained
```

The control plane — limits, approver roster, idempotency store, audit ledger,
fingerprint keys — is **not a stage in this path.** It is the protected asset,
structurally unreachable from the managed agent (INV-12).

## What core does

- Turns a financial tool call into a strict, immutable transaction intent.
- Evaluates value, frequency, counterparty, market state and source trust,
  deterministically.
- Guarantees that several policies can only ever tighten a decision.
- Binds human approval to a precise intent digest.
- Re-verifies before execution, so approving A cannot execute B.
- Handles idempotency, replay, and unknown execution outcomes.
- Emits audit receipts that cannot be silently lost.
- Publishes stable contracts that extensions and enterprise builds depend on.

## What core does not do

- Agent reasoning, prompting, or orchestration.
- Workflow or graph execution.
- Shell, filesystem, or coding-agent security — a different problem with a
  different threat model.
- Multi-tenant backends, SSO, consoles, or billing.
- Online learning or behavioural anomaly models on the live decision path.
- Customer business logic.

The last exclusion is deliberate and worth stating plainly: velocity and
counterparty judgements are **deterministic policy**, not learned signals.
A deterministic rule can be explained to a reviewer, reproduced in an audit,
and defended to a regulator. If learned detection is added later it runs
shadow-only until calibrated, and never as the sole basis for a denial.

## Layering

```text
adapters/     rail-specific, one module per rail
    │
intent/       decision dimensions + closed rail payloads + digest
    │
policy/       deterministic evaluation
decision/     combination and verdict
    │
approval/     maker-checker
gateway/      pre-dispatch verification and execution
audit/        receipts

contracts/    the extension surface — a leaf, imports nothing else
conformance/  the test suites extensions certify against
```

Dependencies point downward only, enforced by `lint-imports` in CI.
`contracts` is deliberately a leaf: an extension speaking through it gains no
reach into policy, decision, gateway or adapter internals (INV-7).

**Adding a rail must not change the decision layer** (INV-8). A new rail is a
new closed payload variant plus an adapter. If it requires touching decision
code, the intent abstraction is wrong and gets fixed rather than patched
around — that is what slice `CORE-S015` exists to falsify.

## Status

Early. The plugin contract, its conformance kit, and the architectural
enforcement are implemented. Intent, policy, decision, approval, gateway and
audit are specified but not yet built; see
[`slices/roadmap.yaml`](slices/roadmap.yaml) for the order and
[`INVARIANTS.md`](INVARIANTS.md) for which guarantees are live tests today
versus commitments with a named slice.
