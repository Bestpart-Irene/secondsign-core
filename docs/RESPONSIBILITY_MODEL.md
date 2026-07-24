# Responsibility Model — Core (self-deployment)

> **Status: DRAFT.** This document describes how responsibility is allocated
> when you run SecondSign Core yourself. It is a statement of the software's
> design posture, **not legal advice**, and it does not create a contract. The
> binding terms for self-deployment are the Apache-2.0 `LICENSE` in this
> repository. The hosted commercial offering is governed by a separate written
> agreement and its own responsibility model — not by this file.

SecondSign Core sits on the execution path before a financial AI agent can move
money, place an order, change account controls, or export financial data. Being
on that path, it invites a fair question: **when money moves the wrong way, who
is responsible?**

The honest answer for the open core is: **the party who deploys and operates it.**
This document says why, and draws the line precisely.

---

## 1. The deployment model

Core is **software you run inside your own trust boundary** — your VPC, your
process, your secrets manager. There is no SecondSign-operated service in the
core deployment. Nothing in this repository phones home, custodies funds, or
holds a credential we can reach.

```text
your financial agent
        │
        ▼
   SecondSign Core          runs inside YOUR boundary
        │  Policy → Decision (ALLOW / REVIEW / DENY)
        ▼
   ExecutionGateway         holds YOUR rail credential, as an opaque handle
        │
        ▼
   the rail (Stripe, Alpaca, …)   YOUR account, YOUR contract with them
```

The account is yours. The rail credential is yours and never leaves the
gateway's custody. The policy is yours to configure. The decision to run in
production is yours. So the responsibility for outcomes is, by construction,
yours too.

---

## 2. What the design guarantees regardless of who operates it

Some things are true no matter who deploys core, because they are enforced in
code and pinned to tests (see [`INVARIANTS.md`](INVARIANTS.md)). They bound the
*shape* of what can go wrong:

- **No bypass path.** The managed agent holds no rail credential and has no
  network route to the rail. Stop SecondSign and it cannot move money. Core
  cannot be the reason an agent moves money the operator never routed through it.
- **Fail closed.** Uncertainty, missing context, and unavailable dependencies
  all take the strictest path. Core's failure mode is to *withhold*, not to
  wrongly permit.
- **Monotonic decision.** Combining judgements may only ever tighten. There is
  no vocabulary in the contract for a plugin to grant an action.
- **Immutable, digest-bound intent.** The decided value and the executed value
  are the same object, re-verified immediately before execution.
- **Credentials never leave the gateway.** Only opaque handles cross a boundary —
  never in an intent, receipt, plugin input, or error output.
- **No raw financial or customer data** in decisions, receipts, or logs.

These reduce the surface. They do **not** make core a guarantor of correctness:
a control that fails closed can still be misconfigured to allow something you
did not intend, or bypassed by not being placed on the path at all.

---

## 3. Responsibility matrix — self-deployment

| Area | You (operator) | SecondSign (as software author) | The rail |
|---|---|---|---|
| Choosing to place core on the money path at all | ✅ | — | — |
| Rail account, its terms, and its execution behaviour | ✅ | — | ✅ (per your rail contract) |
| Custody of rail credentials and secrets | ✅ | — | — |
| Policy configuration — limits, review thresholds, approvers | ✅ | — | — |
| Which agents may submit intents, and their instructions | ✅ | — | — |
| Approver identity, account security, and approval decisions | ✅ | — | — |
| Deployment, patching, monitoring, and incident response | ✅ | — | — |
| The software behaving per its documented contract and invariants | assists (config) | ✅ (best-effort, AS IS) | — |
| A defect in core that causes a wrong decision or leaks a handle | report it | ✅ (fix + disclose) | — |
| Rail executing correctly on a valid instruction | — | — | ✅ |

"✅ (best-effort, AS IS)" is deliberate: authorship responsibility for the open
core is to build it correctly and fix defects in the open — **not** to warrant
your production outcomes. That warranty, where it exists at all, lives in the
commercial agreement, is capped, and is insured. It is not granted here.

---

## 4. Warranty and liability for the open core

Governed entirely by the Apache-2.0 `LICENSE`. In plain terms:

- The software is provided **"AS IS", without warranties or conditions of any
  kind**, and the contributors are **not liable** for damages arising from its
  use, to the extent the license and applicable law allow.
- Deploying it into a money path is a decision you make and own. We strongly
  recommend a sandbox first, then a low transaction cap, then scale.
- If you want someone to stand behind production outcomes with an SLA and a
  contractual, insured liability commitment, that is the **hosted commercial
  offering**, under a separate agreement — not the open core.

Nothing in this document narrows or expands the `LICENSE`. Where they appear to
differ, the `LICENSE` controls.

---

## 5. What core deliberately does not do

To keep the responsibility line clean, the open core **does not**:

- custody funds;
- hold a credential that SecondSign the company can reach;
- reach out to any SecondSign-operated service to make a decision;
- promise to catch every wrong payment.

It provides a **verifiable control and evidence layer that can only ever
tighten** — deployed inside your boundary, auditable line by line. That is the
thing it is responsible for being.

---

## 6. Reporting a defect

Security-relevant defects — anything touching a decision, a credential handle,
tenant isolation, or the no-bypass invariant — go through the process in
`SECURITY.md` (see repository root). Please do not open a public issue for a
credential- or bypass-class report before it is triaged.
