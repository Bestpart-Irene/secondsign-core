# ADR 0005 — An approval binds to a proposal, not to a window

Status: accepted
Date: 2026-07-31

Constrains `CORE-S022`. Amends what INV-10 means by "digest-bound".

## The sentence this ADR exists to protect

> **The validity window is not part of what a human approves. Every other
> material field is.**

## Context

INV-10 says approvals are one-shot, expiring and **digest-bound**: an approval
names a single `IntentDigest` and authorises nothing else. That is what makes
beneficiary substitution (B3) structurally impossible — the reviewer sees an
object, and the same object's digest is re-verified immediately before dispatch.

The digest covers every material field of a `TransactionIntent`, and two of
those fields are `not_before` and `not_after`: the validity window. The window
is in there for a good reason. B5 is stale quotes and market timing, and an
intent that could be executed at any later time is an intent whose price,
balance and counterparty state were all checked against a moment that has
passed.

Both properties are correct, and together they make the flow they describe
impossible to run:

- `INTENT_TTL` is five minutes, and `ExecutionGateway` re-verifies the window
  immediately before dispatch;
- a human review takes longer than five minutes, essentially always;
- so every approved review fails as `window_expired`;
- and re-deciding to obtain a fresh window produces a **different intent
  digest**, which the human never saw and cannot have approved.

This is not a bug in either rule. It is the point where two true statements meet
and one of them has to be made more precise.

The threat model already says which one. B5's stated answer is:

> expiry forces **re-decision, not re-approval**.

Re-decision is a statement about the *decision*. It says nothing about
re-obtaining the human's answer, and it presumes the human's answer survives the
re-decision. For that presumption to hold, the human's answer cannot be bound to
a value that re-decision changes.

## Decision

### 1. Two digests, over the same intent

`IntentDigest` is unchanged. It covers every material field, it binds the
decision to the execution (B1), and the gateway keeps re-verifying it
immediately before dispatch.

A second digest, **`ProposalDigest`**, covers every material field **except**
`not_before` and `not_after`. It is what an approval binds to.

The exclusion list is exactly two fields, it is stated once in code, and a test
asserts both names exist on `DecisionDimensions` — so renaming a window field
fails loudly rather than silently widening what a human is deemed to have
approved. A second test iterates the model's fields and requires every other one
to change the proposal digest, so a field added later is covered by default and
a field deliberately excluded has to be argued for in a pull request.

### 2. The two digests are not interchangeable

They are distinct types, and their hashed material carries a domain label, so
the same intent yields two different values and neither validates where the
other is expected. A hex string that means "this proposal" must not be
mistakable for one that means "this intent" — a system with two digests and one
type is a system with one digest and a bug waiting for a call site.

### 3. What re-decision may and may not do

When a checker approves, the gateway re-completes the intent from the **stored
proposal** — never from anything the agent has sent since — takes a fresh
validity window, and re-decides.

- The new intent's **proposal digest must equal the approved one**. It always
  will, unless the completion logic itself changed under a running deployment;
  it is checked anyway, because that check is the whole guarantee and it costs a
  comparison.
- The new decision must not be `DENY`. Policy state moves — a limit is lowered,
  a window fills up — and a re-decision that now denies is a denial. The
  approval is not burnt by that refusal: the human's answer was not the problem.
- The window may change. Nothing else may.

### 4. What the human's answer means

Precisely this: *these material fields may move value, once, if the decision
still permits it at execution time.* It is not a permission slip that survives a
denial, not a reusable credential, and not a statement about when.

INV-10's other three properties are untouched. One-shot, expiring with a
mandatory TTL, and maker separate from checker all continue to hold, and the
existing tests for them continue to be the enforcement.

## Alternatives rejected

**Keep the strict binding; require approval inside the intent window.** The
guarantee stays maximally simple and the feature does not work. Nobody reviews a
payment in five minutes, so the honest description of this option is "core has
no maker-checker flow", which is where the project already was.

**Give review-bound intents a long window up front.** Complete every intent with
a twenty-four-hour window so an approved one is still valid. This widens the
replay and stale-quote surface for *every* intent, including the ones that are
allowed outright and dispatched immediately, in order to serve the small subset
that gets reviewed. It also cannot be conditioned on the verdict, because the
window is chosen before the decision exists.

**Re-decide and re-bind the approval to the new intent digest.** No new concept,
and the grant ends up naming a digest that no human ever saw. The property
"the human approved exactly this digest" becomes "the human approved something
from which this digest was derived by a code path you are welcome to audit",
which is a comment rather than an invariant. Rejected because the value of a
digest-bound approval is that it is checkable by comparison, not by reading.

**Freeze the clock: reuse the original window on approval.** Executes what was
decided, exactly, and re-introduces B5 in full — an approval sitting for six
hours would dispatch against a six-hour-old view of every limit and balance.
The window exists to prevent this.

## Consequences

- **A stated guarantee is narrower than it was.** "An approval is bound to the
  digest" becomes "an approval is bound to the proposal digest, and execution is
  bound to the intent digest". Two sentences where there was one, and INV-10's
  row says both.
- **A new concept appears in `secondsign.intent`.** Anything that stores or
  transmits approvals now carries two values, and an implementation that stores
  only one has thrown away either what was approved or what was executed.
- **Re-decision at approval time is a real decision.** It reads live policy
  state, so an approved action can still be refused, and an operator debugging
  "the human said yes and nothing happened" needs the receipt to distinguish it
  from a dispatch failure. Every state leaves a receipt for that reason.
- **The window is now the only field a deployment may treat as mutable between
  approval and execution.** If a later slice needs a second such field, it
  amends this ADR rather than adding a quiet exception.
