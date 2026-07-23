# Threat model

What SecondSign Core defends against, and why each invariant exists. Every
design decision in this project should trace to a threat here; a design that
traces to nothing gets a threat analysis or gets removed.

Slice manifests reference these identifiers, and `tools/validate_slice.py`
rejects a manifest citing a threat this file does not define.

## Scope

Protected: **the moment money moves or account control changes.** Not the
model, not the prompt, not the developer environment.

```text
instruction source (user / ticket / email / web page / tool output)
        │   ← source trust is fixed here and only ever decreases
        ▼
    agent reasoning
        │
┌───────────────────────┐
│  intent boundary      │  ← everything above is untrusted input
└───────────────────────┘
        ▼
    decision (ALLOW / REVIEW / DENY)
        ▼
┌───────────────────────┐
│  execution gateway    │  ← re-verify, then dispatch
└───────────────────────┘
        ▼
   bank / broker / custodian
```

Three asset classes, in descending order of how strongly they must be
defended:

| Asset | Contents |
|---|---|
| Control plane | limits, approver roster, idempotency store, audit ledger, fingerprint keys |
| Value actions | payments, transfers, trades, withdrawals, refunds, account changes |
| Data | statements, positions, customer records, transaction history |

**The control plane must be defended more strongly than the money.** An agent
that can raise its own limit has no limit.

## A — General defect classes

These are ways authorization layers fail regardless of domain.

### A1
**Deciding on a redacted value.** One field serves both the audit record and
the policy check, and redaction happens before the check. The decision sees a
placeholder while the gateway forwards the real value.

*Answer:* checks read the raw value, records write the redacted one, and the
two paths are separate types. Raw values live only in memory.

### A2
**The control plane is not itself protected.** Policy files, role definitions,
approval records and ledgers match no rule, so the managed subject can edit
what constrains it. This is a privilege chain, not a single defect.

*Answer:* the control plane is structurally unreachable, and that judgement
depends on no configurable policy — otherwise editing the configuration
removes the protection.

### A3
**Persisted configuration is edited to silently loosen.** A relaxation flows
through an approval gate, but the resulting state sits somewhere directly
editable. A missing expiry turns a temporary relaxation permanent.

*Answer:* read-side verification. Reading any setting looser than default
requires a matching, unexpired, approved record in an append-only ledger;
otherwise it falls back to strictest. A missing expiry counts as expired.

### A4
**Missing context falls back to someone else's policy.** When the scope
identifier is absent, resolution finds a default — or another tenant's rules.

*Answer:* missing context falls back to the strictest default, never to *a*
policy. Scope is derived from authenticated caller identity, never self-reported.

### A5
**A free-form field becomes a payload channel.** A `mapping<string, any>`
passes every name-based check and carries anything. In finance this is the
most likely control to be defeated, because card numbers, account numbers and
customer names are naturally structured data that a developer will put
somewhere convenient.

*Answer:* exact scalar allowlists with a ratchet test; sensitive identifiers
appear only as keyed fingerprints; money is integer minor units.

### A6
**Equivalent expressions evade a rule.** The rule matches a surface form while
the same meaning has several representations.

*Answer:* decide on normalized semantics, not on the caller's surface form.
Normalization is total and deterministic, and normalization failure is read
against the caller.

### A7
**An interception leaves no trace.** The main path is logged; error handling
and degraded paths are not. Nobody can later answer why a transaction did not
execute, or demonstrate that a control was ever in force.

*Answer:* every non-permitting path emits a record. A failed audit write is
itself a fail-closed event.

### A8
**Over-triggering is a security failure.** A noisy control produces approval
fatigue; reviewers begin approving in bulk, and the approval step's real
security value goes to zero while still manufacturing the appearance of
oversight.

*Answer:* approval rate is a first-class metric with a budget. Exceeding it is
answered by improving rule precision, not by raising thresholds.

### A9
**Combination weakens.** Merging several judgements yields something less
strict than one of the inputs.

*Answer:* combination is a maximum over strictness and a union over reasons,
with no branch capable of returning less. Verified by property tests for
commutativity, associativity, idempotence and monotonicity — not by examples.

## B — Financial execution threats

These are specific to moving money and are what distinguishes this project
from a general agent guardrail.

### B1
**Decided value is not executed value (TOCTOU).** The decision approves intent
A and the gateway dispatches intent B, because the caller reassembled the
request or the two paths each built their own parameters.

*Answer:* the decision carries an intent digest covering every material field;
the gateway accepts only the decision-carried object and re-verifies the digest
immediately before dispatch.

### B2
**Approval replay.** One human approval is spent twice, or remains valid long
after it was granted.

*Answer:* approvals bind to a single digest, are one-shot, and expire.
Idempotency is reserved before execution rather than recorded after.

### B3
**Beneficiary substitution.** The reviewer sees one counterparty and a
different one is paid, because the display and the execution read different
fields.

*Answer:* what is shown is rendered from the object that will be executed, not
from a copy or a summary.

### B4
**Structuring.** Ten transfers of 9,999 defeat a limit of 10,000. Also across
rails, across time windows, and across counterparty aliases.

*Answer:* limits are judged on sliding-window aggregates; a single transaction
is the special case. Natural-day boundaries are themselves evadable.

### B5
**Stale quotes and market timing.** The rate or price at approval is not the
one at execution, and human review widens that window considerably.

*Answer:* intents carry a validity window; expiry forces re-decision, not
re-approval. Price-sensitive actions get materially shorter approval TTLs.
Closed sessions and halts are deterministic blocks.

### B6
**Approver isolation fails.** Initiator and approver are the same principal,
or the agent can reach the approval channel and approve itself.

*Answer:* maker and checker are distinct types, not two values of one set. The
approval channel is part of the control plane (A2).

### B7
**Screening freshness.** Sanctions or compliance screening happens at decision
time and the list has changed by execution time, or a result is cached past its
validity.

*Answer:* screening results carry their own validity; expired means unscreened,
not previously-cleared. Screening unavailable means deny.

### B8
**Partial execution and compensation.** A transfer times out downstream in an
unknown state. Is a retry the same transaction? Is a reversal itself an
authorized money movement?

*Answer:* outcomes are success / failure / **unknown**, and unknown is not
failure. Retries carry the original idempotency key. Reversals and refunds are
independent actions that take the full decision path.

### B9
**Source trust is upgraded.** An instruction that originated in untrusted
content is labelled as a direct user instruction somewhere along the chain.

*Answer:* source trust only ever decreases. Mixed provenance is treated as its
least trusted component. High-value actions require trusted provenance, and
that requirement is not waived for small amounts.

## Coverage

Each threat maps to one or more invariants in [`INVARIANTS.md`](INVARIANTS.md),
and each invariant names the test that enforces it. Threats whose enforcement
is still a commitment rather than a test are marked there with the slice that
will close them.
