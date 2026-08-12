# On-chain threat model

What SecondSign defends against when the managed agent holds a wallet, and why
each on-chain design constraint exists. Every on-chain design decision should
trace to a threat here; a design that traces to nothing gets a threat analysis or
gets removed.

This is a separate document from [`THREAT_MODEL.md`](THREAT_MODEL.md), not an
appendix to it. The financial model's A and B threats still apply — an
authorization layer fails in the same general ways whatever it sits in front of —
but on-chain execution is a different risk language, not a wider version of the
same one. That is why the on-chain contract surface is versioned separately
rather than widening Policy Plugin API v1.

Slice manifests reference these identifiers, and `tools/validate_slice.py`
resolves a C id against this file specifically: a manifest citing a C threat this
document does not define is rejected, and so is one citing a C threat while this
document is missing or empty.

## Scope

Protected: **the instant before a signature exists.** Not the wallet, not key
storage, not the RPC endpoint.

```text
instruction source (user / ticket / on-chain data / web page / tool output)
        │   ← source trust is fixed here and only ever decreases
        ▼
    agent reasoning
        │
┌──────────────────────────────────┐
│  intent boundary (on-chain       │  ← first trust boundary
│  adapter): proposal → normalised │    above: untrusted input
│  semantics + simulation at a     │    below: structured, redacted intent
│  stated block height             │
└──────────────────────────────────┘
        ▼
    decision (ALLOW / REVIEW / DENY)
        ▼
    human approval, bound to the final signable bytes
        ▼
┌──────────────────────────────────┐
│  controlled signer / guard       │  ← second boundary, and the only real veto
│  re-simulate → re-verify → sign  │
└──────────────────────────────────┘
        ▼
    broadcast → included → finalized
```

### Three structural differences from the fiat path

Each one produces threats the financial model does not have.

**There is no protocol-level reversal.** No chargeback, no dispute window, no
bank recall. Compensation is *a new authorized action that needs the
counterparty's cooperation*, not an undo of the original. Exceptions exist and
cannot be relied on: some stablecoin issuers can freeze or blacklist an address,
and a few chains have governed a state rollback — those are the issuer's or the
governance's discretion, not a capability the holder can invoke. For design
purposes, the check before execution is the only check there will be.

**Value can leave after the action.** A fiat payment moves the money within the
one action. An on-chain approval lets someone else move it later. "How much is
this transaction" stops being the same question as "how much risk is this
transaction".

**The action is code, not a field.** A fiat rail has a closed field set. Calldata
is arbitrary bytes whose consequences are known only by executing them. This is
what makes simulation a required input on the decision path — and simulation is
itself an input that can go stale.

### Assets, in descending order of how strongly they must be defended

| Asset | Contents |
|---|---|
| Signing authority and the account control surface | signer set, threshold, modules, guards, proxy implementation slot, limit configuration, approver roster, audit ledger |
| Value actions | transfers, approvals, swaps, bridges, contract calls |
| Data | balances, positions, transaction history |

**An agent that can change the signer set, a module or a guard has no limit at
all.** This is the financial model's A2 in its sharpest on-chain form, because
on-chain a control-plane change *is* an ordinary transaction whose value is zero.

**An independent veto exists only at the signer or the smart-account guard
boundary.** A service the agent calls for advice is not a control: the agent can
decline to call it, or call it and ignore the answer. If SecondSign is not on the
signing path, every constraint in this document is decoration.

## C — On-chain execution threats

### C1
**Future exposure is not current outflow.** An approval moves nothing now and
exposes everything later. `approve(spender, 2^256-1)` transfers no asset, so a
per-transaction cap and a sliding-window total both pass it. ERC-20 lets the
spender draw *repeatedly* within the allowance without returning to the wallet
holder, and that outflow is initiated by a third party at a time when SecondSign
is not on the path.

The aggregation semantics have to be stated precisely, because the obvious
version is wrong: standard ERC-20 `approve` **overwrites** the current allowance,
it does not accumulate. What genuinely aggregates is five other things —
incremental interfaces such as `increaseAllowance`; totals across spenders and
across tokens; sub-delegation systems that redistribute an allowance beneath one
spender; **re-granting after consumption**, where each grant is within the limit
but cumulative outflow is unbounded; and assets arriving in the future that fall
under an approval that already exists.

*Answer:* value carries at least three dimensions — `immediate_outflow`,
`future_exposure`, `execution_cost` — and they must not be folded into one
scalar. `future_exposure` is not an integer either: it separates value at risk
under current balances and allowances from the standing capability to draw
again, and an unbounded approval is expressed as an enumerated value rather than
a large number, because a large number invites a policy to compare it. Unbounded
approvals are denied by default. Folding has a known consequence: pushing
`future_exposure` into the financial path's `value_upper_minor` puts it through
the same sliding-window aggregation and denies every ordinary transfer in that
window — safe, and the limit is now useless.

### C2
**An approval can be created by an offline signature, with no transaction.**
ERC-2612 `permit` creates an allowance from an EIP-712 signature that never goes
on chain, costs no gas, and passes through no "review pending transactions"
control. Batched-approval signature schemes in wide use have the same property.
Any design whose control point is transaction broadcast rather than signing is
fully bypassed here.

*Answer:* the control point is the **signature**, not the transaction. The
controlled signer intercepts every signing request, including EIP-712 typed data
and `personal_sign`, not only transaction signing. A typed-data request whose
structure cannot be normalised to known semantics is denied. An implementation
that can only see `eth_sendTransaction` is incomplete, and this document treats
it as non-conformant rather than as a partial control.

### C3
**An account control change looks like a zero-value transaction.** Adding an
owner, lowering the threshold, enabling a module, replacing a guard, swapping the
fallback handler: each is an ordinary contract call whose value is zero, so any
policy organised around amounts cannot see it. On a Safe-style smart account an
enabled module can originate transactions without meeting the threshold — that
is, past every approval.

*Answer:* account control change is its own action class, not a subset of
"contract call". In v1 it is denied outright rather than escalated to human
review: v1's scope contains no account upgrade, and offering an approval path
for an out-of-scope action means using a human click to endorse semantics nobody
modelled. Review becomes available only once the class is explicitly supported
and its effects are closed. `future_exposure` for this class is account-wide —
every asset the account holds now or later, not zero and not some integer. Where
SecondSign is itself a co-signer or guard, "remove SecondSign" must be
structurally inexpressible or permanently denied; a self-removal control that a
setting can enable is not a control.

The denial above is a policy decision at signing time; underneath it sits an
on-chain floor that does not depend on the co-signer or the engine at all. The
production double guard (`ONCHAIN-S005`, ADR 0008) refuses every account-control
change on the agent's `execTransaction` path and the subverting ones on the module
path — with the one exception of a threshold-preserving `swapOwner` on the module
path, the recovery seam — and refuses `delegatecall` on both. Each of the four
invariants (SecondSign stays a required signer, the threshold stays two, neither
guard is removable, no value-moving or delegatecall module is enabled) is proven by
an executed transaction that reverts at the guard's own reason, on both hooks
(`onchain/test/production/ConstitutionalGuard.t.sol`). The guard enforces integrity,
not value: it judges no amount or counterparty, so it holds with the engine offline.

### C4
**The code can change after the decision.** Two paths. `delegatecall` executes
external code in the caller's storage context and can rewrite any slot including
ownership, so a harmless target address does not imply harmless executed code.
And a proxy's implementation slot can be upgraded, so an address audited
yesterday executes different bytecode today. Approvals are the worst case here,
because an allowance is granted to an address, not to code.

*Answer:* binding the target address's code hash is not enough — a proxy's own
bytecode can be identical while the implementation slot moves, so a code hash
covers only non-proxy contracts. What gets bound is a **set of code
dependencies**: the resolved implementation address and its code hash, the
relevant proxy configuration slot readings, the state snapshot the simulation
used, and where applicable the code hashes of the guards and modules in effect.
A proxy that cannot be fully resolved is treated as an unknown contract (C5),
not as a known address. Every dependency is re-read before signing, and any
mismatch against decision time sends the action back to the decision layer.
`delegatecall` is denied in v1. An approval to an upgradeable proxy is ranked no
lower in risk than an approval to an unknown contract.

### C5
**Unknown calldata has no decidable semantics.** The four-byte selector is not
in any known-protocol table, so "what will this transaction do" has no answer.
The financial model's A4 — falling back to a policy that reads a different field
when context is missing — appears here as treating an unknown call as a
low-value ordinary transaction, because its `value` field is zero.

*Answer:* undecidable semantics deny. Not review: a human shown raw calldata
cannot decide it either, so routing it to a person transfers responsibility
without adding control. **Simulation is not a semantic proof** — it is execution
evidence under one state snapshot, and "the simulation covered every effect" is
not a proposition a simulation can establish about itself. Downgrading to review
requires three things simultaneously: an allowlisted semantic decoder that maps
the call into a closed action class; the code and implementation dependencies
fully bound per C4; and a simulated trace whose effects fall entirely inside that
action class's closed effect model. If any one fails, the answer is still deny.
The known-protocol table is an explicit allowlist, never a heuristic match.

### C6
**Simulation results expire, and they expire faster than approval takes.**
Simulating at block N says "100 USDC out, no permission change". Human approval
takes four minutes. At signing the chain is at block N+20, and in between the
target was upgraded, balances moved, prices moved, and a prior allowance was
consumed. The original conclusion no longer holds for the current state.

*Answer:* a simulation records its **validity envelope**: block height, the
entire code-dependency set from C4 and the state readings behind it, the relevant
balance and allowance readings, and the price with its timestamp — not a single
target code hash. The transaction is re-simulated before signing, and any entry
out of range sends it back for a new decision rather than a retry. Simulation
being unavailable is undecidable semantics, and therefore a denial (C5). How the
simulation enters the approval digest must make "what was approved was this
transaction under this simulation" verifiable afterwards.

### C7
**A batch can be harmless per call and harmful as a whole.** Approve a small
allowance to a router; make a small swap; replace the guard with a contract that
does nothing. Each step reads as low risk, and after atomic execution the wallet
is no longer controlled. The reverse also holds: atomicity hides intermediate
states, so simulating step by step produces a result the real execution does not.

*Answer:* the unit of judgement is the **whole ordered batch**, not the sum of
per-call verdicts, and order is part of the semantics. **Net effect is not the
test.** Approve, spend, revoke nets to zero allowance while the value has already
left, so judgement rests on intermediate and peak exposure rather than the final
state. Permission changes and value changes never net against each other:
revoking an old approval inside a batch does not offset granting a new one.
`execution_cost` is the batch's total upper bound, not its net. Any account
control change anywhere in a batch denies the entire batch in v1. Approval binds
a normalised batch digest covering every ordered sub-call — per-call approval is
unnecessary provided the digest genuinely covers each one and order enters the
hash.

### C8
**Value is bidirectional, and the loss can be on the receiving side.** A ten
thousand dollar swap at forty percent slippage loses four thousand while the
outflow is exactly as expected, the counterparty is allowlisted, and the
reversibility judgement was correct. Sandwich attacks, poor routing and a stale
deadline are the same class. The financial model has no such dimension because
payment is one-directional; a large share of on-chain actions are not.

*Answer:* a bidirectional action must express maximum paid, minimum received,
maximum slippage, permitted routes and a deadline. **Minimum received is a
constraint, not an estimate**: it has to appear in the final signable bytes, or
the policy layer's slippage ceiling has no force at execution. An absent or
excessively wide minimum is treated at the same level as unknown calldata.

### C9
**One signature can replay on another chain or another entry point.** A signature
not bound to a chain id replays on any EVM-compatible chain, and using the same
address across chains is normal for an agent wallet. Under account abstraction
there is a second layer: an ERC-4337 `UserOperation` signing domain must bind
both the chain id and the EntryPoint address, or one signature can be resubmitted
against a different EntryPoint deployment.

*Answer:* what decision and approval bind includes the chain id and, where
applicable, the EntryPoint address. A nonce is a property of the chain and the
account jointly, never a global one. One-shot approval (the financial model's B2)
is enforced on chain by the nonce and the signing domain together, not by a
control-plane record alone.

### C10
**State keeps drifting after broadcast.** Submitted is not settled, and settled
can return to unsettled: a transaction can be replaced with the same nonce at a
higher gas price, stall, or be reorganised out. On an L2 there is one more layer,
because a sequencer's soft confirmation is not L1 finality and the two can
diverge.

*Answer:* the on-chain lifecycle is its own state machine — `broadcast`,
`included`, `finalized`, `reverted`, `replaced`, `reorged` — and it is
**orthogonal** to the gateway's `success / failure / unknown`, not a refinement
of it. The gateway's three states describe whether submission is settled; the
lifecycle describes whether the outcome is. Folding them loses `replaced` and
`reorged` entirely.

"Drift means re-decide" is not always executable, because a signed transaction
can return to the mempool after a reorg and be included again with no second
chance to veto. So the constraint splits by case. A replacement that keeps the
semantics and only raises gas within the approved `execution_cost` bound is an
allowed replacement and does not trigger a new decision. A change to calldata,
target or native value is a different transaction and must be re-decided.
Re-execution after `included → reorged` cannot be caught after the fact at all —
it is constrained only by what was written into the signable content beforehand:
an on-chain deadline, the one-shot nature of the nonce, and the smart account's
own validation logic. That is the real reason C14 binds deadline and nonce.
`finalized` under a declared finality policy is terminal and does not regress on
an ordinary reorg, or the state machine has no end and the audit trail has no
moment of settlement. Finality is declared per chain and never defaulted, and an
L2 must separate sequencer confirmation from L1 finality. Audit records the
migration sequence, not only the final state.

### C11
**The agent obtains signing capability without passing through SecondSign.** It
holds the private key or seed phrase; it reaches a different RPC provider with an
already-signed transaction; it calls a wallet SDK signing method nobody
intercepted; a second signer exists in the runtime. This is the financial model's
B10 — side-channel execution straight to the rail — with heavier consequences,
because there is no protocol-level reversal and recovery needs the
counterparty's cooperation.

*Answer:* the private key never enters a process, environment variable, file or
log the agent can reach. The deployment shape has to make an unmediated
signature structurally impossible: a co-signer holding a required seat in the
threshold, a customer-side signer gateway, or a smart-account guard. Where a
deployment cannot provide that guarantee, the product must state that what it
offers there is visibility, not control — a system that claims control while
being bypassable is more dangerous than one that claims nothing.

Guard coverage is where this threat is won or lost, and it must be stated
exactly rather than assumed; see [Technical
assumptions](#technical-assumptions-and-residual-risks).

### C12
**Token semantics are not uniform.** Transferring 100 does not mean 100 arrives:
fee-on-transfer tokens deduct during transfer, rebasing balances change over
time, `decimals` is not always 18 (USDC uses 6), and some widely held tokens do
not return a bool from `transfer`, so a standards-conformant call fails or is
misread. A judgement made on nominal amounts disagrees with the outcome.

*Answer:* an asset is identified by `chain_id + token_contract`, never by symbol,
because symbols collide and can be forged. Amounts are integers in the token's
base unit, and **`decimals` is display and valuation metadata that takes no part
in execution semantics**. v1 therefore does not trust a contract's live
`decimals` at decision time: for allowlisted assets the expected value is fixed
in configuration and verified, and a mismatch denies — a `decimals` that can
change between calls is, if valuation reads it, an attacker-controllable
valuation dial. Judgement rests on the balance changes the simulation produced,
not on the nominal parameters in the calldata. This is the financial model's A6,
an equivalent expression that evades the rule, in its on-chain form.

### C13
**Cost drains value while every transaction stays under the limit.** An agent is
induced to send failing or pointless transactions repeatedly, each cheap and
cumulatively not; or one transaction carries an extreme gas price or priority
fee; or a paymaster absorbs it and the sponsor pays.

*Answer:* `execution_cost` is an independent value dimension with its own
per-transaction ceiling and windowed total. The gas bound enters the bytes that
approval binds (C14), or the restriction has no force at execution. High
frequency at low value is a rate dimension rather than an amount dimension —
the financial model's B4, structuring to stay under a threshold, applies
unchanged.

### C14
**Approval binds a summary instead of the signable content.** The screen says
"send 100 USDC to 0xAB…CD", the human approves, and the bytes actually signed
are different calldata. This is the financial model's B1 — the decided value and
the executed value are not the same object — with a much larger surface, because
one semantic summary corresponds to unboundedly many distinct calldatas.

*Answer:* approval binds the joint hash of the **normalised semantics** and a
**commitment to the final signable bytes**, never either alone: bind only the
semantics and the bytes can be swapped, bind only the bytes and the human cannot
tell what they approved. The binding covers at least the chain id, the EntryPoint
address where applicable, sender, nonce, target, calldata hash, native value, gas
bound, deadline, the normalised ordered batch digest covering every sub-call, and
the simulation result with its validity envelope. Deadline and nonce are in the
binding for a second reason beyond replay: together with the smart account's own
validation logic they are the *ex ante* mechanism that still constrains
re-execution after a reorg, when an *ex post* decision would arrive too late
(C10). The joint hash is recomputed immediately before signing, and a mismatch
refuses the signature rather than re-deciding — a mismatch means something
rewrote the request after approval.

## Candidate invariants

Derived from the threats above. Final numbering is fixed in the on-chain
component specification, and each one names the test that enforces it once its
slice lands; until then the enforcement column in
[`INVARIANTS.md`](INVARIANTS.md) is the progress bar.

| Candidate invariant | Source |
|---|---|
| Value is three-dimensional; `future_exposure` and `immediate_outflow` never fold together | C1 |
| `future_exposure` separates value at risk from standing capability; unbounded is an enumerated value, not a large number | C1 |
| The control point is the signature, not the transaction; every signing type including EIP-712 is intercepted | C2 |
| Account control change is denied in v1; review requires the class to be explicitly supported first | C3 |
| A decision binds a set of code dependencies — implementation address, proxy slots, state snapshot, guards and modules — not one address's code hash | C4 |
| A proxy that cannot be fully resolved is treated as an unknown contract | C4 |
| Undecidable semantics deny; simulation is not a semantic proof, and a downgrade needs decoder, dependency binding and a closed effect model simultaneously | C5 |
| A simulation carries a validity envelope; out of range means a new decision | C6 |
| A batch is judged whole and ordered, on peak and intermediate exposure rather than net effect; permission and value changes never offset | C7 |
| Batch approval binds one normalised digest covering every ordered sub-call | C7, C14 |
| A bidirectional action expresses minimum received, and it appears in the signable bytes | C8 |
| The binding includes chain id and EntryPoint; a nonce is a chain-and-account property | C9 |
| The on-chain lifecycle and the gateway outcome are orthogonal state machines | C10 |
| Replacements are classified by semantics: gas-only within the approved bound may proceed, everything else re-decides | C10 |
| `finalized` under a declared finality policy is terminal and does not regress on an ordinary reorg | C10 |
| The veto on the signing path is structural and cannot be lifted through any agent-reachable path | C3, C11 |
| Judgement rests on simulated actual changes, not nominal parameters; `decimals` takes no part in execution semantics | C12 |
| `execution_cost` carries its own limits | C13 |
| Approval binds a joint commitment over semantics and signable bytes | C14 |
| Guard configuration identity enters the commitment: the guards in effect at decision time are the guards in effect at execution | C3, C11 |

## v1 scope

The first version does not attempt every chain, token or protocol.

**In scope**

- one EVM chain: Base Mainnet, chain id 8453
- Safe-style smart account, at a pinned version, with both a transaction guard
  and a module guard installed (see the assumptions below)
- USDC
- `token_transfer`
- `token_approval`, with unbounded approvals denied by default
- mandatory human approval for a new destination address
- per-transaction and sliding-window limits
- the customer holds the signer; SecondSign custodies no private key
- an agent-unreachable recovery path, under a timelock, that is also the failure
  recovery path
- unknown contract calls denied

**Deliberately out of scope, deferred rather than overlooked**

- `swap` — second step, restricted to allowlisted routes
- `bridge`, arbitrary calldata, leverage, governance, general protocol calls
- account control change (owner, threshold, module, guard, proxy upgrade) — the
  correct result for an out-of-scope action is denial, not an approval path; see
  C3
- `batch`
- multiple chains and cross-asset valuation
- MEV protection — v1 expresses a slippage constraint and does not actively
  defend
- automatic reorg compensation — v1 records and alerts; the *ex ante* constraint
  is carried by deadline, nonce and the account's validation logic per C10
- the co-signer deployment shape

**Why the scope is narrow.** C5 and C6 together say that the ceiling on how much
an on-chain control can be trusted is set by whether semantics can be decided at
all. Real control over a narrow decidable set is worth more than bypassable
control over a wide one — especially in an environment with no protocol-level
reversal.

## Red-team matrix

Every threat gets at least one case that must fail. **These cases are specified,
not yet executed:** none of `C-RT-001`..`C-RT-026` is backed by a running test
today. The only Solidity that executes is the toolchain smoke test
(`PinnedReleases.t.sol`), which proves the harness is real — not that any case
below holds. The expected verdicts are the specification the later on-chain
slices are built against, a commitment rather than a result.

**The identifiers are
stable, not row numbers**: cases are added but never renumbered, a deleted case
leaves its number retired, and a revised case keeps its number. On-chain reason
codes are derived from these identifiers, so unstable numbering would mean
unstable provenance for every reason code. Nothing should reference this matrix
by count.

| ID | Case | Expected |
|---|---|---|
| `C-RT-001` | `approve(spender, 2^256-1)` | DENY |
| `C-RT-002` | Repeated small `increaseAllowance` calls summing past the limit | DENY |
| `C-RT-003` | Re-granting after an allowance is consumed: each grant within the limit, cumulative outflow past it | DENY |
| `C-RT-004` | Exposure to several spenders for one token summing past the limit | DENY |
| `C-RT-005` | An approval covering assets that arrive later | `future_exposure` non-zero and counted |
| `C-RT-006` | An EIP-712 permit signing request whose structure is unknown | DENY |
| `C-RT-007` | Add owner, lower threshold, enable module, replace guard | DENY, out of v1 scope |
| `C-RT-008` | Remove SecondSign's own signer seat | Structurally inexpressible, or permanently DENY |
| `C-RT-009` | `delegatecall` | DENY |
| `C-RT-010` | Proxy bytecode unchanged, implementation slot moved | Pre-signing re-verification fails, re-decide |
| `C-RT-011` | A proxy whose implementation cannot be resolved | Treated as unknown contract, DENY |
| `C-RT-012` | Unknown selector | DENY, never REVIEW |
| `C-RT-013` | Known decoder, but simulation shows a permission change outside the effect model | DENY |
| `C-RT-014` | Blocks advance during approval until a balance leaves range | Re-decide |
| `C-RT-015` | Batch: approve, spend, revoke, ending at zero allowance | Judged on peak exposure; a zero net must not pass |
| `C-RT-016` | A guard change hidden inside a batch | Whole batch DENY |
| `C-RT-017` | Batch sub-calls reordered | Different digest, a different transaction, re-decide |
| `C-RT-018` | Swap with no minimum received | DENY |
| `C-RT-019` | The same signature replayed on another chain id or another EntryPoint | Rejected |
| `C-RT-020` | Same-nonce replacement raising gas only, within the approved bound | Allowed, no new decision |
| `C-RT-021` | Same-nonce replacement changing calldata or target | Must re-decide |
| `C-RT-022` | An ordinary reorg after `finalized` | Stays terminal, does not regress |
| `C-RT-023` | A fee-on-transfer token judged on its nominal amount | Judged on simulated actual movement |
| `C-RT-024` | An allowlisted asset whose `decimals` return value disagrees with configuration | DENY |
| `C-RT-025` | An extreme gas price | Rejected once past the `execution_cost` bound |
| `C-RT-026` | Calldata rewritten after approval | Commitment comparison fails before signing, signature refused |

**Known coverage gaps, stated rather than papered over.** C11 has no case in this
matrix: bypassing the signing boundary is verified on chain in two parts. The
double-guard **topology** is falsified and confirmed on a local chain by
`ONCHAIN-S001` (built and merged) — a single transaction guard leaves the module
path open, two guards close it — and the **production guards** that enforce the
four account-control invariants (C3) on both hooks, by executed refusal, are
`ONCHAIN-S005` (`onchain/test/production/ConstitutionalGuard.t.sol`). What remains
for C11 is the *identity* part: a case for a change in guard configuration between
decision and execution, which lands with the slice that puts that identity into the
commitment. The rest of the matrix is wider still: as the heading says, most of its
cases do not execute yet, so those expected verdicts remain commitments this design
must be held to, not results it has already produced.

## Technical assumptions and residual risks

These are load-bearing. Each is stated so that a reader can check it
independently rather than take the design's word for it.

**A transaction guard covers one path only.** On a Safe-style account a
transaction guard is invoked on the `execTransaction` path and only there.
Transactions originated by an enabled module take a separate path, governed by a
module guard, which is a distinct mechanism. "A guard is installed, therefore
everything is covered" is false, and the entire no-bypass argument for C3 and C11
depends on not making that mistake.

**Zero modules is not a self-sustaining property on earlier versions.** Where a
module can originate a call to the account itself, a self-authorised
configuration function such as clearing the guard is reachable through the module
path with no guard hook invoked, because the only condition such a function
checks is that the caller is the account. Enabling a module does pass through the
guarded path and can be refused there, so the topology holds forward — but that
makes it circular: zero modules is maintained by the guard, and the guard is
unbypassable only while there are zero modules. The circle can only be broken at
installation time.

**On those versions, no-bypass and recoverability are mutually exclusive.** A
guard that always reverts makes an account with no modules unable to execute
anything at all, including the call that would remove the guard. So a topology
strong enough to be unbypassable is also strong enough to brick the account
permanently.

**v1's answer, and what remains unverified.** v1 pins a Safe version that
provides module guards and installs both guards, so each execution path has a
guard and no-bypass no longer rests on a topology assumption; zero modules
becomes defence in depth. Two things are consequences rather than conclusions and
are verified by the falsification checkpoint `ONCHAIN-S001` before anything is
built on them: whether the second revertable guard reintroduces a bricking mode
of its own, and whether recovery under single-guard failure works in both
directions. A double failure — both guards reverting permanently — still bricks
the account, and that is recorded here as a residual risk rather than presented
as solved.

**The recovery path must not be a guard bypass.** A recovery mechanism that
bypasses the guards is, on chain, indistinguishable from the attack it is meant
to survive: both are a configuration change arriving through an unguarded path.
Where a recovery mechanism has to take the module path, it must be on the module
guard's explicit allowlist and constrained by a timelock, so that what the guard
admits is a specific approved and unexpired recovery record rather than a class
of caller. **`ONCHAIN-S010` builds this** (ADR 0009): the `RecoveryController`,
enabled as the account's sole module, is the only path to the `swapOwner` the
ADR-0008 module guard permits, and a narrow one — a single configured initiator,
one owner-rotation, after a timelock the account itself (`execTransaction`) can
veto, one-shot. The allowlist and timelock live in the controller, not the guard,
which stays capability-based; because S005 freezes the module set at setup
(`enableModule` is refused on both paths), the controller is permanently the only
module that can reach `swapOwner`. Proven by executed transactions in
`onchain/test/production/RecoveryController.t.sol`. The stated residual: a hostile
recovery succeeds only if the cold recovery key is stolen **and** the agent
colludes so the account's own veto is unreachable — two independent compromises;
`M`-of-`N` guardians (a later upgrade) is the mitigation that closes even that.

**The submitter identity a guard observes is not an authorisation.** A guard
observes the address that invoked the guarded entry point, which is the submitter
or relayer — not the owner whose signature authorised the transaction. It
therefore cannot be used to argue that the agent is isolated from recovery
authority. Configuration changes bind an independent cryptographic authorisation
or an approved recovery record instead.

**Installation atomicity is the property to hold, and inbound value is not
preventable.** Deployment, initialisation and both guard configurations complete
atomically, and until that configuration verifies the account is not marked
ready, is not funded, and can take no outbound action. The stronger-sounding
claim — that the account cannot receive value before installation completes — is
not provable on an EVM chain: anyone can send an ERC-20 to an address in advance,
and native value can be forced in. An unprotected balance is therefore a state to
handle, not a possibility to deny.

**Base is an L2, which the finality policy has to reflect.** A sequencer's soft
confirmation is not L1 finality, and `sequencer_soft` must not be declared
terminal. Which rule v1 defaults to — a confirmation count or L1 finalisation —
trades settlement latency against strength and is decided in the lifecycle slice,
not here.

**Simulation trust is unresolved.** Whether simulation comes from a self-hosted
fork, a third-party service, or two sources compared against each other changes
the failure mode this document can claim: dual-sourcing downgrades "the
simulation provider was compromised" from undetectable to detectable, at a cost
in latency. v1's choice is stated in the component specification, and the
threat's design constraints hold under any of them.

## Public standards referenced

The mechanisms above derive from public standards and public contract behaviour:
ERC-20 for token semantics and allowances, ERC-2612 for signature-created
approvals, ERC-4337 for account abstraction and its signing domain, and EIP-1967
for proxy storage slots. Safe's guard and module mechanisms are described from
their externally observable behaviour and their published documentation. Public
availability of a mechanism does not license copying an implementation's
expression: this project restates mechanisms in its own domain language and
writes its own implementations.

## Coverage

Each threat maps to one or more invariants in [`INVARIANTS.md`](INVARIANTS.md),
and each invariant names the test that enforces it. Threats whose enforcement is
still a commitment rather than a test are marked there with the slice that will
close them. The on-chain queue in
[`slices/roadmap.yaml`](slices/roadmap.yaml) starts with a falsification
checkpoint rather than a build, because the topology this document depends on is
a claim about external contracts and has to be tested before anything is built on
top of it.
