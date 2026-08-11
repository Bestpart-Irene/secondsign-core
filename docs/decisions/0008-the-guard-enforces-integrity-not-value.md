# ADR 0008 — The constitutional guard enforces integrity, not value

Status: accepted
Date: 2026-08-11

Constrains `ONCHAIN-S005`. Answers on-chain threat C3 (account-control change),
and pins what the production Safe guard does — and, deliberately, what it does
not. Supersedes the guard-enforcement content of `ONCHAIN_COMPONENT_SPEC.md` §3.8.

## The sentence this ADR exists to protect

> **The guard keeps the 2-of-2 co-signer arrangement un-subvertable. It does not
> decide value. A transfer that is within policy and one that is not look the same
> to the guard; the co-signer and the off-chain engine tell them apart.**

## Context

The co-signer (ONCHAIN-S004) is the decision point: SecondSign's second signature
is the ALLOW verdict. That arrangement is only worth anything if the agent cannot
dismantle it on-chain — remove SecondSign as a signer, drop the threshold, replace
or delete the guard, or slip in a module that moves value with no signature. The
guard is the on-chain floor that makes those moves impossible.

Two forces have to be separated, because conflating them is a real prior mistake:

- The illustrative demos (#99/#100) put an amount cap **in the Solidity guard**.
  The 2026-08-05 architecture fixed this as the wrong model: value is decided once,
  off-chain, by one engine (policies, velocity, maker-checker, simulation) — not
  re-implemented on-chain where the guard can only see coarse calldata.
- `ONCHAIN_COMPONENT_SPEC.md` §3.8, written earlier, still lists the guard
  enforcing an asset allowlist, a target allowlist and a per-transaction cap. That
  is the same wrong model, and this ADR supersedes it. (§3.8 should be updated;
  the manifest's `forbidden` list already forbids policy in the guard.)

## Decision

### 1. The guard is integrity only

The guard enforces exactly the four constitutional invariants and refuses
`delegatecall`. It judges no amount, no counterparty, and no velocity. A normal
ERC-20 `transfer` or `approve` passes the guard on both execution paths — whether
that transfer is *allowed* is the co-signer's and the engine's question, answered
by whether the second signature exists, not by the guard.

The four invariants:

1. **SecondSign stays a required signer** — no `removeOwner` / `swapOwner` /
   `addOwnerWithThreshold` that drops or dilutes it.
2. **The threshold stays two** — no `changeThreshold`.
3. **Neither guard is removable or replaceable** — no `setGuard` / `setModuleGuard`.
4. **No value-moving or delegatecall module is enabled** — no `enableModule` /
   `disableModule`, and `delegatecall` (`operation != Call`) is refused, because it
   can rewrite ownership and the guard slots directly.

`setFallbackHandler` is refused with the same reasoning as a module change: it
alters what the account executes.

### 2. Two hooks, because there are two paths

A Safe Transaction Guard covers only `execTransaction`; module transactions take a
separate path governed by a Module Guard (Safe 1.5.0). `ONCHAIN-S001` falsified
that a single guard leaves the module path open — `setGuard(0)` down the module
path fired no hook on ≤1.4.1. So v1 is **both** guards, and the module path is
enforced, not assumed empty.

### 3. The paths are asymmetric, and that asymmetry is the recovery seam

- **Transaction path (the agent's `execTransaction`):** every account-control
  change is refused, including owner changes. The agent reconfigures nothing.
- **Module path (`checkModuleTransaction`):** the *subverting* changes are refused
  — `setGuard`, `setModuleGuard`, `changeThreshold`, `enableModule`,
  `disableModule`, `setFallbackHandler`, and `delegatecall` — but **owner changes
  are allowed.** This is the recovery capability: a lost SecondSign key is replaced
  by a `swapOwner` down the module path, which the agent's path forbids.

Invariant 1 ("remove SecondSign") is therefore enforced against the *agent* on the
transaction path; the module path leaves owner changes open **as a capability**.
What makes that capability safe — that only an approved, unexpired recovery may use
it — is the `RecoveryController`'s allowlist and timelock (a later slice, §3.11);
v1 runs zero enabled modules as defence in depth until then. The guard is
capability-based, not identity-based: it forbids the dangerous capabilities on both
paths and permits owner-recovery on the module path.

### 4. Proven by refused execution, not by reading

Every invariant is asserted by an **executed transaction that reverts at the
guard's own revert reason** — never by reading the guard's source or its
configuration. A guard that "looks right" and a guard that acts are different
things, and only the second is evidence (the standard `ONCHAIN-S001` set).

### 5. Integrity does not depend on the engine

The guard is on-chain and unconditional: it enforces the four invariants with the
off-chain engine offline, because its refusals read only the transaction and the
account, never any off-chain state. "Engine offline → the account cannot move
value" is the co-signer withholding its signature; "engine offline → the account
cannot be reconfigured" is the guard. Both are fail-closed, and neither waits on
the other.

## Alternatives rejected

**Put the value policy in the guard (§3.8).** Defence in depth if the co-signer is
bypassed, and it re-implements on-chain the policy the engine already owns —
diverging the moment the engine gains a dimension the guard cannot see (simulation,
velocity, cross-token exposure). Rejected: one decision engine; the guard is the
integrity floor, not a second policy.

**One guard.** Simpler, and `ONCHAIN-S001` proved it leaves the module path a
silent bypass. Rejected: both hooks.

**Refuse owner changes on the module path too.** Maximally strict, and it makes
key-loss recovery impossible — the account is bricked the day SecondSign's key is
lost. Rejected: owner-recovery is the module path's reason to exist; the allowlist
and timelock that bound it are the RecoveryController's job.

## Consequences

- **`onchain/src` is no longer empty.** The first production contracts ship here;
  the prohibition in the roadmap on writing there is lifted by this slice.
- **The guard and the co-signer enforce different things, and both are required.**
  Turn off the co-signer and value cannot move (no second signature); the guard
  still holds the arrangement together. Remove the guard — which nothing on-chain
  can do — and the co-signer still decides, but the module-path bypass reopens.
- **A production audit is still owed** before unrestricted real value. This slice
  writes the guard and proves its invariants by execution; an external Solidity
  audit is a separate, later milestone.
- **§3.8 is stale** on guard enforcement and should be updated to match this ADR.
