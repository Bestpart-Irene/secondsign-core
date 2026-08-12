# ADR 0009 — Recovery is a bounded user of the swapOwner capability, not a new hole

Status: accepted
Date: 2026-08-11

Constrains `ONCHAIN-S010`. Builds directly on ADR 0008 (the constitutional double
guard) and answers the residual that ADR left open: the module path *permits*
`swapOwner`, but nothing on-chain bounds **who** may use it or **when**. This ADR
pins the `RecoveryController` — the single, timelocked, bounded user of that
capability — and, deliberately, what it cannot do.

## The sentence this ADR exists to protect

> **A lost SecondSign key can be replaced without the replacement being, on-chain,
> indistinguishable from the theft it is meant to survive. Recovery is one
> initiator, one owner-rotation, after one timelock the account itself can veto —
> and nothing else.**

## Context

ADR 0008 made the module path permit exactly `swapOwner` (a threshold-preserving
owner rotation) as the recovery seam, and forbade everything else on both paths.
It left two things to a later slice:

- **The capability is unbounded.** The guard is capability-based: it admits
  `swapOwner` from *any* enabled module, on purpose (identity is not the guard's
  job). So "who may rotate an owner, and after what delay" is not yet answered.
- **Recovery must not be a guard bypass** (`ONCHAIN_THREAT_MODEL.md`, C11). A
  recovery mechanism that reaches owner-rotation through an unguarded path is
  indistinguishable from the attack. Where recovery takes the module path, what the
  guard admits must be "a specific approved and unexpired recovery record", not "a
  class of caller".

Two facts from ADR 0008 make the bound clean, and this ADR leans on both:

1. **The module set is frozen at setup.** Both guards refuse `enableModule` on both
   paths, so after the account is set up no new module can ever be added. If setup
   enables exactly one module — the `RecoveryController` — then it is *permanently*
   the only module that can reach `swapOwner`. "Sole module" is guard-enforced, not
   a deployment convention.
2. **`swapOwner` preserves the owner count and the threshold.** So recovery cannot
   change the 2-of-2 arrangement (invariant 2 holds *through* recovery); it can only
   change *which* key is the second signer.

## Decision

### 1. One initiator, one rotation, one timelock, one veto

The `RecoveryController` is a Safe module, enabled as the **sole** module at setup.
It holds one piece of configuration set at construction and never changed on-chain:
a single **`recoveryInitiator`** address (the customer's cold recovery key) and a
**`delay`** (the timelock). It exposes exactly three actions and no others:

- **`requestRecovery(prevOwner, oldOwner, newOwner)`** — callable **only** by
  `recoveryInitiator`. Records one pending rotation with `readyAt = now + delay`.
  A new request replaces any pending one (the initiator can correct a mistake); it
  never executes anything.
- **`cancelRecovery(...)`** — callable **only by the account's own authority**
  (`msg.sender == safe`, i.e. a normal `execTransaction`, which on a live account
  means the 2-of-2 co-signer agreed). Clears the pending request. This is the veto.
- **`executeRecovery(...)`** — callable only by `recoveryInitiator`, only once
  `readyAt` has passed. It makes exactly one call:
  `execTransactionFromModule(safe, safe, swapOwner(prevOwner, oldOwner, newOwner), Call)`.
  The ADR-0008 module guard admits the `swapOwner`; the rotation executes. The
  request is cleared (one-shot; a request id prevents replay).

The controller can reach **no** account-control operation other than `swapOwner`.
It never encodes `setGuard`, `changeThreshold`, `enableModule`, `setFallbackHandler`
or a `delegatecall`; there is no path through it to any of them. So even though the
guard would *admit* those from a module, the only module that exists cannot *emit*
them.

### 2. The bound lives in the controller, not the guard

This is how ADR 0008's capability-based guard and the threat model's
"explicit allowlist + timelock" are reconciled without touching S005: the guard
stays the capability floor (admits `swapOwner` from the frozen module set), and the
**allowlist (one initiator) and timelock live inside the controller**. What the
guard ultimately admits is therefore a specific, approved, unexpired record —
because the one module that can call it will only call it after its own checks.

### 3. The veto is the account's own authority, and its limits are stated

`cancelRecovery` requires `msg.sender == safe` — the account acting as itself,
which on a live 2-of-2 means both the agent and SecondSign agreed. This is chosen
over "any current owner may cancel" deliberately:

- In the **legitimate** case (SecondSign's key is lost) there is nothing to veto,
  and no honest party is missing that matters — the rotation completes after the
  delay. A "any current owner may cancel" rule would instead let a **malicious agent
  grief every legitimate recovery**, freezing the account permanently (with
  SecondSign lost, the agent alone cannot even move value — so griefing recovery is
  pure denial with no offsetting benefit to anyone). Requiring the account's own
  authority removes that grief vector.
- In the **hostile** case (the cold recovery key is stolen while SecondSign is
  present) the 2-of-2 vetoes the attacker's request during the delay.

The residual is stated, not hidden: a hostile recovery succeeds only if the cold
recovery key is stolen **and** the agent colludes (so the 2-of-2 veto is
unreachable) — two independent compromises, in a state where the attacker already
holds two of the three relevant credentials. `M`-of-`N` guardians (§4, deferred)
is the mitigation for accounts that need to close even this.

### 4. Proven by executed transaction, not by reading

Every claim below is asserted by an **executed** module transaction, in the
ONCHAIN-S001/S005 style — never by reading the controller's source:

1. only `recoveryInitiator` can open or execute a recovery;
2. `executeRecovery` before `readyAt` is refused; after it, the `swapOwner` executes
   and the account count and threshold are unchanged;
3. the account's own authority can cancel a pending recovery, and a cleared request
   cannot be replayed;
4. the controller cannot rotate anything but an owner — there is no reachable path
   to `setGuard`, `changeThreshold`, `enableModule`, `setFallbackHandler` or a
   `delegatecall`.

## Alternatives rejected

**Put the allowlist in the guard.** Make the module guard admit `swapOwner` only
from a pinned controller address. Defensible, and it contradicts ADR 0008's
capability-based stance and forces a change to a merged, `stop_for_human` guard.
Rejected: the module set is already frozen at setup, so the guard's "any module"
is the controller by construction; the bound belongs in the controller.

**`M`-of-`N` guardians for v1.** Strictly stronger against a stolen recovery key,
and a bigger build with more customer-side setup, unneeded to close the residual
S005 flagged. Rejected **for v1**, kept as the documented upgrade path; the single
initiator is a constructor seam an `M`-of-`N` policy can later sit behind.

**SecondSign co-signs recovery (2-of-2 recovery).** A strong "even recovery is
dual-controlled" story, and it couples recovery to SecondSign's availability —
SecondSign down means recovery is *also* blocked, partly reintroducing the very
stuck-account risk recovery exists to remove. Rejected.

**Any current owner may cancel.** See §3 — it trades the theft-with-colluding-agent
residual for a malicious-agent griefing vector that freezes legitimate recovery.
Rejected in favour of the account's own authority.

## Consequences

- **The `RecoveryController` is the only module the account ever runs**, and S005's
  frozen module set makes that permanent. Enabling it is part of the atomic setup;
  no second module can be added afterwards.
- **Invariant 1 has exactly one bounded exception, and it is on-chain legible**: a
  single initiator, after a timelock, vetoable by the account, rotating one owner.
- **The stated residual** (stolen recovery key + colluding agent) is real and
  documented; `M`-of-`N` guardians is the named mitigation, deferred.
- **A production audit is still owed** before unrestricted real value — this slice
  proves the controller's bounds by execution; an external audit is a later
  milestone (as for S005).
