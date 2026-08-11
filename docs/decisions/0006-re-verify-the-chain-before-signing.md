# ADR 0006 — Re-verify the chain before signing, and pin the token identity

Status: accepted
Date: 2026-08-09

Constrains `ONCHAIN-S007`. Extends the digest-bound / re-verify-before-execution
posture (INV-9 / ADR 0005) onto the on-chain co-signer, and answers on-chain
threats C1 and C4.

## The sentence this ADR exists to protect

> **A co-signature is a statement about a transaction under a *known* account and
> a *known* token. If the co-signer cannot read the chain and confirm both match
> what was attested, it does not sign.**

## Context

The co-signer landed in `ONCHAIN-S004` as a library primitive. It takes the
transaction's `nonce` as a caller argument, and it judges an `approval_cap` that
is a bare integer with no token attached. Two consequences follow, and both are
the on-chain form of a threat the fiat path already closes:

- **It trusts the caller for the signable content.** A managed agent that
  proposes the transaction also supplies the nonce; the co-signer signs an
  EIP-712 hash built from it. Nothing reads the Safe's actual state, so the
  co-signer cannot notice that the account's owners, threshold, or guards have
  changed under it, that it is on the wrong chain, or that the Safe is not the
  version whose behaviour the topology was falsified against (`ONCHAIN-S001`).
  This is C4: *the code can change after the decision.* Its stated answer is that
  every dependency is **re-read before signing, and any mismatch against decision
  time sends the action back** — not signed.

- **The cap does not know its token.** `approval_cap=1_000_000` bounds an amount
  with no unit and no contract. A `transfer`/`approve` to a look-alike token, or
  to canonical USDC after its implementation has been upgraded, is judged the
  same as one to the real asset. This is C1: an approval grants a standing draw
  capability *to an address, not to code*, so the identity that must be bound is
  the token's — and because canonical USDC is a proxy, C4 is explicit that a
  proxy's own code hash is not enough: what is bound is the **resolved
  implementation and that implementation's code hash**.

Core has a hard posture that must not be broken to fix this: it takes on no
network dependency and its runtime flow is deterministic (ADR 0001). A live RPC
client on the decision path would violate both.

## Decision

### 1. Chain reads are a protocol, not a client

Core defines `ChainStateReader`, a protocol that returns the facts the co-signer
must confirm: a `SafeChainState` (nonce, owners, threshold, transaction guard,
module guard, chain id, Safe version) and a `TokenIdentity` (the resolved
implementation address and its code hash) for a token. Core ships **only the
protocol and a deterministic in-memory reference double**; the live Base RPC
implementation — including how a particular proxy standard resolves its
implementation slot — belongs to the deployment, never to core. The decision
stays a pure function of the read state, so determinism (ADR 0001) holds: the
non-determinism is the chain, and it lives outside the boundary, exactly as the
spend window and the audit sink already do.

This is the same open/closed boundary the signing key itself will take: the
contract is public so a self-hoster can implement it and verify the behaviour;
the reliable, live implementation is the operated service.

### 2. Re-verification runs before every signature, and refuses on any drift

Before it signs — on the direct path and on the review-resolve path both — the
co-signer reads the Safe's live state and compares it to an attested
`ExpectedSafeConfig`. Any mismatch refuses and is recorded; it does not sign and
does not approximate:

- a live chain id that is not the attested one → refuse (a signature valid on the
  wrong chain is a cross-chain replay surface, C-RT-019);
- a Safe version outside the attested one → refuse (outside the model);
- owners, threshold, transaction guard, or module guard changed from the attested
  set → refuse (an account-control change, C-RT-007/016 — `structural_change`);
- the pinned token's resolved implementation or its code hash changed → refuse
  (`implementation_moved`, C-RT-010/011).

The nonce is **read from the chain, not from the caller.** A held review records
the nonce it was built against; if the chain nonce has advanced by the time a
checker answers, the held transaction is stale — the content the human approved
can no longer be the account's next transaction — and it refuses rather than
signs a hash the Safe would reject.

### 3. The token is pinned, by identity

The policy gains a token allowlist: a `transfer`/`approve` whose target is not the
pinned token address is denied (`token_not_allowlisted`, a new closed reason code
tracing to C-RT-011/024). Address alone is a necessary but not sufficient bind —
the implementation-and-code-hash check in §2 is what makes it identity rather than
a name — but the address check belongs in the static policy so an unpinned token
is refused without a chain read at all.

### 4. Absence is refusal

A co-signer constructed without a `ChainStateReader` and an `ExpectedSafeConfig`
does not fall back to trusting the caller — it refuses to sign. The attestation is
not optional configuration; it is the precondition of a signature. This is a
breaking change to the `ONCHAIN-S004` constructor, made deliberately: a signing
boundary whose safety depends on a dependency being wired must fail closed when it
is not.

## Alternatives rejected

**Trust the caller's nonce, verify nothing.** The `ONCHAIN-S004` status quo. It
signs an EIP-712 hash over content a hostile proposer chose, against an account
whose configuration it never confirmed. Rejected: it is precisely C4 left open.

**Put a live RPC client in core.** Simplest to wire, and it makes the decision
path non-deterministic and gives core a network dependency and an RPC secret —
breaking ADR 0001 and the no-network posture the whole architecture rests on.
Rejected: the reader is a protocol; the client is the deployment's.

**Bind only the token's own code hash.** Cheap, and wrong for a proxy — and
canonical USDC is a proxy. Its proxy bytecode is stable while Circle can move the
implementation slot, so a code hash of the proxy address would pass an upgraded
token. C4 says bind the resolved implementation; this ADR does.

**Make re-verification optional (default on, allow off).** Would keep the old
tests unchanged. It also makes fail-open the default for any caller who forgets to
wire it — the exact shape of defect the review pass before this one kept finding.
Rejected: absence refuses.

**Re-verify only on the direct-sign path, not on resolve.** Smaller change. It
leaves the review path — which also produces a signature, after a delay during
which the chain moves the most — signing without a fresh read. Rejected: "before
every signature" means both paths.

## Consequences

- **The `ONCHAIN-S004` constructor is breaking.** A co-signer now requires a
  reader and an `ExpectedSafeConfig`, and `cosign` no longer takes a `nonce`. Call
  sites and tests move with it.
- **A new public contract appears in `secondsign.onchain`.** `ChainStateReader`,
  `SafeChainState`, `TokenIdentity` and `ExpectedSafeConfig` are the surface a
  deployment implements against. They are boundary data and a port — shared, with
  an import closure free of the control plane — while the deciding policy stays
  control-plane (as `onchain.policy` already is).
- **A held review can now go stale.** A REVIEW held across a Safe nonce advance
  refuses on resolve and must be re-proposed. This is re-decision, not
  re-approval (ADR 0005's principle, applied to the chain moving).
- **The pilot scope is now expressible.** With the token pinned to one identity
  and the account re-verified, "a Base Safe that only touches canonical USDC" is a
  configuration, not a promise — which is what the first pilot needs.
