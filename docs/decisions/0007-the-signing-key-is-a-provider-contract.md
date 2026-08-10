# ADR 0007 — The signing key is a provider contract, not a raw key

Status: accepted
Date: 2026-08-10

Constrains `ONCHAIN-S009`. Extends INV-12 (the control plane holds the signing
capability; the agent cannot reach it) to the *form* the on-chain signing key
takes, and answers on-chain threat C11.

## The sentence this ADR exists to protect

> **The co-signer signs through a capability it is handed; it never holds the raw
> key, and the contract it holds cannot give the key back.**

## Context

`ONCHAIN-S004` landed the co-signer as a library primitive: it takes
`private_key: bytes`, reconstructs an account with `eth_account`, and signs. That
is fine for a library test and wrong for custody of real value. A raw key in
application configuration is a key in process memory, in a config store, and one
careless log line from disclosure; it cannot be rotated without a redeploy, cannot
be versioned, and cannot be kept in an HSM. C11 is the threat — signing capability
reaching anywhere it should not — and a raw key is the widest surface for it.

Two constraints shape the fix. Core must keep its no-crypto-at-runtime discipline
(`eth_account` is an optional dependency; importing core pulls in no signing
library). And the reliable custody of a key — KMS/HSM, rotation, per-wallet keys,
no export — is operational, multi-tenant work that belongs in the enterprise plane,
not in the open kernel.

## Decision

### 1. A `SignerProvider` protocol, in core

The co-signer takes a `SignerProvider`, not `private_key: bytes`. The contract is
exactly two things: the signer's **address**, and **`sign_hash(hash) -> signature`**.
It exposes nothing that yields the key. The co-signer signs through it and reads
its address through it; it never reconstructs or holds raw key material.

### 2. Core ships only a reference implementation

`LocalSigner` wraps `eth_account` behind the protocol — the current behaviour,
now the *reference* rather than the *only* implementation. It keeps `eth_account`
optional and lazily imported, so core still imports with no crypto present. The
production implementation — a KMS/HSM-backed signer, key lifecycle, rotation,
versioning, per-wallet keys — implements the same protocol in the enterprise
plane and is never pulled into core.

### 3. The contract is the open/closed boundary

The protocol is public so a self-hoster can implement it and verify the co-signer
against it, and so a security lead can read exactly what the co-signer asks of a
key (sign this hash; tell me your address — nothing else). The operated,
key-holding implementation is the product. This is the same boundary the
`ChainStateReader` takes (ADR 0006): the contract is core, the reliable live
implementation is the deployment's. A `SignerProvider` that does not use
`eth_account` at all must be able to drive the co-signer — the test asserts it,
which is what proves the KMS implementation can live outside core.

### 4. Absence of a key in core is structural

The co-signer holds a `SignerProvider`, and a provider's contract cannot return
the key, so there is no call site at which raw key material sits in the co-signer.
A KMS provider never has the key in the process at all. `LocalSigner` does hold one
(it must, to sign locally) — it is the reference, not what a deployment runs — and
it too exposes no export through the contract.

## Alternatives rejected

**Keep `private_key: bytes`.** The `ONCHAIN-S004` status quo. A raw key in app
config is not a production key form (C11); rejected.

**Put a KMS client in core.** Simplest single implementation, and it gives core a
crypto/network runtime dependency and a cloud credential, breaking the no-crypto
discipline and the open/closed split. Rejected: core gets the protocol, the KMS
client is the enterprise plane's.

**Expose the key through the provider (a `key()` / export method) for
"flexibility".** Any such method is the exact disclosure surface this ADR removes;
a contract that can return the key is a raw key with extra steps. Rejected.

**A generic `Signer` shared type.** Signing capability mediates a control-plane
asset (the key), so the provider is control-plane, not shared — an agent-surface
module must not import it. It lives on the control-plane side with the co-signer.

## Consequences

- **The `ONCHAIN-S004` constructor changes** (stacked on `ONCHAIN-S007`): the
  co-signer takes a `SignerProvider`; `LocalSigner(private_key)` reproduces the old
  behaviour at call sites and tests.
- **A public contract appears** that the enterprise KMS implements — the seam
  along which "kernel open, control plane closed" is drawn in code.
- **Key lifecycle is now expressible where it belongs.** Rotation, versioning,
  per-wallet keys and no-export are properties of the provider implementation, so
  they can be added in the enterprise plane without touching the co-signer.
