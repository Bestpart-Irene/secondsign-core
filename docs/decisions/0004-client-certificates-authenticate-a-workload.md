# ADR 0004 — Client certificates authenticate a workload, never an approver

Status: accepted
Date: 2026-07-28

Constrains `CORE-S019`. Depends on ADR 0003, which decided the client is a
separate distribution reaching the gateway over a network.

## The sentence this ADR exists to protect

> **A client certificate authenticates a workload and derives policy scope. It
> is never an approval identity, and it never grants permission.**

Everything below is machinery for keeping that true.

## Context

ADR 0003 put a network between the agent and the gateway. A network hop needs a
peer identity, and the moment a system has a verified identity it acquires a
temptation: the caller is authenticated, so let the authenticated caller do
more. That is how `mTLS` turns into an authorization mechanism, and it is the
exact shape this project already refused once — a plugin has no `ALLOW` in its
vocabulary (ADR 0002) precisely so that "the plugin cleared this" is not an
expressible statement.

Two boundaries are at risk. **Scope** must come from the authenticated caller
rather than from what a request says about itself, which the threat model
already requires. **Approval** must keep coming from the approval provider, with
maker and checker as distinct types (INV-10). A design that lets a certificate
become a `MakerIdentity` has quietly given an agent the ability to be one of the
two humans in its own maker-checker pair.

## Decision

### 1. What the certificate represents

An **authenticated agent workload** — a client deployment. Not a natural person,
and not an approval identity.

- Identity is the certificate's **URI SAN**, read as a stable `ClientPrincipal`.
- The gateway **refuses** the connection when the SAN is missing, when more than
  one identity SAN is present, when it is malformed, or when the principal is
  not on the allowlist. Ambiguous identity is no identity.
- `ClientPrincipal` may be used for exactly three things: selecting **policy
  scope**, namespacing **rate limits and idempotency**, and **audit
  correlation**.
- Audit records carry a **keyed fingerprint** of the principal, never the raw
  SAN — the same rule every other identifier in this system already obeys.
- The principal is **derived from the TLS session**. A request body that carries
  or overrides it is refused, not ignored; accepting-and-ignoring leaves a field
  that a later change can start honouring.
- **Maker and checker continue to come from the approval provider.** A client
  certificate never becomes a `MakerIdentity`, and under no circumstances a
  `CheckerIdentity`.

mTLS establishes *who is asking*. It says nothing about whether the request is
permitted.

### 2. Idempotency namespacing

A reservation binds:

```text
authenticated_client_principal + request_ref + intent_digest
```

`request_ref` is supplied by the agent. Two workloads sharing a namespace could
therefore collide — accidentally, and then a retry by one is de-duplicated
against the other's reservation; or deliberately, which is a way to make another
workload's authorization disappear. The principal is the only term in that key
the agent cannot choose, so it is what separates the namespaces.

### 3. Key custody in the reference deployment

The reference deployment **does not pretend to be a secret store.**

- The test harness generates an ephemeral CA, a gateway leaf and a client leaf at
  start-up. **No private key is ever committed.**
- Material reaches containers as **read-only file mounts**, not environment
  variables.
- The **gateway container** gets the gateway key and the rail credential. The
  **agent container** gets the client key and nothing else — never the CA
  signing key, never the gateway key, never the rail credential.
- The documentation states plainly that a Compose mount demonstrates **custody
  separation** and provides **no secret-at-rest guarantee**. Vault, Kubernetes
  Secrets and cloud KMS are deployment concerns; the gateway's interface is a
  file path.

An adversarial case asserts this from inside the agent container by walking its
environment and mounts. Note what it may *not* assert: the client private key is
supposed to be there. "The agent container holds no credential" would be a false
claim, and stating it would be the same error as calling `ModuleNotFoundError`
the boundary.

### 4. Revocation

**v1 uses short-lived certificates and implements no online revocation.**

Described accurately, because the temptation is to describe it well:

> There is no online revocation. A leaked certificate remains valid until it
> expires.

- Client leaf validity is capped at **24 hours**; the gateway refuses anything
  longer.
- The reference deployment issues **1-hour** certificates.
- `notBefore`, `notAfter`, key usage and the **client-auth EKU** are all
  strictly verified.
- **CA bundle rotation** is supported: old and new CA overlap briefly, then the
  old one is removed.
- Emergency response is to **remove the principal or CA from the allowlist** and
  restart, or reload atomically.
- A certificate with no expiry, or a setting that disables time validation, is
  refused. There is no such configuration.

CRL and OCSP are deliberately left to a later slice. Both introduce network
availability, cache staleness and fail-closed behaviour on a path where this
system already fails closed for other reasons, and mixing that in here would
make one change carry two arguments.

### 5. The minimum for a non-loopback listener

On loopback, the process boundary is the authentication. Off it, the gateway
starts **only** when all of these hold:

1. a server certificate;
2. its private key;
3. a client CA bundle;
4. client certificate verification **enabled**;
5. a minimum TLS version;
6. a principal successfully derived from the presented certificate;
7. unknown principals resolving **fail-closed**.

**"TLS is configured" is not sufficient.** A listener with a server certificate
but no client verification is an unauthenticated listener wearing encryption,
and the gateway refuses to start rather than warning.

## Consequences

- **A compromised workload can spend its own scope until its certificate
  expires** — up to 24 hours in the worst permitted case, one hour as deployed
  in the reference. That is the accepted cost of having no online revocation,
  and it is stated in the threat model as residual risk rather than left for
  someone to work out.
- **Certificate issuance becomes an operational dependency.** One-hour
  certificates need automated issuance; an operator who cannot automate it will
  be tempted toward the 24-hour cap, which is why the cap is enforced by the
  gateway rather than recommended.
- **`ClientPrincipal` is a new public concept** on the wire contract, and
  therefore versioned and ratcheted like the rest of it.
- **Idempotency keys change shape.** They are now namespaced by principal, so a
  key computed before this change does not match one computed after. Pre-1.0,
  and no deployment holds durable reservations yet.
