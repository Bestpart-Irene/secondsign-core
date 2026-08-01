# Changelog

Notable changes to SecondSign Core, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versions follow [Semantic Versioning](https://semver.org/), with one thing worth
saying plainly while the project is pre-1.0: **`0.x` releases may change the
public surface in a minor bump.** The contract surface frozen in `CORE-S005`
(`secondsign.contracts`, `CONTRACT_VERSION = 1`) is the part that is held stable
and ratcheted by test; everything else may still move. Pin an exact version if
you are building on it.

Security-relevant entries are marked **[security]**. A change that weakens a
guarantee will never appear as a bare bullet — it requires an ADR under
[`docs/decisions/`](docs/decisions/), and that ADR will be linked here.

## [Unreleased]

Nothing released yet from this section. What is queued, and what is available to
pick up, is in [`docs/slices/STATUS.md`](docs/slices/STATUS.md).

## [0.2.0] — 2026-08-01

The release that closes 0.1.0's first known limitation: the process boundary
now exists. An agent holds a client certificate and no rail credential; the
gateway holds the credential and the decision. The property "the agent cannot
reach the rail" is now something a deployment inherits from the shipped
topology and CI falsifies on purpose, rather than a convention the reader is
asked to keep.

Pre-1.0 surface changes in this release: the wire contract (`WIRE_VERSION = 1`)
is new; `AuditReceipt` gained `principal_ref`. The plugin contract surface
(`secondsign.contracts`, `CONTRACT_VERSION = 1`) is unchanged.

### Added

- **Standalone gateway process** (`secondsign.gateway.server`, `CORE-S019`).
  mTLS termination against a private CA, the client principal read from the
  certificate's single URI SAN and never from the body, and a seven-condition
  bind check where a failed condition — or an unrecognised `SECONDSIGN_*`
  setting — refuses to start. `/authorize` decides end to end: authenticate,
  decide, dispatch, answer, with the rail's ledger growing by exactly one.
- **`secondsign-client`**, a second distribution under [`client/`](client/):
  the agent-side half of the boundary, pydantic-only, carrying no gateway, no
  policy, no credential handling — asserted against the built wheel. Wire
  version mismatch is a refusal in all four directions, and every transport
  failure reads `refused` by type.
- **Reference deployment** ([`deploy/reference/`](deploy/reference/)): a
  Compose topology in which the agent container has no route to the rail, plus
  a CI gate that is itself falsified — `compose.joined.yaml` adds the one line
  that breaks isolation, and the build requires the real isolation tests to go
  red against it.
- **Wire conformance kit** (`WireClientConformance`): certifies a third-party
  agent-side client through a three-line adapter, against a probe gateway that
  can produce the malformed answers the real one cannot be asked for, with 19
  deliberately non-conformant candidates the kit must catch.
- **Control-plane pieces** behind the gateway: `controlplane.fingerprint`
  (INV-12's fifth asset as a real object), `controlplane.window` (the
  trailing-window spend ledger), and `rails.http` (2xx success, 4xx failure,
  everything else unknown).
- A worked example of a policy plugin certified by the conformance kit
  ([#49](https://github.com/Bestpart-Irene/secondsign-core/pull/49), external
  contribution).
- Malformed `Fingerprint` values are now explained without echoing the
  identifier (`CORE-S021`,
  [#44](https://github.com/Bestpart-Irene/secondsign-core/pull/44), external
  contribution).

### Changed

- **[security]** What the wire does not say closes strictest: provenance is
  untrusted, the beneficiary is new, cross-border is true — the dimensions an
  injected agent would most like to choose are not read from the request, and
  the one claim the wire does carry may only tighten the decision. What wire
  v1 cannot express is refused, not approximated.
- **[security]** An indeterminate dispatch reads `refused` to the agent while
  the receipt records `unknown` — and it consumes the spending window, so an
  ambiguous first answer cannot be spent twice.
- **[security]** A leaf certificate that scoped nothing was good for
  everything: under RFC 5280 a leaf with no `keyUsage` and no
  `extendedKeyUsage` is unrestricted, so the gateway now reads both extensions
  from the DER and refuses their absence; the reference PKI issues
  `digitalSignature` leaves with RFC 5280 key identifiers. Found by test
  before release, fixed with no new runtime dependency.
- CI is now fronted by a single required **`CI gate`** (`tools/ci_gates.py`)
  that decides and verifies that every conditional job ran or was skipped for
  a recorded reason — a skipped job can no longer read as a green one.
- Release supply chain: every workflow action is pinned to a commit SHA, and
  release artefacts carry signed build provenance verifiable with
  `gh attestation verify`.
- The sdist now ships `deploy/` and `client/`, so the test suite is
  self-sufficient from the sdist alone.

### Known limitations

- **A `REVIEW` verdict is still a slower refusal.** The maker-checker flow
  that carries a review to a human and back is built and under review as
  `CORE-S022`; the approver's own channel is `CORE-S023`. Until both land, the
  reference deployment deliberately sets no review threshold.
- **One shipped policy**, unchanged from 0.1.0.
- **No independent security review**, unchanged from 0.1.0.

## [0.1.0] — 2026-07-25

First public release. The whole decision path, end to end, with each guarantee
bound to the test that enforces it in
[`docs/INVARIANTS.md`](docs/INVARIANTS.md).

### Added

- **Plugin contract surface** (`secondsign.contracts`), frozen at
  `CONTRACT_VERSION = 1`. Closed, immutable boundary models; combination is
  monotone and property-tested; a plugin has no vocabulary for granting
  permission — `PluginVerdict` has no `ALLOW` member.
- **Intent model** (`secondsign.intent`). `TransactionIntent` with a
  deterministic, versioned `IntentDigest` covering every material field. Money
  is integer minor units; account and customer references are opaque
  fingerprints.
- **Policy** (`secondsign.policy`). `AmountWindowPolicy`, judging limits on a
  sliding-window aggregate; missing context resolves to the strictest default.
- **Decision engine** (`secondsign.decision`). ALLOW / REVIEW / DENY, monotone
  by construction; evaluation failure resolves to DENY; every non-ALLOW carries
  stable reason codes.
- **Human approval** (`secondsign.approval`). Digest-bound maker-checker.
  Approvals are one-shot, expiring, and bound to one intent; a missing expiry is
  treated as expired. Maker and checker are distinct types.
- **Execution gateway** (`secondsign.gateway`). Re-verifies the digest
  immediately before dispatch, reserves idempotency before executing rather than
  recording after, and reports success / failure / unknown as three states.
- **Audit** (`secondsign.audit`). Redacted, hash-chained receipts. Every
  non-ALLOW path produces one, including error and degraded paths; a receipt
  that cannot be written is a fail-closed event.
- **Rail adapters** (`secondsign.adapters`). Stripe and Alpaca, each certified
  against `RailAdapterConformance`. Idempotency keys are derived, never accepted
  from the caller; source trust can only be downgraded.
- **Conformance kits** (`secondsign.conformance`) for policy plugins, rail
  adapters, approval providers and audit sinks. A third party certifies an
  extension by inheriting a suite, and the kits are themselves tested to reject
  non-conformant extensions.
- **Agent surface** (`secondsign.agent`). `AuthorizationRequest` /
  `AuthorizationOutcome` and the `SecondSignClient` protocol — one verb, no
  parameter through which an agent could pass an approval, a credential or a
  setting. The outcome deliberately carries less than the control plane knows.
- **[security]** Structural control-plane isolation (`CORE-S017`, INV-12). The
  limits, approver roster, idempotency store, audit ledger and fingerprint keys
  are unreachable from the agent surface by import structure, enforced by
  `lint-imports` and by an architecture test that discovers modules rather than
  naming them. Reading any setting looser than its strictest default requires a
  matching, unexpired, approved ledger record.
- **On-chain threat model** ([`docs/ONCHAIN_THREAT_MODEL.md`](docs/ONCHAIN_THREAT_MODEL.md)),
  C1–C14, with its red-team matrix. Designed and published; **not implemented**.

### Known limitations

- **No process boundary yet.** Core runs in your agent's process, so "the agent
  cannot reach the rail" is a property of your deployment rather than of this
  software. The standalone gateway process and credential-free agent-side client
  are specified as `CORE-S019` and not built. Right for development and
  evaluation; not yet for production custody of money.
- **One shipped policy.** `AmountWindowPolicy` is the only policy in the box.
  Anything else is a plugin you write against the published contract.
- **No independent security review.** The invariants are bound to tests and the
  red-team matrix is executed, but nobody outside the project has audited it.

[Unreleased]: https://github.com/Bestpart-Irene/secondsign-core/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Bestpart-Irene/secondsign-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Bestpart-Irene/secondsign-core/releases/tag/v0.1.0
