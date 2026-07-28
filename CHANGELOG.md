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

[Unreleased]: https://github.com/Bestpart-Irene/secondsign-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bestpart-Irene/secondsign-core/releases/tag/v0.1.0
