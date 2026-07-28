# Security Policy

SecondSign Core sits on the execution path before a financial agent can move
money. A defect here is not an ordinary bug, so this file says how to report one
privately, what is in scope, and what to expect back.

## Reporting a vulnerability

**Do not open a public issue for a security report.** A public issue broadcasts
the method before a fix exists, which is the one thing this project cannot
afford on its own decision path.

Report privately through GitHub:

1. Go to the [**Security** tab](https://github.com/Bestpart-Irene/secondsign-core/security/advisories/new).
2. Choose **Report a vulnerability**.

That opens a private advisory visible only to you and the maintainers. It keeps
the report, the discussion, and the eventual fix in one place, and it is how a
CVE is requested if one is warranted. No email address is required.

Please include enough to reproduce: affected version or commit, the invariant
you believe is broken (see [`docs/INVARIANTS.md`](docs/INVARIANTS.md)), and a
minimal case. **Never put real financial or customer data, credentials, or live
account identifiers in a report** — a redacted reproduction is enough, and this
project's own rules forbid that data anywhere near it.

## What to expect

- **Acknowledgement within 3 business days** that the report was received.
- **An initial assessment within 10 business days** — whether it is in scope,
  and a severity.
- Coordinated disclosure: a fix is prepared privately, and the advisory is
  published together with the release that carries it. We will credit you unless
  you ask us not to.

This is a pre-1.0 project with a small maintainer group; these are targets, not
a contractual SLA.

## Scope

**In scope** — a report that shows any of these is a security issue:

- A path that returns a **weaker** verdict than one of its inputs (monotonicity
  broken).
- Any way to reach **ALLOW**, or to skip the decision, that the invariants say
  should be impossible.
- A **fail-open** path: an error, missing context, or unavailable dependency
  that resolves to anything other than the strictest outcome.
- **Raw financial or customer data, credentials, or account identifiers**
  reaching a decision record, receipt, log, plugin input, or error output.
- An approval that is **replayable, transferable, or outlives its intent
  digest**.
- A plugin, extension, or rail adapter escaping the isolation the contract
  promises — reaching internals, granting permission, or influencing a decision
  it should not.
- A secret, key, or real identifier committed to the repository.

**Out of scope** — report these as ordinary issues, not advisories:

- Findings in the quarantined enterprise or reference trees. This policy covers
  **`secondsign-core` only**; those are not distributed from here.
- Missing hardening that breaks no stated invariant (a defence-in-depth
  suggestion is welcome as a normal issue).
- Volumetric denial of service against your own deployment, and anything
  requiring a already-compromised host or maintainer account.
- Vulnerabilities in a dependency — report those upstream; tell us if core's use
  of it is what makes it exploitable.

## Verifying what you installed

Releases carry signed [build provenance](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).
The attestation records which workflow, at which commit, produced the exact file
you have — so you can check that a wheel came from this repository rather than
from a compromised publisher account, without taking this project's word for it:

```bash
pip download --no-deps --no-binary :none: secondsign-core==<version>
gh attestation verify secondsign_core-<version>-py3-none-any.whl \
  --repo Bestpart-Irene/secondsign-core
```

Two limits worth stating, because a signature invites more trust than it earns:

- Provenance attests **where an artefact came from, not that it is correct.** A
  faithfully built release of vulnerable code verifies perfectly.
- Attestation began with the first release built by the current workflow. Older
  artefacts have none, and their absence is not evidence of tampering.

Every GitHub Action used in CI and in the release workflow is pinned to a commit
SHA rather than a tag, so what runs cannot change without a reviewed diff. The
same already applied to Foundry and gitleaks, which are pinned by version and
verified by checksum.

## What this project has not done

Stated here rather than left for a reader to discover:

- **No independent security audit.** The invariants are each bound to an
  enforcing test and the red-team matrix is executed on every run, but nobody
  outside the project has reviewed this code. Branch coverage of 100% is an
  engineering signal — it means every branch executed, not that the assertions
  are right.
- **No process boundary yet.** Core runs inside your agent's process today. The
  standalone gateway process is specified as `CORE-S019` and is not built, so
  "the agent cannot reach the rail" is currently a property of how you deploy,
  not of this software. See [Status](README.md#status).
- **No SBOM published yet**, and no OpenSSF Scorecard. Both are wanted; neither
  exists.

## Supported versions

Core is pre-1.0. Fixes land on `main` and in the next release; there is no
back-porting to older `0.x` tags yet. When the Policy Plugin API is frozen at
v1, this section will name the supported line.

| Version | Supported |
|---|---|
| `main` / latest `0.x` | ✅ |
| older `0.x` | ❌ — upgrade to the latest |
