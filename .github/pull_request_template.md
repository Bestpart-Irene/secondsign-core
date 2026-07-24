<!--
One slice, one branch, one pull request. If this PR does more than one slice,
split it — the review below cannot be given honestly for two changes at once.
-->

## Slice

- **Slice id:** <!-- e.g. CORE-S006; must match the branch name, CI reads it -->
- **Title:**
- **Threats addressed:** <!-- ids from docs/THREAT_MODEL.md, or "none — why" -->

## What this changes

<!-- Two or three lines. What can the system do afterwards that it could not before? -->

## Tests

- **Added:** <!-- files -->
- **Written RED first:** <!-- which, and what defect each proved before the fix -->
- **Acceptance criteria covered:** <!-- from the manifest -->

## Invariants

Tick only what you have actually reasoned about. An untouched invariant needs
no tick; a touched one needs a sentence.

- [ ] **Fail closed** — every new error, timeout, and unknown path takes the
      strictest branch
- [ ] **Monotonic** — no path returns a verdict weaker than any of its inputs
- [ ] **Immutable, digest-bound intent** — the decided value is the executed
      value
- [ ] **Approvals one-shot, expiring, digest-bound** — never bound to an agent,
      a session, or an action type
- [ ] **Control plane unreachable** — no new path from the managed agent to
      limits, roster, idempotency store, ledger, or keys
- [ ] **No raw financial or customer data** — including tests and fixtures;
      money is integer minor units
- [ ] **Deterministic** — identical inputs give identical output, reason
      ordering included
- [ ] **Rail-agnostic** — no rail-specific knowledge entered the decision layer

Invariants touched, and why each still holds:

## Scope

- **Declared scope:** <!-- from the manifest -->
- **Anything touched outside it:** <!-- "none", or what and why the manifest was widened first -->

## Authorship boundary

- [ ] No third-party source, comment, identifier, module layout, or test
      implementation was copied or adapted
- [ ] Nothing here was written by reading another implementation and producing
      something similar
- [ ] Every commit is signed off (`git commit -s`)
- [ ] Any third-party source that informed this change is named below, with its
      licence
- [ ] AI assistance used in this change is noted below

Sources / AI assistance:

## Docs

- [ ] `README.md` updated if public behaviour moved
- [ ] `docs/INVARIANTS.md` updated if an invariant's enforcement moved from a
      promised slice to a real test
- [ ] `docs/EXTENSION_CONTRACTS.md` updated if the published surface changed
- [ ] ADR added under `docs/decisions/` if this is architectural

## Risks

<!-- Deviations from the manifest, shortcuts, tech debt introduced, or "none" -->
