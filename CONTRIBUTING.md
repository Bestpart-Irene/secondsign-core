# Contributing to SecondSign Core

## Developer Certificate of Origin (required)

Every commit must carry a `Signed-off-by` line:

```bash
git commit -s
```

By signing off you certify the [Developer Certificate of Origin
1.1](https://developercertificate.org/) — in short, that you wrote the
contribution or otherwise have the right to submit it under this project's
licence, and that you understand the contribution and your sign-off are public
and permanent.

**Why this project enforces it from the first commit:** without a DCO or CLA,
copyright in a multi-contributor project ends up distributed across every
individual author, and no single person — not even the maintainer — can then
relicense, warrant provenance, or answer an acquirer's diligence question on
behalf of the project. Adding this later is far more expensive than adding it
now.

## Authorship boundary

This repository is authored from scratch, and contributions must keep it that
way.

**Never copy expression from a third-party codebase** — not source, comments,
identifiers, module layout, test implementations, or configuration structure.
Requirements, threat analysis, and externally observable behaviour may inform a
design; the way someone else wrote it may not. "I checked how another project
did this and wrote something similar" is the thing this rule exists to prevent,
and it is not made acceptable by retyping.

If a contribution was informed by any third-party source, say so in the pull
request with the source and its licence. That disclosure costs a contributor
nothing and is the difference between a clean record and an unanswerable
question later.

## The slice protocol

All work lands as a **slice**: one branch, one review, one reviewable change
with declared scope. This is what lets contributors — human or agent — extend
the project without a maintainer explaining the design each time.

1. **Pick or propose a slice.** Existing queue:
   [`docs/slices/roadmap.yaml`](docs/slices/roadmap.yaml). For something new,
   copy [`docs/slices/TEMPLATE.yaml`](docs/slices/TEMPLATE.yaml) and open it as
   the first commit of your branch, so scope is agreed before code exists.
   Validate it: `python tools/validate_slice.py path/to/slice.yaml`
2. **Write the failing test first**, and confirm it actually fails. A test that
   passes before the implementation exists is testing nothing.
3. **Implement minimally.** Stay inside the declared `scope`. A change outside
   it is a scope violation, not a bonus.
4. **Run every gate** (below).
5. **Update docs**, and add an ADR under [`docs/decisions/`](docs/decisions/)
   if the change is architectural or changes a guarantee.
6. **Commit with `git commit -s`.**

Every design decision must trace to a threat in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). A change on the decision path
that traces to no threat needs an analysis or does not belong.

## Gates

```bash
ruff check .
ruff format --check .
mypy src
pytest
lint-imports
python tools/validate_slice.py docs/slices/roadmap.yaml
python tools/check_slice_scope.py
```


All of these run in CI on every pull request, plus a secret scan, a DCO check,
a build check, and a dependency licence review.

## Test layout

| Directory | Purpose |
|---|---|
| `tests/unit/` | Behaviour of a single component |
| `tests/properties/` | Algebraic laws, via Hypothesis — combination, ordering, digests |
| `tests/contracts/` | The published extension surface |
| `tests/conformance/` | That the conformance kits certify correctly, including rejecting bad extensions |
| `tests/architecture/` | Invariants enforced across the whole package by discovery, so a new model is covered the moment it exists |
| `tests/redteam/` | Adversarial regression per threat model section 6 |

Only `contracts/`, `conformance/` and `architecture/` exist so far. The rest are
created by the slice that first needs them — an empty directory with a
placeholder file suggests coverage that is not there, and the honest signal is
its absence. `tests/redteam/` in particular waits for something to attack: there
is no decision path yet, and a corpus written against components that do not
exist would be a suite of tests that pass because nothing runs.

## Extending rather than changing core

Adding a rail, a policy source, an approval channel or an audit destination
should not require changing core. See
[`docs/EXTENSION_CONTRACTS.md`](docs/EXTENSION_CONTRACTS.md) — you certify your
extension by inheriting a conformance suite, not by persuading a reviewer.

If you need a fact the published view does not carry, that is a core change:
open an issue proposing a new *derived, redacted* dimension and expect to
justify it against the threat model. There is no metadata escape hatch, by
design.

## Also

- No raw financial or customer data in code, tests, fixtures, or logs.
- Note any AI assistance used, in the PR description.

## Security invariants that a PR may never weaken

1. Fail closed on uncertainty.
2. Monotonic combination — no path returns a weaker verdict than its inputs.
3. Decided value and executed value are the same digest-bound object.
4. Approvals are one-shot, expiring, and bound to an intent digest.
5. The control plane stays structurally unreachable from the managed agent.

A PR that touches any of these needs an explicit maintainer review note
explaining why the invariant still holds.
