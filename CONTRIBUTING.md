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

**What the DCO is, precisely.** It is a per-commit assertion about *the right to
submit*: that the contributor authored the work, or received it under a
compatible licence, and may contribute it here. It produces a durable,
machine-checkable provenance record — for every commit, a named person on the
record asserting where the code came from.

**What it is not.** The DCO is not a copyright assignment and not a Contributor
Licence Agreement. Contributors keep the copyright in their own contributions;
the project receives the inbound licence that
[Apache-2.0 §5](https://www.apache.org/licenses/LICENSE-2.0#contributions)
grants, and nothing wider. In particular, sign-off gives the maintainers **no
right to relicense a contribution**, and it does not consolidate copyright in
any one person. Copyright in a multi-contributor project is distributed across
its authors whether or not a DCO is in force — the DCO changes what is *known*
about each contribution's origin, not who owns it.

**Why this project enforces it from the first commit anyway:** a provenance
record has to be built as the commits land. Reconstructing one afterwards means
going back to every contributor for an assertion about work they may barely
remember, and for a project whose premise is an auditable record, an
unreconstructable gap in that record is the expensive outcome.

If SecondSign ever needs to relicense, dual-licence, or offer a proprietary
grant, that requires a separate instrument — a CLA or an explicit licence grant
— agreed with contributors and reviewed by a lawyer. This file will not pretend
otherwise, and no contributor should sign off here expecting that outcome.

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
pytest --cov=secondsign --cov-report=term-missing --cov-fail-under=100
lint-imports
python tools/validate_slice.py docs/slices/roadmap.yaml
python tools/check_slice_scope.py
python tools/render_roadmap.py --check
```

Two of these are worth knowing about before they fail on you:

- **Coverage is a ratchet at 100%**, because README states that figure and a
  claim about this repository should not depend on anyone remembering. It
  measures which branches executed. It is not evidence that the assertions are
  right, and it is not a security argument.
- **`render_roadmap.py --check`** verifies that
  [`docs/slices/STATUS.md`](docs/slices/STATUS.md) still matches what the tool
  derives from the roadmap and Git. If it fails, do not edit that file — run
  `python tools/render_roadmap.py` and commit the result.

### On-chain slices

A slice that declares `forge_fmt` or `forge_test` also runs the Solidity gates,
in the `onchain/` verification workspace. That workspace is deliberately outside
the Python distribution: it pins the exact Safe releases the on-chain topology
work has to reproduce, and nothing in the published package depends on it.

```bash
cd onchain
npm ci                        # the pinned Safe releases, from the committed lockfile
forge fmt --check
forge test
```

The lockfile resolves to two packages and nothing else. Safe declares `ethers` as
a peer dependency, and npm would otherwise pull a JavaScript crypto stack into a
tree that exists only so `forge` can read `.sol` files — so `onchain/.npmrc` sets
`legacy-peer-deps`. There is no JavaScript in this workspace; if you find yourself
needing a runtime dependency here, that is worth a conversation before a commit.

Foundry is needed only for these slices. CI installs it by pinned version and
checksum, so match that version locally rather than tracking latest:

```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup --install 1.0.0
```

All of these run in CI on every pull request, plus a secret scan, a DCO check,
a build check, and a dependency licence review. The Solidity job also re-runs
its suite against a deliberately mutated assertion and requires that to fail —
a gate that cannot fail is not a gate, and this way a broken or skipped install
cannot be reported as green.

## Test layout

Tests are grouped **by the component under test**, mirroring `src/secondsign/`.
The `required_tests` categories a slice manifest declares — `unit`,
`properties`, `contracts`, `conformance`, `architecture`, `redteam`, `e2e`,
`onchain_topology` — describe the *kind* of test to write, not a directory to
put it in.

| Directory | Component under test |
|---|---|
| `tests/adapters/` | Rail adapters and their conformance runs |
| `tests/approval/` | Maker-checker and the approval provider contract |
| `tests/audit/` | Receipts, the hash chain, the sink contract |
| `tests/contracts/` | The published extension surface and combination laws |
| `tests/decision/` | The decision engine |
| `tests/gateway/` | Idempotency reservation and execution |
| `tests/intent/` | `TransactionIntent`, payloads, the digest |
| `tests/policy/` | Shipped policies |

Four directories are cross-cutting rather than per-component:

| Directory | Purpose |
|---|---|
| `tests/architecture/` | Invariants enforced across the whole package by discovery, so a new model is covered the moment it exists |
| `tests/conformance/` | That the conformance kits certify correctly, including rejecting a non-conformant extension |
| `tests/redteam/` | Adversarial regression against the threat model's red-team matrix |
| `tests/e2e/` | The whole path, end to end, including the no-committed-credentials scan |
| `tests/tooling/` | The slice validator and the repository's own gates |

Property tests sit beside the component they constrain, named `*_properties.py`
or `*_laws.py` — for example `tests/policy/test_amount_properties.py`. Keeping a
law next to the thing it governs is what stops it being read as a separate,
optional suite.

Create a directory when the slice that needs it arrives. An empty directory with
a placeholder file suggests coverage that is not there, and the honest signal is
its absence.

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
