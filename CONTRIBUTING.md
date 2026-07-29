# Contributing to SecondSign Core

## Your first contribution

**Check your Git identity first.** Every commit here carries a sign-off naming
you, and CI rejects a template placeholder — so read what is set *before* you
commit. Afterwards the fix is a rebase over the whole branch, which is the step
that turns a five-minute contribution into an afternoon.

```bash
git config --get user.name
git config --get user.email
```

If either is empty, or is a template's suggestion rather than you, set it. The
address has to be one that could reach you:

```bash
git config user.name  "Ada Lovelace"
git config user.email <the address on your GitHub account>
```

If you would rather not publish your own address, GitHub issues you one:
**Settings → Emails → "Keep my email addresses private"** gives you an
`ID+USERNAME@users.noreply.github.com`. It attributes the commit to you, keeps
your address out of a public log, and passes this gate.

Then:

```bash
# 1. Branch. The prefix matters: CI reads it.
#    docs/… or chore/… for documentation and housekeeping — no slice needed.
#    fix/<SLICE-ID>/… or feat/<SLICE-ID>/… when you touch src/ — the issue you
#    picked up names the id, and its manifest is already on main. See below.
git checkout -b docs/your-change

# 2. Install, including the dev toolchain the gates use.
pip install -e ".[dev]"

# 3. Commit with -s. Without it CI fails, and the fix is a rebase.
git commit -s -m "docs: what you changed"

# 4. Ask, locally, everything CI is going to say about the protocol.
python tools/contributor_check.py

# 5. Run the gates. They are the same ones CI runs.
ruff check . && ruff format --check . && mypy src && pytest && lint-imports

# 6. Push and open a pull request.
git push -u origin HEAD
```

Step 4 is the one worth not skipping. `tools/contributor_check.py` runs the
repository's own gates — sign-off, branch name, declared scope, the derived
status table — against your branch and prints the command that fixes each
failure. Every one of those is a one-command fix, and every one of them used to
be discovered on a runner, minutes after a push, in a log you had to go and
find. That was a defect in this project, not in anyone's contribution.

**There are two pull request templates.** The default is short — what changed,
tests, authorship, risks — and it is the right one for documentation, examples,
assets, tooling and a contained bug fix. A change on the decision path (`src/`,
`client/src/`, `onchain/`) uses the longer one, which asks for threats, declared
scope and the invariants you reasoned about; open it by adding
`?template=core-slice.md` to the compare URL. Asking a documentation fix to
account for eight security invariants taught people to tick boxes without
reading them, which is exactly how those boxes stop meaning anything on the pull
requests where they matter.

You do not need to add yourself to [`CONTRIBUTORS.md`](CONTRIBUTORS.md). It is
generated from the Git history after your change merges.

Issues labelled [`good first
issue`](https://github.com/Bestpart-Irene/secondsign-core/labels/good%20first%20issue)
each carry their scope, acceptance criteria, the commands to run, and the branch
name to use. If any step here is unclear, say so in the issue — the protocol
being unclear is a defect in this file.

## What a maintainer does, so you do not have to

A contributor's job here is the change: the failing test, the implementation,
the sign-off. Several other things have to happen for a change to land, and none
of them is a good use of a first contribution. They are maintainer work, and
they are done for you.

**The slice manifest is already on `main`.** A change under `src/` belongs to a
slice, which declares its scope, its threat coverage and its acceptance criteria
before any code exists. That is a governance decision —
[`GOVERNANCE.md`](GOVERNANCE.md) reserves roadmap acceptance to maintainers — so
for anything labelled `good first issue` the manifest is written and merged
before the issue is filed. You will not be asked to author one, to keep the
generated [`docs/slices/STATUS.md`](docs/slices/STATUS.md) in step, or to rewrite
your first commit when the scope turns out to need widening. The issue tells you
which files you may change; that is the whole of it.

For something *not* on the roadmap, open an issue first and let the boundary be
agreed there. A manifest arriving inside an implementation pull request is a
scope decision and an implementation asking for one review, and it cannot
honestly be given.

**"This branch is out of date" is not yours to fix.** `main` requires branches to
be up to date before merging, so every merge to trunk leaves every open pull
request behind. A maintainer presses **Update branch**. You are welcome to merge
`main` yourself if you want the gates run against trunk as it stands, but nobody
will ask you to rebase on someone else's schedule.

**Mechanical fixes may be pushed to your branch**, if you left "Allow edits by
maintainers" on — formatting, a scope manifest, a regenerated status table,
syncing with `main`. What will never be changed for you is the logic, the
security semantics, or your sign-off: those are the parts the review is actually
about, and they are yours.

**Review comes in one pass.** Everything that blocks a merge is listed at once
and marked as blocking; anything else is marked `optional` and you may decline
it. Discovering one more problem per round is a review style, not a standard,
and it is not this project's.

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

**What CI actually checks** (`tools/check_dco.py`), because a gate that only
looked for the shape of a sign-off let a template placeholder through once:

1. every non-merge commit carries a `Signed-off-by:` trailer;
2. one of its trailers names the commit's **author or its committer** — the
   second because DCO 1.1 §(c) covers passing along work received from someone
   else, where the trailer belongs to whoever submitted it;
3. the address could be an address — ASCII, `local@domain.tld`, not a reserved
   example domain, not a known template value.

Rule 3 is a heuristic and cannot be complete: nothing in a repository can verify
that a person exists, because verifying an address means sending mail to it. It
raises the cost of signing off carelessly, and that is all it claims to do.

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

1. **Pick a slice.** The queue is
   [`docs/slices/roadmap.yaml`](docs/slices/roadmap.yaml), and for anything
   labelled `good first issue` the manifest is already merged — see "What a
   maintainer does, so you do not have to" above. To *propose* something new,
   open an issue; a maintainer agrees the boundary and lands the manifest, and
   the issue is then marked ready to implement. If you are a maintainer writing
   one, copy [`docs/slices/TEMPLATE.yaml`](docs/slices/TEMPLATE.yaml), land it on
   `main` first, and validate it with
   `python tools/validate_slice.py path/to/slice.yaml`.
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

The last three, plus the sign-off check and a comparison against `main`, are
what `python tools/contributor_check.py` runs in one pass — the same scripts,
invoked rather than reimplemented, with the fix command printed beside each
failure. It deliberately does not wrap `ruff`, `mypy` or `pytest`: those explain
themselves, and a wrapper would only put a layer between you and a clear message.

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
