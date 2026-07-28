# Governance

SecondSign Core is an open project with a small maintainer group and a large
surface for contribution. This file says who decides what, and — more usefully —
how much can be decided without anyone deciding at all.

## Principle

**Most contributions should not require a judgement call.**

The security properties are written down in [`docs/INVARIANTS.md`](docs/INVARIANTS.md),
each one is bound to a test, and extensions certify themselves against a
published conformance suite. If CI is green and the slice manifest validates,
a change is acceptable on its merits. Reviewers spend their attention on design
and clarity, not on re-litigating whether raw account numbers are allowed in a
log.

That is what makes the project extensible by contributors the maintainers have
never met, and by agents working from the repository alone.

## Roles

**Contributors** open slices and pull requests. No permission needed.

**Reviewers** approve pull requests within an accepted slice. They check
design, scope adherence, and test quality — not the invariants, which CI
already enforces.

**Maintainers** accept slices into the roadmap, approve ADRs, cut releases,
and hold the checkpoints below. Listed in
[`CONTRIBUTORS.md`](CONTRIBUTORS.md).

## Human checkpoints

Six things stop for a maintainer. Everything else proceeds on green CI.

1. **Freezing or changing a public contract.** Extensions depend on it; a
   surprise here breaks code the project does not control.
2. **Weakening any guarantee.** Removing or loosening an enforcement test
   requires an accepted ADR that states what replaces the guarantee, in the
   same pull request.
3. **Changing product scope** — what core is and is not responsible for.
4. **External credentials, real money, release, or deployment.**
5. **Legal, licensing, or trademark questions.**
6. **When tests cannot settle which behaviour is correct.** If reasonable
   people disagree about what the software *should* do, that is a design
   decision, not a bug, and it needs a person.

Ordinary implementation, test-failure fixes, documentation, lint, and internal
refactoring are explicitly *not* checkpoints.

## Decisions

Durable architectural and policy decisions are recorded as ADRs in
[`docs/decisions/`](docs/decisions/). An ADR states the context, the decision,
and the consequences — including what it costs. Superseding an ADR means
writing a new one, not editing the old one.

## Scope

Core is a deterministic execution authorization kernel for financial agent
actions. It is not an agent framework, not a workflow engine, not a
multi-tenant backend, and it runs no learned model on the live decision path.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the boundary.

Proposals outside that boundary are usually better as an extension. That is
what the extension contracts exist for.

## Provenance

Every commit carries a DCO sign-off, enforced in CI from the first commit. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

It certifies the right to submit, and it leaves a named assertion of origin
against every commit. It is **not** a copyright assignment and **not** a CLA:
contributors keep copyright in their contributions, the project receives the
inbound licence Apache-2.0 §5 grants and nothing wider, and no maintainer
acquires a right to relicense anyone's work. Relicensing, dual-licensing or a
proprietary grant would each need a separate instrument agreed with
contributors — a legal question, and therefore a maintainer checkpoint (§5
above), not something the sign-off already settled.
