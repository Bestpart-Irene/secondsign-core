# ADR 0002 — Extensions cannot grant permission

Status: accepted
Date: 2026-07-23

## Context

Core is meant to be extended by third parties: organisation policy, compliance
providers, proprietary risk rules. Every such extension is code the project
does not control, running on a path that moves money.

The usual shape gives a plugin a verdict enum including "allow" and a combining
rule that documentation asks everyone to respect. That places the guarantee in
review discipline, where it will eventually fail — through a well-meaning
override flag, a "trusted plugin" exemption, or a merge nobody scrutinised.

## Decision

An extension's vocabulary is `ABSTAIN`, `REVIEW`, `DENY`. There is no `ALLOW`.

Combination is a maximum over strictness and a union over reasons, with no
branch capable of returning less than an input. The laws — commutativity,
associativity, idempotence, monotonicity, with `ABSTAIN` as identity — are
property-tested rather than sampled.

Extension failure resolves to `DENY`: a crash, an unknown contract version, or
a non-judgement return. Even a well-formed judgement from a mismatched contract
version is discarded, because a plugin speaking a different dialect may mean
something different by `DENY`.

## Consequences

- "The plugin approved this payment" is not an expressible statement. Permission
  comes from core policy alone.
- A crashing extension can hold every transaction. This is a real availability
  cost and it is accepted; the answer is operator-visible extension health and a
  declared degraded state, not a softer verdict.
- The alternative — escalating unknowns to human review — was considered and
  rejected. An extension that failed might have been the one about to deny, and
  routing "we do not know" into a review queue converts a machine-checkable
  guarantee into one that gets bulk-approved under load (threat A8).
- Extension authors own their own availability: timeouts and fallbacks for any
  external service they call are their responsibility.
