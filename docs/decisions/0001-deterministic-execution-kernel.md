# ADR 0001 — A deterministic execution authorization kernel

Status: accepted
Date: 2026-07-23

## Context

Agent guardrails are usually built around the agent: prompts, tool allowlists,
behavioural anomaly scores. Those help, but they sit on the wrong side of the
problem for money. A payment either goes out or it does not, the effect is
often irreversible, and afterwards someone has to explain the decision to an
auditor or a regulator.

Two properties follow from that and are hard to retrofit: the decision must be
reproducible, and it must be explainable in terms of stated rules rather than
model behaviour.

## Decision

Core is a deterministic authorization kernel on the execution path. Given the
same intent and the same policy state, it returns the same verdict, and every
non-permitting verdict carries stable reason codes.

No learned component sits on the live decision path in v1. Velocity,
counterparty risk and similar judgements are expressed as deterministic policy
over derived, redacted features.

## Consequences

- Detection sophistication is lower than a learned system could reach.
  Accepted: an unexplainable denial is not usable in this domain.
- Every rule must be expressible over a closed, typed feature set — which
  forces the intent model to be designed rather than accumulated.
- If learned detection is added later, it runs shadow-only until calibrated and
  is never the sole basis for a denial. That constraint is part of this
  decision, not a later concession.
- The threat model, not intuition, is the source of new rules. A design that
  traces to no threat gets an analysis or gets removed.
