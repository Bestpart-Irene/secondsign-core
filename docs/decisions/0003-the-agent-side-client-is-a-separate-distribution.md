# ADR 0003 — The agent-side client is a separate distribution

Status: accepted
Date: 2026-07-28

Supersedes nothing. Constrains `CORE-S019`.

## Context

README opens with a falsification test: *turn SecondSign off; if the agent can
still move money, you have not installed a boundary — you have installed a
library it is free to skip.* Core does not currently pass it. Run in-process, as
it ships at 0.1.0, SecondSign is a control the calling code chooses to route
through.

`CORE-S017` closed the half that is expressible inside one repository. The
managed-agent surface cannot import the control plane: two `lint-imports`
contracts and an architecture test that discovers modules rather than naming
them (INV-12). That is a true and useful property, and it is not the claim the
threat model rests on.

The gap is that **import structure is a property of this repository, not of the
process an operator runs.** `secondsign.agent` cannot import
`secondsign.gateway` — but the agent's *process* can. Nothing stops application
code beside the agent from writing:

```python
from secondsign.gateway import ExecutionGateway   # not from secondsign.agent
```

and constructing a gateway of its own. What actually stops that today is that
the process holds no rail credential. So the guarantee currently rests on
**credential locality**: a deployment fact, unenforced by this software, and
invisible to anyone assessing it.

A2 and A3 are about exactly this failure shape — a control whose enforcement
lives somewhere the constrained party can reach or edit.

## Decision

**The agent-side client ships as its own distribution, `secondsign-client`,
which does not depend on `secondsign-core` and contains no gateway, no rail
adapter, and no control-plane module.**

An agent host installs `secondsign-client`. A gateway host installs
`secondsign-core`. In the agent's environment:

```python
>>> import secondsign.gateway
ModuleNotFoundError: No module named 'secondsign'
```

That traceback is the boundary. It is not a rule, a setting, or a review
convention — it is the absence of the code, verifiable by anyone with a shell on
the agent host and no knowledge of this project.

Three constraints follow, and each is a test rather than a paragraph:

1. **`secondsign-client` depends on `pydantic` and nothing else.** It carries
   the request and outcome models, and the transport. If it ever needs a fact
   the published outcome does not carry, that is a core change with a threat
   analysis, not a new dependency here.

2. **The gateway refuses to start bound to a non-loopback address unless the
   operator states a bound interface explicitly and the process is not holding
   default credentials.** A boundary that a config typo (`0.0.0.0`) silently
   widens is the thing `CORE-S019`'s manifest forbids: *a process boundary that
   a configuration setting can collapse.* Refusing to start is the fail-closed
   direction; starting with a warning is not.

3. **The wire contract is versioned independently of the Python API**, and a
   client speaking a version the gateway does not recognise is refused rather
   than best-effort parsed. This mirrors the existing rule that a plugin
   speaking a mismatched contract version has its judgement discarded (ADR
   0002): a peer speaking a different dialect may mean something different by
   `DENY`.

## Alternatives considered

**A sidecar process from a single distribution**, over a Unix domain socket,
using only the standard library. Genuinely attractive: zero new dependencies, a
socket is not routable off-host so there is no misbinding failure mode, and it
satisfies every acceptance criterion `CORE-S019` states.

Rejected on one point. The agent's process still contains `secondsign.rails` and
`secondsign.gateway`, so "it will not bypass" continues to rest on it not having
a key rather than on it not having the code. That is the same class of guarantee
as before — better enforced, but still a fact about deployment. It also excludes
Windows and does not model the cross-host deployment the threat model's language
("no network route to the rail") actually describes.

**Deferring the split to a later version** was considered and rejected on
timing. The package has one published version and no known downstream
dependents. Splitting is a breaking change whose cost is paid by every user who
has already imported the agent surface from `secondsign-core`; that population
is currently zero and will only grow. This is the cheapest moment this decision
will ever have.

## Consequences

- **Two distributions to release together.** `docs/RELEASING.md` gains a second
  path, and a version-skew matrix becomes something to test rather than assume.
  This is a real, recurring cost, accepted in exchange for a structural claim.

- **The wire contract becomes a public surface** with the same obligations as
  the plugin contract: frozen, versioned, ratcheted by test, and carrying its
  own conformance kit so a third-party client — Node, Go, anything — can certify
  itself rather than persuade a maintainer. A cross-language client is a
  consequence worth having: most agent stacks are not Python.

- **A new failure mode: the gateway is unreachable.** The client resolves it to
  `refused`, never to a local decision, because `AgentOutcomeStatus` has no
  fourth state for uncertainty and an agent that can distinguish "no" from "we
  could not tell" can retry against the second one (INV-1). Availability of the
  gateway therefore becomes availability of payments — the same trade ADR 0002
  accepted for a crashing plugin, and the same answer applies: operator-visible
  health and a declared degraded state (`CORE-S018`), never a softer verdict.

- **In-process use does not disappear**, and should not be described as
  supported for production. `secondsign-core` remains directly importable for
  development, evaluation and testing. What changes is that the honest
  deployment now exists, so README can stop describing an aspiration.

- **This ADR does not make the falsification test pass.** It states the shape.
  `CORE-S019` makes it pass, and the criterion is the red-team case: with the
  gateway process stopped, execution must be *impossible* rather than merely
  unauthorized.
