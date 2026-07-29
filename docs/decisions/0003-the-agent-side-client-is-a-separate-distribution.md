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
from secondsign.gateway import ExecutionGateway  # not from secondsign.agent
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

**That traceback is evidence, not the boundary.** An earlier draft of this ADR
called it the boundary, and that was an overclaim of exactly the kind this
project exists to argue against. It proves one thing — this process does not
contain the gateway or a rail adapter — and one thing only. It does not prove
that money cannot move, because an agent that wants to bypass has other routes:

- open a socket to the rail with the standard library, no SDK required;
- `pip install stripe`, or `pip install secondsign-core`, and re-acquire the code;
- read a rail credential that was mounted into the wrong container;
- reach the payment service through an egress path the host already has.

No-bypass is a **conjunction**, and every term is required:

```text
    the agent process holds no rail credential
  ∧ the agent process has no network route to the rail
  ∧ its only route out is the gateway
  ∧ the agent cannot alter any of the above
```

The separate distribution buys the first term structurally and makes the second
and third *checkable*. It buys none of them on its own. Whether the whole
conjunction holds is a property of a **deployment**, and `CORE-S019` is
therefore not finished by a package split — it is finished by an executable
demonstration of the conjunction in an environment where hostile code is
actually running.

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

4. **A non-loopback listener requires mutual TLS, not merely an operator's
   say-so.** On loopback the process boundary is the authentication: only code
   on that host can connect. Off it, nothing about "the operator explicitly
   allowed `0.0.0.0`" identifies the peer, encrypts the request, or stops a
   captured one being replayed — an authorization request is exactly the
   message an attacker most wants to replay. So the gateway refuses to start
   bound off-loopback unless it is given a client CA and its own certificate,
   and it verifies the client certificate on every connection. Replay is bounded
   by the intent's existing validity window and its idempotency reservation
   rather than by a new mechanism; the wire contract states that dependence
   explicitly so it is reviewable rather than incidental.

## Assumptions, and what is residual risk

The conjunction above has four terms. This software can enforce two of them.
The other two are **deployment preconditions**, and naming which is which is the
difference between a security claim and a marketing one.

**Enforced by the software, and tested:**

- The agent-side distribution contains no gateway, rail adapter or
  control-plane module.
- The gateway holds the only rail credential, and no response it returns carries
  one — the outcome model is closed and already forbids it.
- The gateway refuses to start off-loopback without mutual TLS.

**Deployment preconditions — assumed, not defended, and stated in the threat
model as residual risk:**

- The agent's network namespace has no route to the rail. Core cannot enforce
  this; it can only demonstrate it in a reference deployment and give operators
  something to copy.
- The agent cannot install packages, or can but still has no route out. Package
  installation is *not* a blocked capability; it is irrelevant only because the
  second term holds. An agent that can install `stripe` **and** reach the
  internet has bypassed SecondSign, and no packaging decision prevents that.
- The agent cannot escape its container, gain host privilege, or read the
  gateway's environment or filesystem. A container escape defeats this design
  completely, and that is accepted rather than mitigated.
- The rail credential is mounted only into the gateway. A misdelivered secret
  defeats the first term directly.

The honest summary: **the package split makes bypass require a deployment
failure or a privilege escalation, instead of requiring only an import.** That
is a real and large improvement. It is not the same sentence as "the agent
cannot move money", and this ADR will not print the second sentence.

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

- **A reference deployment becomes part of the deliverable**, not an example
  bolted on afterwards. `deploy/reference/` carries a two-network topology, CI
  stands it up, and the adversarial suite runs *inside the agent container*:

  ```text
  agent container ──internal net── gateway container ──rail net── mock rail
        ×──────────────────────────────────────────────────────────┘
                        no route, asserted by hostile code
  ```

  The adversarial cases are written against the **standard library**, not
  against `secondsign-client`. A demonstration that the sanctioned client
  behaves correctly tests the sanctioned path; it says nothing about an agent
  that has stopped cooperating, which is the only agent worth defending against.
  Two cases keep it honest: the gateway must be *reachable* from that same
  container, so the suite cannot pass by everything being down; and the mock
  rail must record exactly the gateway's dispatches and no others, so a
  successful bypass is caught at the destination rather than inferred from the
  source.

- **This ADR does not make the falsification test pass, and neither does the
  package split.** It states the shape and buys one term of the conjunction.
  `CORE-S019` is finished when the adversarial suite demonstrates the rest —
  with the gateway container stopped, no path from the agent container reaches
  the rail, and the mock rail records zero requests for the whole case.
