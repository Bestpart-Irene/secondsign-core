# Reference deployment

A topology in which SecondSign's no-bypass claim is a property of the network
rather than of the agent's good behaviour.

```text
agent ──agentnet── gateway ──railnet── rail
  ×────────────────────────────────────┘
```

`agent` is joined to `agentnet` and nothing else. No firewall rule does this and
no policy enforces it: the container has **no interface** on the network the
rail is on. "The agent cannot reach the rail" is therefore a fact about what
exists, not about what is permitted.

```bash
cd deploy/reference
python tls/generate.py              # ephemeral PKI, never committed
docker compose up --build
docker compose down -v
```

The adversarial suite that interrogates this deployment is
[`tests/deployment/`](../../tests/deployment/), run by the
`deployment_topology` gate:

```bash
pytest -m deployment
```

## What it demonstrates

**Network isolation.** Hostile code inside the agent container, written against
the standard library, cannot open a socket to the rail. The suite asserts the
failure is `EHOSTUNREACH` / `ENETUNREACH` / `ETIMEDOUT` rather than
`ECONNREFUSED`, and that distinction is the point: a refusal means a control is
*running* and declining, and a running control can be misconfigured off or
crash. There is no route at all.

**Custody separation.** Three directories of key material, each mounted
read-only into exactly one container:

| Directory | Holds | Mounted into |
|---|---|---|
| `tls/ca/` | CA signing key | **nothing** |
| `tls/gateway/` | gateway cert + key, CA cert | `gateway` |
| `tls/agent/` | client cert + key, CA cert | `agent` |

The CA signing key is mounted nowhere. Something that can *mint* an identity
outranks anything that can use one — an agent able to read it could name itself
any principal it liked, and every other control here would be decoration.

The rail credential is in the gateway's environment and nowhere else.

**Destination-side accounting.** The mock rail records every request that
reaches it, before validating it, and the suite compares that ledger against
what the gateway dispatched. This is the only check that can catch a bypass that
*worked*: asking the agent whether its attempt failed has a blind spot exactly
where it matters.

## Why you should believe the demonstration

Everything above is a **negative**, and negatives pass for boring reasons.
Nothing was listening. A container never started. A name did not resolve. The
harness stopped probing. Each of those produces the same green as a correctly
isolated deployment, which is why two things run alongside the suite.

`TestTheSuiteIsNotVacuous` requires the gateway to be reachable *from the same
container the attacks fail from*, and the rail to be reachable from the gateway.
Without it, "nothing was up" would read as "the rail was unreachable".

That guard is still an assertion inside the suite being questioned, though: it
can say the addresses were reachable, not that the suite would have **noticed**
a reachable rail — because a correct deployment never has one to notice. So CI
builds one. [`compose.joined.yaml`](compose.joined.yaml) overlays a single line
onto this topology, `railnet` on the agent, changing nothing else: same images,
same mounts, same credential placement, same certificates. The isolation cases
are then re-run, unmodified, against that stack, and are **required to fail**.

```bash
docker compose -f compose.yaml -f compose.joined.yaml up -d   # do not deploy this
pytest -m deployment_mutation -q
```

A gate that cannot be made to fail is not evidence of anything.

## What it does not demonstrate

Stated plainly, because a working reference deployment reads as an endorsement
of far more than it establishes.

- **This is not a secret store.** Bind-mounted files are readable by anyone with
  access to the host. The mounts demonstrate *which container gets which key*
  and give **no secret-at-rest guarantee**. Production deployments bring Vault,
  a Kubernetes Secret or a cloud KMS; the gateway's interface is a file path,
  and how that path gets populated is a deployment concern.
- **Containers are not a boundary against a privileged host attacker.** A
  container escape defeats all of this. That is accepted and unmitigated.
- **There is no online revocation.** No CRL, no OCSP. A leaked certificate stays
  valid until it expires — 1 hour as deployed here, 24 hours being the maximum
  the gateway will accept. Emergency response is removing the principal or CA
  from the allowlist and reloading.
- **The agent container does hold a credential**: its own client private key. It
  must, or it could not authenticate. The suite asserts that key *is* present
  before asserting the gateway key, CA signing key and rail credential are not —
  because "the agent holds no credential" would be false, and a demonstration
  that overstates itself is worth less than one that does not.
- **It proves that one correct deployment passes**, not that any deployment a
  user builds is safe. Copy the topology, not the confidence.

## Preconditions this cannot enforce

Both networks are `internal: true`, so nothing here has a route off the host.
That models the real precondition honestly rather than hiding it: **an agent
with general internet egress can reach a payment API**, and no packaging or
process decision in SecondSign prevents that. Likewise an agent that can install
packages *and* reach the network has bypassed this design.

The full split between what the software enforces and what a deployment must
provide is in
[ADR 0003](../../docs/decisions/0003-the-agent-side-client-is-a-separate-distribution.md),
with the certificate identity model in
[ADR 0004](../../docs/decisions/0004-client-certificates-authenticate-a-workload.md).

## Status

`CORE-S019` is in progress. The topology, the mock rail, the PKI and the gateway
process are built: `python -m secondsign.gateway.server` terminates mTLS, derives
the caller's identity from the certificate, and the stack comes up. The
deployment suite and the mutation check both run in CI.

What the gateway does **not** do yet is authorize. `/authorize` answers `503
authorization_unavailable` to a perfectly authenticated caller, because the
decision engine behind it is a later step of this slice and a refusal is the
only honest verdict until then. One consequence is visible in the suite:
`TestDestinationSideAccounting` compares the rail's ledger against what the
gateway dispatched, and passes today because both are zero. It becomes evidence
when the gateway starts dispatching.
