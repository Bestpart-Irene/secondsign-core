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
docker compose up --build      # certs are generated automatically
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

`CORE-S019` is in progress. The topology, the mock rail and the PKI are built;
the gateway service starts `python -m secondsign.gateway.server`, which does not
exist yet. Until it does, the stack does not come up and the deployment suite
reports that rather than reporting a pass.
