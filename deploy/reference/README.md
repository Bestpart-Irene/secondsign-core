# Reference deployment

A topology in which SecondSign's no-bypass claim is a property of the network
rather than of the agent's good behaviour.

```text
agent ──agentnet── gateway ──railnet── rail
  ×───────────────────╂─────────────────┘
  ×────approvernet────┨
approver ─────────────┘
```

`agent` is joined to `agentnet` and nothing else. No firewall rule does this and
no policy enforces it: the container has **no interface** on the network the
rail is on. "The agent cannot reach the rail" is therefore a fact about what
exists, not about what is permitted.

The same construction guards the other direction of trust (`CORE-S023`): the
**approver channel** — the second mTLS listener a human answers reviews
through — binds to the gateway's fixed address on `approvernet`, a network the
agent likewise has no interface on. Its clients authenticate under a *separate
CA*; the gateway refuses to start if the two anchors are one certificate, or
if any principal appears on both allowlists.

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
| `tls/ca/` | agent-channel CA signing key | **nothing** |
| `tls/approver-ca/` | approver-channel CA signing key | **nothing** |
| `tls/gateway/` | both listeners' certs + keys, both CA certs | `gateway` |
| `tls/agent/` | client cert + key, agent CA cert | `agent` |
| `tls/approver/` | checker cert + key, approver CA cert | `approver` |

The CA signing key is mounted nowhere. Something that can *mint* an identity
outranks anything that can use one — an agent able to read it could name itself
any principal it liked, and every other control here would be decoration.

The rail credential is in the gateway's environment and nowhere else.

**Destination-side accounting.** The mock rail records every request that
reaches it, before validating it, and the suite compares that ledger against
what the gateway dispatched. This is the only check that can catch a bypass that
*worked*: asking the agent whether its attempt failed has a blind spot exactly
where it matters.

**A CA you can actually rotate.** `SECONDSIGN_CLIENT_CA` names a *bundle*, so
the new CA is appended, agents re-enrol during the overlap, and the old CA is
removed once nobody is behind it — no instant in which every agent must have
already moved. A rotation that requires one is a rotation nobody performs, and a
CA nobody rotates is the one that is still trusted years after the key it signs
with should have been retired. The gateway also requires a client leaf to *be*
one: `keyUsage` permitting signature and an `extendedKeyUsage` naming client
authentication, both present. An unrestricted leaf is valid for every purpose
under RFC 5280, so a CA that scopes nothing is a CA whose every certificate is a
gateway credential.

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
  the gateway will accept. Emergency response is removing the principal from
  `SECONDSIGN_CLIENT_ALLOWLIST`, or its CA from the bundle, and **restarting the
  gateway**: both are read once at start-up, and there is no atomic-reload path
  in this version. `tests/e2e/test_ca_rotation.py` drives that sequence and
  asserts the withdrawn credential is refused while remaining, in itself,
  perfectly valid — which is what a deployment without revocation has instead of
  revocation.
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

`CORE-S019` has built everything it declared, and the vertical path is closed:
an agent in the agent container, holding a client certificate and no rail
credential, proposes a payment through `secondsign-client`; the gateway
authenticates it, decides it, dispatches it to the rail, and answers. The
deployment suite, the sanctioned-path cases and the mutation check all run in
CI. What the slice does *not* deliver is below — and it is a gap in the product,
not an unmet acceptance criterion.

The agent container now installs `secondsign-client` — and only that. `import
secondsign.gateway` in there is a `ModuleNotFoundError`, executed by the suite
rather than asserted. The adversarial cases remain standard-library and remain
the point: what the client demonstrates is that the same workload, asking
properly, moves money it has no route and no credential to move itself.

Limits in this deployment are a fixed demonstration constant in the gateway, not
a setting. That is deliberate — an operator who can raise a limit by editing the
enforcing process's environment has a limit that is a suggestion. Real limits are
control-plane state under an auditable authority (`CORE-S017`), which is not yet
wired.

Since `CORE-S022`/`CORE-S023`, a `REVIEW` is no longer a dead end here. The
deployment enables a review band **exactly because** the approver channel is
configured — a proposal between $200 and the $500 cap parks, the approver
container lists it and answers it over its own channel
(`approver/console.py`), and the agent's re-send of its own handle reads
`completed`. A deployment without the approver settings gets no review band,
so no action is ever parked where no human can reach it.
