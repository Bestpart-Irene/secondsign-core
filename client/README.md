# secondsign-client

The agent-side client for [SecondSign](https://github.com/Bestpart-Irene/secondsign-core).
It carries a proposal that value should move to a SecondSign gateway process,
over mutual TLS, and reads the answer. That is all of it.

```python
from secondsign_client import GatewayClient, AuthorizationRequest

client = GatewayClient(
    "gateway",
    8787,
    ca_file="/etc/secondsign/tls/ca-cert.pem",
    client_cert="/etc/secondsign/tls/client-cert.pem",
    client_key="/etc/secondsign/tls/client-key.pem",
)
outcome = client.request_authorization(request)  # completed / refused / awaiting_review
```

## What this package deliberately is not

This distribution contains **no gateway, no rail adapter, no policy engine, no
approval flow, and no credential handling**. Its only dependency is `pydantic`.
In an environment with only this package installed:

```python
>>> import secondsign.gateway
ModuleNotFoundError: No module named 'secondsign'
```

That traceback is *evidence*, not the boundary: it proves this process does not
contain the gateway code, and nothing more. Whether the agent can actually
bypass its gateway is a property of the deployment — no rail credential in the
agent's environment, no network route to the rail, the gateway as the only way
out — demonstrated by the reference deployment in `deploy/reference/` of the
core repository and asserted by its adversarial suite.

## Behaviour worth knowing before depending on it

- **Unreachable means refused.** If the gateway is down, unreachable, or
  refuses the handshake, every request resolves to `refused` — never a locally
  computed verdict. An agent that could tell "no" from "we could not tell"
  could retry against the second one.
- **One dialect.** The wire contract is versioned (`WIRE_VERSION`),
  independently of core's plugin contract. A response speaking any other
  version is refused rather than best-effort parsed.
- **Plaintext exists only on literal loopback.** Off loopback, the client
  requires the CA bundle, its certificate and its key, and verifies the
  gateway's name. There is no setting that relaxes this.
- **Replay bounds are inherited, not added.** A captured authorization request
  is bounded by the intent's validity window and the gateway's idempotency
  reservation; the transport adds no replay mechanism of its own (ADR 0003 §4).

## Licence

Apache-2.0. Part of the SecondSign project; developed in the
[secondsign-core](https://github.com/Bestpart-Irene/secondsign-core) repository.
